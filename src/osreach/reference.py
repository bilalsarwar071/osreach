"""Reference semantics: a concrete, operational packet simulator.

This module deliberately shares no logic with ``encode.py`` beyond parsing.
It forwards one concrete packet hop by hop, the way you would trace it by hand
through Neutron, and is used for two things:

1. every witness produced by the solver is replayed here before it is shown
   to the user (a witness that fails replay is a bug and raises);
2. the test-suite differentially checks the Z3 encoding against it on many
   random packets.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

from .common import ICMP, NON_INTERNET, PORT_PROTOS, ExternalEP, UnsupportedProtocol, proto_number
from .snapshot import Port, Rule, Snapshot

IPv4 = ipaddress.IPv4Address


def _addr(x) -> Optional[IPv4]:
    try:
        a = ipaddress.ip_address(x)
    except (ValueError, TypeError):
        return None
    return a if a.version == 4 else None


def _net(x) -> Optional[ipaddress.IPv4Network]:
    try:
        n = ipaddress.ip_network(x, strict=False)
    except (ValueError, TypeError):
        return None
    return n if n.version == 4 else None


@dataclass(frozen=True)
class Pkt:
    sip: IPv4
    dip: IPv4
    proto: int
    dport: int


class Simulator:
    def __init__(self, snap: Snapshot):
        self.snap = snap
        self.ports = {p.id: p for p in snap.ports}
        self.sgs = {g.id: g for g in snap.security_groups}
        self.ags = {a.id: a for a in snap.address_groups}
        self.subnets = {s.id: s for s in snap.subnets}
        self.nets = {n.id: n for n in snap.networks}
        self.routers = {r.id: r for r in snap.routers}

    # ------------------------------------------------------------ helpers
    def _fixed(self, p: Port) -> list[IPv4]:
        return [a for a in (_addr(f.ip) for f in p.fixed_ips) if a is not None]

    def _aap(self, p: Port) -> list[ipaddress.IPv4Network]:
        return [n for n in (_net(x) for x in p.allowed_address_pairs) if n is not None]

    def owns(self, p: Port, ip: IPv4) -> bool:
        return ip in self._fixed(p) or any(ip in n for n in self._aap(p))

    def subnet_cidr(self, sid: str) -> Optional[ipaddress.IPv4Network]:
        s = self.subnets.get(sid)
        if s is None or s.ip_version != 4:
            return None
        return _net(s.cidr)

    def is_external_net(self, network_id: str) -> bool:
        n = self.nets.get(network_id)
        return bool(n and n.external)

    def external_cidrs(self) -> list[ipaddress.IPv4Network]:
        out = []
        for s in self.snap.subnets:
            if self.is_external_net(s.network_id):
                c = self.subnet_cidr(s.id)
                if c is not None:
                    out.append(c)
        return out

    def router_ok(self, rid: Optional[str]) -> bool:
        if not rid or rid not in self.routers:
            return True
        return self.routers[rid].admin_state_up

    # --------------------------------------------------------- SG verdict
    def rule_allows(self, rule: Rule, pkt: Pkt, peer: IPv4) -> bool:
        if rule.ethertype != "IPv4":
            return False
        try:
            pn = proto_number(rule.protocol)
        except UnsupportedProtocol:
            return False
        if pn is not None:
            if pkt.proto != pn:
                return False
            lo, hi = rule.port_range_min, rule.port_range_max
            if lo is not None or hi is not None:
                lo = hi if lo is None else lo
                hi = lo if hi is None else hi
                if pn == ICMP:
                    if pkt.dport != lo:
                        return False
                elif pn in PORT_PROTOS:
                    if not lo <= pkt.dport <= hi:
                        return False
        if rule.remote_group_id:
            return any(self.owns(m, peer) for m in self.snap.ports if rule.remote_group_id in m.security_group_ids)
        if rule.remote_address_group_id:
            ag = self.ags.get(rule.remote_address_group_id)
            return bool(ag) and any(peer in n for n in (_net(a) for a in ag.addresses) if n is not None)
        if rule.remote_ip_prefix:
            n = _net(rule.remote_ip_prefix)
            return n is not None and peer in n
        return True

    def allows(self, p: Port, direction: str, pkt: Pkt) -> bool:
        if not p.port_security_enabled:
            return True
        peer = pkt.sip if direction == "ingress" else pkt.dip
        for gid in p.security_group_ids:
            g = self.sgs.get(gid)
            if g is None:
                continue
            for r in g.rules:
                if r.direction == direction and self.rule_allows(r, pkt, peer):
                    return True
        return False

    # ----------------------------------------------------------- forwarding
    def _router_subnets(self, r) -> list[str]:
        return [i.subnet_id for i in r.interfaces if self.subnet_cidr(i.subnet_id) is not None]

    def _fips_of(self, p: Port):
        return [f for f in self.snap.floating_ips
                if f.port_id == p.id and _addr(f.ip) is not None and _addr(f.fixed_ip) is not None]

    def external_sources(self, s: Port, sip: IPv4) -> set[IPv4]:
        """Possible source addresses after the packet leaves the cloud edge."""
        out: set[IPv4] = set()
        fips = [f for f in self._fips_of(s) if self.router_ok(f.router_id)]
        fip_fixed = {_addr(f.fixed_ip) for f in self._fips_of(s)}
        for f in fips:
            if _addr(f.fixed_ip) == sip:
                out.add(_addr(f.ip))
        if self.is_external_net(s.network_id):
            out.add(sip)
        if sip not in fip_fixed:
            for r in self.snap.routers:
                if not r.admin_state_up or r.gateway is None or not r.gateway.enable_snat:
                    continue
                for sid in self._router_subnets(r):
                    sub = self.subnets[sid]
                    if sub.network_id == s.network_id and sip in self.subnet_cidr(sid):
                        out.update(a for a in (_addr(x) for x in r.gateway.ips) if a is not None)
        return out

    def external_arrivals(self, dip: IPv4) -> list[tuple[Port, IPv4]]:
        """Ports that receive a packet addressed to ``dip`` from the external network."""
        out = []
        for f in self.snap.floating_ips:
            if _addr(f.ip) == dip and f.port_id in self.ports and _addr(f.fixed_ip) and self.router_ok(f.router_id):
                out.append((self.ports[f.port_id], _addr(f.fixed_ip)))
        for p in self.snap.ports:
            if self.is_external_net(p.network_id) and self.owns(p, dip):
                out.append((p, dip))
        return out

    def send(self, s: Port, pkt: Pkt) -> list[tuple[Port, Pkt, str]]:
        """All (port, delivered packet, how) that receive ``pkt`` sent from ``s``."""
        if not s.admin_state_up:
            return []
        if s.port_security_enabled and not self.owns(s, pkt.sip):
            return []  # anti-spoofing drop
        if not self.allows(s, "egress", pkt):
            return []
        cands: list[tuple[Port, Pkt, str]] = []
        # L2
        for p in self.snap.ports:
            if p.id != s.id and p.network_id == s.network_id and self.owns(p, pkt.dip):
                cands.append((p, pkt, "l2"))
        # one router hop, east-west
        for r in self.snap.routers:
            if not r.admin_state_up:
                continue
            attached = self._router_subnets(r)
            src_ok = any(self.subnets[a].network_id == s.network_id and pkt.sip in self.subnet_cidr(a)
                         for a in attached)
            if not src_ok:
                continue
            for a in attached:
                sub = self.subnets[a]
                if sub.network_id == s.network_id or pkt.dip not in self.subnet_cidr(a):
                    continue
                for p in self.snap.ports:
                    if p.id != s.id and p.network_id == sub.network_id and self.owns(p, pkt.dip):
                        cands.append((p, pkt, "routed"))
        # out through the external network and back in
        for new_sip in self.external_sources(s, pkt.sip):
            for p, new_dip in self.external_arrivals(pkt.dip):
                if p.id != s.id:
                    cands.append((p, Pkt(new_sip, new_dip, pkt.proto, pkt.dport), "external"))
        return [(p, q, how) for p, q, how in cands
                if p.admin_state_up and self.owns(p, q.dip) and self.allows(p, "ingress", q)]

    def receive_external(self, ext: ExternalEP, pkt: Pkt) -> list[tuple[Port, Pkt]]:
        """Ports that accept ``pkt`` arriving from an external host ``pkt.sip``."""
        if not self.external_member(ext, pkt.sip):
            return []
        out = []
        for p, new_dip in self.external_arrivals(pkt.dip):
            q = Pkt(pkt.sip, new_dip, pkt.proto, pkt.dport)
            if p.admin_state_up and self.owns(p, new_dip) and self.allows(p, "ingress", q):
                out.append((p, q))
        return out

    def send_external(self, s: Port, ext: ExternalEP, pkt: Pkt) -> bool:
        if not s.admin_state_up or not self.external_member(ext, pkt.dip):
            return False
        if s.port_security_enabled and not self.owns(s, pkt.sip):
            return False
        if not self.allows(s, "egress", pkt):
            return False
        return bool(self.external_sources(s, pkt.sip))

    def external_member(self, ext: ExternalEP, ip: IPv4) -> bool:
        if ext.internet:
            return not any(ip in n for n in NON_INTERNET) and not any(ip in n for n in self.external_cidrs())
        return any(ip in n for n in (_net(c) for c in ext.cidrs) if n is not None)

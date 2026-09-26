"""Symbolic semantics: Neutron reachability as quantifier-free bit-vector formulas.

A connection attempt is described by

* observable variables, shared by every formula in an analysis:
  ``proto`` (8 bit), ``dport`` (16 bit; ICMP type for ICMP) and ``ext``
  (32 bit; the address of an external peer, when one is involved);
* hidden variables, private to one Encoder: the packet as it leaves the
  source port (``out_sip``, ``out_dip``) and as it arrives at the destination
  port after any NAT (``in_sip``, ``in_dip``).

``reach(src, dst)`` is satisfiable exactly when some packet can be sent by
``src`` and delivered to ``dst`` under the model in docs/semantics.md. Every
satisfying assignment is a concrete witness, which callers re-validate with
the independent reference semantics in ``reference.py``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import z3

from .common import (
    ICMP,
    NON_INTERNET,
    PORT_PROTOS,
    Endpoint,
    ExternalEP,
    PortEP,
    ServiceSpec,
    UnsupportedProtocol,
    proto_number,
    rule_port_range,
)
from .snapshot import Port, Rule, SecurityGroup, Topology, v4net

TRUE = z3.BoolVal(True)
FALSE = z3.BoolVal(False)


def ipval(a: ipaddress.IPv4Address | str) -> z3.BitVecNumRef:
    return z3.BitVecVal(int(ipaddress.IPv4Address(a)), 32)


def in_net(v: z3.BitVecRef, net: ipaddress.IPv4Network) -> z3.BoolRef:
    if net.prefixlen == 0:
        return TRUE
    mask = z3.BitVecVal(int(net.netmask), 32)
    return (v & mask) == z3.BitVecVal(int(net.network_address), 32)


def any_of(xs) -> z3.BoolRef:
    xs = [x for x in xs if not z3.is_false(x)]
    if not xs:
        return FALSE
    if any(z3.is_true(x) for x in xs):
        return TRUE
    return xs[0] if len(xs) == 1 else z3.Or(*xs)


def all_of(xs) -> z3.BoolRef:
    xs = [x for x in xs if not z3.is_true(x)]
    if not xs:
        return TRUE
    if any(z3.is_false(x) for x in xs):
        return FALSE
    return xs[0] if len(xs) == 1 else z3.And(*xs)


@dataclass
class Observables:
    proto: z3.BitVecRef
    dport: z3.BitVecRef
    ext: z3.BitVecRef

    @classmethod
    def fresh(cls, tag: str = "") -> Observables:
        return cls(z3.BitVec(f"proto{tag}", 8), z3.BitVec(f"dport{tag}", 16), z3.BitVec(f"ext{tag}", 32))

    def constrain(self, spec: ServiceSpec) -> z3.BoolRef:
        cs = []
        if spec.proto is not None:
            cs.append(self.proto == spec.proto)
        if spec.ports is not None:
            lo, hi = spec.ports
            cs.append(z3.And(z3.UGE(self.dport, lo), z3.ULE(self.dport, hi)))
        return all_of(cs)


@dataclass
class Case:
    """One way a packet can travel (L2, a router hop, FIP, SNAT, ...)."""

    description: str
    formula: z3.BoolRef


@dataclass
class Reach:
    src: Endpoint
    dst: Endpoint
    formula: z3.BoolRef
    cases: list[Case] = field(default_factory=list)
    hidden: list[z3.BitVecRef] = field(default_factory=list)

    @property
    def possible(self) -> bool:
        return not z3.is_false(self.formula)


class Encoder:
    def __init__(self, topo: Topology, obs: Observables, tag: str = ""):
        self.topo = topo
        self.obs = obs
        self.out_sip = z3.BitVec(f"out_sip{tag}", 32)
        self.out_dip = z3.BitVec(f"out_dip{tag}", 32)
        self.in_sip = z3.BitVec(f"in_sip{tag}", 32)
        self.in_dip = z3.BitVec(f"in_dip{tag}", 32)
        self.hidden = [self.out_sip, self.out_dip, self.in_sip, self.in_dip]
        self._filter_cache: dict[tuple[str, str], z3.BoolRef] = {}
        self._group_cache: dict[tuple[str, int], z3.BoolRef] = {}
        self.warnings: list[str] = []

    # ------------------------------------------------------------ SG rules
    def peer_var(self, direction: str) -> z3.BitVecRef:
        # Ingress rules are evaluated on the packet as delivered (post-NAT) and
        # constrain its source; egress rules on the packet as sent, constraining
        # its destination.
        return self.in_sip if direction == "ingress" else self.out_dip

    def rule_match(self, rule: Rule, peer: z3.BitVecRef) -> z3.BoolRef:
        """Does ``rule`` allow the current (proto, dport, peer)? FALSE for non-IPv4 rules."""
        if rule.ethertype != "IPv4":
            return FALSE
        try:
            pn = proto_number(rule.protocol)
        except UnsupportedProtocol:
            self.warnings.append(f"rule {rule.id}: unknown protocol {rule.protocol!r}, treated as matching nothing")
            return FALSE
        cs = []
        if pn is not None:
            cs.append(self.obs.proto == pn)
            rng = rule_port_range(rule)
            if rng is not None and (pn in PORT_PROTOS or pn == ICMP):
                lo, hi = rng
                if pn == ICMP:
                    # port_range_min is the ICMP type; the code (max) is not modelled.
                    cs.append(self.obs.dport == lo)
                else:
                    cs.append(z3.And(z3.UGE(self.obs.dport, lo), z3.ULE(self.obs.dport, hi)))
        cs.append(self.remote_match(rule, peer))
        return all_of(cs)

    def remote_match(self, rule: Rule, peer: z3.BitVecRef) -> z3.BoolRef:
        if rule.remote_group_id:
            return self.group_addresses(rule.remote_group_id, peer)
        if rule.remote_address_group_id:
            ag = self.topo.address_groups.get(rule.remote_address_group_id)
            nets = [n for n in (v4net(a) for a in (ag.addresses if ag else [])) if n is not None]
            return any_of(in_net(peer, n) for n in nets)
        if rule.remote_ip_prefix:
            n = v4net(rule.remote_ip_prefix)
            return FALSE if n is None else in_net(peer, n)
        return TRUE

    def group_addresses(self, sg_id: str, peer: z3.BitVecRef) -> z3.BoolRef:
        key = (sg_id, peer.get_id())
        if key not in self._group_cache:
            terms = []
            for m in self.topo.sg_members.get(sg_id, []):
                terms += [peer == ipval(a) for _, a in self.topo.fixed_v4(m)]
                terms += [in_net(peer, n) for n in self.topo.aap_v4(m)]
            self._group_cache[key] = any_of(terms)
        return self._group_cache[key]

    def port_filter(self, port: Port, direction: str) -> z3.BoolRef:
        """Security-group verdict at ``port`` for traffic in ``direction``."""
        key = (port.id, direction)
        if key not in self._filter_cache:
            if not port.port_security_enabled:
                f = TRUE
            else:
                peer = self.peer_var(direction)
                terms = []
                for sg_id in port.security_group_ids:
                    sg = self.topo.sgs.get(sg_id)
                    if sg is None:
                        self.warnings.append(f"port {port.id}: security group {sg_id} not in snapshot")
                        continue
                    terms += [self.rule_match(r, peer) for r in sg.rules if r.direction == direction]
                f = any_of(terms)
            self._filter_cache[key] = f
        return self._filter_cache[key]

    def matching_rules(self, port: Port, direction: str) -> list[tuple[SecurityGroup, Rule, z3.BoolRef]]:
        peer = self.peer_var(direction)
        out = []
        for sg_id in port.security_group_ids:
            sg = self.topo.sgs.get(sg_id)
            if sg is None:
                continue
            for r in sg.rules:
                if r.direction == direction:
                    out.append((sg, r, self.rule_match(r, peer)))
        return out

    # ----------------------------------------------------------- addresses
    def owns(self, port: Port, v: z3.BitVecRef) -> z3.BoolRef:
        """Addresses a port accepts traffic for: its fixed IPs and allowed-address-pairs."""
        fixed = [v == ipval(a) for _, a in self.topo.fixed_v4(port)]
        return any_of(fixed + [in_net(v, n) for n in self.topo.aap_v4(port)])

    def may_send_from(self, port: Port, v: z3.BitVecRef) -> z3.BoolRef:
        """Anti-spoofing: with port security off a port may use any source address."""
        if not port.port_security_enabled:
            return TRUE
        return self.owns(port, v)

    def external_member(self, ep: ExternalEP, v: z3.BitVecRef) -> z3.BoolRef:
        if ep.internet:
            excluded = list(NON_INTERNET) + list(self.topo.external_cidrs)
            return all_of([z3.Not(in_net(v, n)) for n in excluded])
        nets = [n for n in (v4net(c) for c in ep.cidrs) if n is not None]
        return any_of(in_net(v, n) for n in nets)

    # ----------------------------------------------- external path options
    def egress_options(self, port: Port) -> list[Case]:
        """Ways traffic from ``port`` reaches the external network, with its source translation."""
        cases = []
        fips = self.topo.fips_by_port.get(port.id, [])
        for f in fips:
            if self.topo.router_up(f.router_id):
                cases.append(Case(f"source NAT to floating IP {f.ip}",
                                  z3.And(self.out_sip == ipval(f.fixed_ip), self.in_sip == ipval(f.ip))))
        if self.topo.on_external(port):
            cases.append(Case("sent directly on external network", self.in_sip == self.out_sip))
        fip_fixed = [self.out_sip == ipval(f.fixed_ip) for f in fips]
        for r, sid, gws in self.topo.snat_routers(port):
            for gw in gws:
                cases.append(Case(
                    f"SNAT via router {r.name or r.id[:8]} to {gw}",
                    all_of([in_net(self.out_sip, self.topo.subnet_net[sid]),
                            z3.Not(any_of(fip_fixed)),
                            self.in_sip == ipval(gw)]),
                ))
        return cases

    def ingress_options(self, port: Port) -> list[Case]:
        """Ways traffic from the external network reaches ``port``, with its destination translation."""
        cases = []
        for f in self.topo.fips_by_port.get(port.id, []):
            if self.topo.router_up(f.router_id):
                cases.append(Case(f"destination NAT from floating IP {f.ip}",
                                  z3.And(self.out_dip == ipval(f.ip), self.in_dip == ipval(f.fixed_ip))))
        if self.topo.on_external(port):
            cases.append(Case("received directly on external network", self.in_dip == self.out_dip))
        return cases

    # --------------------------------------------------------------- reach
    def reach(self, src: Endpoint, dst: Endpoint) -> Reach:
        t = self.topo
        if isinstance(src, PortEP) and isinstance(dst, PortEP):
            return self._port_to_port(t.ports[src.port_id], t.ports[dst.port_id], src, dst)
        if isinstance(src, ExternalEP) and isinstance(dst, PortEP):
            return self._external_to_port(src, t.ports[dst.port_id], dst)
        if isinstance(src, PortEP) and isinstance(dst, ExternalEP):
            return self._port_to_external(t.ports[src.port_id], dst, src)
        return Reach(src, dst, FALSE)

    def _port_to_port(self, s: Port, d: Port, sep, dep) -> Reach:
        if s.id == d.id or not (s.admin_state_up and d.admin_state_up):
            return Reach(sep, dep, FALSE, hidden=self.hidden)
        same = z3.And(self.in_sip == self.out_sip, self.in_dip == self.out_dip)
        cases: list[Case] = []
        if s.network_id == d.network_id:
            net = t_name(self.topo.networks.get(s.network_id), s.network_id)
            cases.append(Case(f"same network {net} (L2)", same))
        for r, ss, sd in self.topo.routed_pairs(s, d):
            cases.append(Case(
                f"routed by {r.name or r.id[:8]} "
                f"({self.topo.subnet_net[ss]} -> {self.topo.subnet_net[sd]})",
                all_of([in_net(self.out_sip, self.topo.subnet_net[ss]),
                        in_net(self.out_dip, self.topo.subnet_net[sd]), same]),
            ))
        for e in self.egress_options(s):
            for i in self.ingress_options(d):
                cases.append(Case(f"via external network: {e.description}; {i.description}",
                                  z3.And(e.formula, i.formula)))
        if not cases:
            return Reach(sep, dep, FALSE, hidden=self.hidden)
        formula = all_of([
            self.may_send_from(s, self.out_sip),
            self.port_filter(s, "egress"),
            any_of(c.formula for c in cases),
            self.owns(d, self.in_dip),
            self.port_filter(d, "ingress"),
        ])
        return Reach(sep, dep, formula, cases, self.hidden)

    def _external_to_port(self, ext: ExternalEP, d: Port, dep) -> Reach:
        if not d.admin_state_up:
            return Reach(ext, dep, FALSE, hidden=self.hidden)
        cases = self.ingress_options(d)
        if not cases:
            return Reach(ext, dep, FALSE, hidden=self.hidden)
        formula = all_of([
            self.obs.ext == self.in_sip,
            self.out_sip == self.in_sip,
            self.external_member(ext, self.in_sip),
            any_of(c.formula for c in cases),
            self.owns(d, self.in_dip),
            self.port_filter(d, "ingress"),
        ])
        return Reach(ext, dep, formula, cases, self.hidden)

    def _port_to_external(self, s: Port, ext: ExternalEP, sep) -> Reach:
        if not s.admin_state_up:
            return Reach(sep, ext, FALSE, hidden=self.hidden)
        cases = self.egress_options(s)
        if not cases:
            return Reach(sep, ext, FALSE, hidden=self.hidden)
        formula = all_of([
            self.obs.ext == self.out_dip,
            self.in_dip == self.out_dip,
            self.external_member(ext, self.out_dip),
            self.may_send_from(s, self.out_sip),
            self.port_filter(s, "egress"),
            any_of(c.formula for c in cases),
        ])
        return Reach(sep, ext, formula, cases, self.hidden)


def t_name(obj, fallback: str) -> str:
    return (getattr(obj, "name", "") or fallback[:8]) if obj is not None else fallback[:8]


# ---------------------------------------------------------------------------
# Witness extraction
# ---------------------------------------------------------------------------


@dataclass
class Packet:
    sip: str
    dip: str


@dataclass
class Witness:
    proto: int
    dport: int
    sent: Packet
    delivered: Packet
    path: list[str]
    egress_rules: list[tuple[SecurityGroup, Rule]]
    ingress_rules: list[tuple[SecurityGroup, Rule]]
    egress_open: bool = False  # port security disabled at the source
    ingress_open: bool = False  # port security disabled at the destination


def _ip(model: z3.ModelRef, v: z3.BitVecRef) -> str:
    return str(ipaddress.IPv4Address(model.eval(v, model_completion=True).as_long()))


def extract_witness(enc: Encoder, reach: Reach, model: z3.ModelRef) -> Witness:
    ev = lambda f: z3.is_true(model.eval(f, model_completion=True))  # noqa: E731
    t = enc.topo
    w = Witness(
        proto=model.eval(enc.obs.proto, model_completion=True).as_long(),
        dport=model.eval(enc.obs.dport, model_completion=True).as_long(),
        sent=Packet(_ip(model, enc.out_sip), _ip(model, enc.out_dip)),
        delivered=Packet(_ip(model, enc.in_sip), _ip(model, enc.in_dip)),
        path=[c.description for c in reach.cases if ev(c.formula)],
        egress_rules=[],
        ingress_rules=[],
    )
    if isinstance(reach.src, PortEP):
        p = t.ports[reach.src.port_id]
        w.egress_open = not p.port_security_enabled
        if not w.egress_open:
            w.egress_rules = [(g, r) for g, r, f in enc.matching_rules(p, "egress") if ev(f)]
    if isinstance(reach.dst, PortEP):
        p = t.ports[reach.dst.port_id]
        w.ingress_open = not p.port_security_enabled
        if not w.ingress_open:
            w.ingress_rules = [(g, r) for g, r, f in enc.matching_rules(p, "ingress") if ev(f)]
    return w

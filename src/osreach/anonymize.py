"""Keyed, analysis-preserving anonymisation of snapshots.

Designed so a snapshot from a private cloud can be published (a bug report, a
test fixture, a paper artefact) without leaking its addressing plan or names,
while every osreach result is unchanged up to renaming.

* IPv4 addresses are mapped by a keyed, *prefix-preserving* permutation in the
  style of Crypto-PAn: two addresses share a k-bit prefix after mapping iff
  they did before, so every CIDR maps to a CIDR of the same length and all
  containment relations between addresses, subnets and rule prefixes survive.
  Bits on the path to a special-purpose range (RFC 1918, loopback, ...) are
  never flipped, so "is this address on the internet?" is also preserved.
* UUIDs are replaced by keyed pseudonyms (consistent across the snapshot, and
  across snapshots anonymised with the same key, so ``osreach diff`` works).
* Names become ``<kind>-<hash>`` unless ``keep_names`` is set; descriptions
  are dropped. IPv6 values are replaced by a fixed placeholder.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import uuid
from functools import lru_cache

from .common import NON_INTERNET
from .snapshot import Snapshot

_PROTECTED = [(int(n.network_address) >> (32 - n.prefixlen) if n.prefixlen else 0, n.prefixlen) for n in NON_INTERNET]


def _protected_ancestor(prefix_bits: int, length: int) -> bool:
    """Is the input prefix a proper ancestor of some protected range in the bit trie?"""
    for bits, plen in _PROTECTED:
        if plen > length and (bits >> (plen - length)) == prefix_bits:
            return True
    return False


class Anonymizer:
    def __init__(self, key: bytes, keep_names: bool = False, keep_ips: bool = False):
        if not key:
            raise ValueError("an anonymisation key is required")
        self.key = key
        self.keep_names = keep_names
        self.keep_ips = keep_ips
        self._bit = lru_cache(maxsize=None)(self._prf_bit)

    # ------------------------------------------------------------- IPv4
    def _prf_bit(self, length: int, prefix: int) -> int:
        msg = length.to_bytes(1, "big") + prefix.to_bytes(4, "big")
        return hmac.new(self.key, b"ip" + msg, hashlib.sha256).digest()[0] & 1

    def ip_int(self, a: int) -> int:
        out = 0
        for i in range(32):
            prefix = a >> (32 - i) if i else 0
            bit = (a >> (31 - i)) & 1
            flip = 0 if _protected_ancestor(prefix, i) else self._bit(i, prefix)
            out = (out << 1) | (bit ^ flip)
        return out

    def ip(self, s):
        if s is None or self.keep_ips:
            return s
        try:
            a = ipaddress.ip_address(s)
        except ValueError:
            return s
        if a.version != 4:
            return "2001:db8::1"
        return str(ipaddress.IPv4Address(self.ip_int(int(a))))

    def cidr(self, s):
        if s is None or self.keep_ips:
            return s
        try:
            n = ipaddress.ip_network(s, strict=False)
        except ValueError:
            return s
        if n.version != 4:
            return "2001:db8::/32"
        if n.prefixlen == 0:
            return str(n)
        mapped = self.ip_int(int(n.network_address))
        return str(ipaddress.IPv4Network((mapped, n.prefixlen), strict=False))

    # --------------------------------------------------------- ids/names
    def id(self, s):
        if not s:
            return s
        d = hmac.new(self.key, b"id" + s.encode(), hashlib.sha256).digest()
        return str(uuid.UUID(bytes=d[:16], version=4))

    def name(self, kind: str, s):
        if self.keep_names or not s:
            return s
        return f"{kind}-{hmac.new(self.key, b'name' + s.encode(), hashlib.sha256).hexdigest()[:6]}"

    # ---------------------------------------------------------- snapshot
    def snapshot(self, snap: Snapshot) -> Snapshot:
        s = copy.deepcopy(snap)
        I, N, A, C = self.id, self.name, self.ip, self.cidr  # noqa: E741
        for p in s.projects:
            p.id, p.name = I(p.id), N("project", p.name)
        for n in s.networks:
            n.id, n.name, n.project_id = I(n.id), N("net", n.name), I(n.project_id)
        for sn in s.subnets:
            sn.id, sn.network_id, sn.name = I(sn.id), I(sn.network_id), N("subnet", sn.name)
            sn.cidr, sn.gateway_ip = C(sn.cidr), A(sn.gateway_ip)
        for r in s.routers:
            r.id, r.name, r.project_id = I(r.id), N("router", r.name), I(r.project_id)
            if r.gateway:
                r.gateway.network_id = I(r.gateway.network_id)
                r.gateway.ips = [A(x) for x in r.gateway.ips]
            for i in r.interfaces:
                i.subnet_id, i.ip = I(i.subnet_id), A(i.ip)
            for rt in r.routes:
                rt["destination"], rt["nexthop"] = C(rt.get("destination")), A(rt.get("nexthop"))
        for g in s.security_groups:
            g.id, g.name, g.project_id = I(g.id), N("sg", g.name) if g.name != "default" else g.name, I(g.project_id)
            for rule in g.rules:
                rule.id = I(rule.id)
                rule.remote_group_id = I(rule.remote_group_id)
                rule.remote_address_group_id = I(rule.remote_address_group_id)
                rule.remote_ip_prefix = C(rule.remote_ip_prefix)
                rule.description = ""
        for ag in s.address_groups:
            ag.id, ag.name, ag.addresses = I(ag.id), N("ag", ag.name), [C(x) for x in ag.addresses]
        for p in s.ports:
            p.id, p.network_id, p.project_id, p.device_id = I(p.id), I(p.network_id), I(p.project_id), I(p.device_id)
            p.name, p.device_name = N("port", p.name), N("vm", p.device_name)
            for f in p.fixed_ips:
                f.subnet_id, f.ip = I(f.subnet_id), A(f.ip)
            p.security_group_ids = [I(x) for x in p.security_group_ids]
            p.allowed_address_pairs = [C(x) if "/" in x else A(x) for x in p.allowed_address_pairs]
        for f in s.floating_ips:
            f.id, f.ip, f.network_id = I(f.id), A(f.ip), I(f.network_id)
            f.port_id, f.fixed_ip = I(f.port_id), A(f.fixed_ip)
            f.router_id, f.project_id = I(f.router_id), I(f.project_id)
        s.meta = {k: v for k, v in s.meta.items() if k in ("source", "created")}
        s.meta["sanitized"] = True
        s.meta["kept"] = [k for k, v in (("names", self.keep_names), ("ips", self.keep_ips)) if v]
        return s

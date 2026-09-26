"""Definitions shared by the symbolic (Z3) and reference (concrete) semantics."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional, Union

# Neutron accepts protocol names or numbers (as strings) on security group rules.
PROTO_NUMBERS = {
    "icmp": 1, "igmp": 2, "ipip": 4, "tcp": 6, "egp": 8, "udp": 17, "dccp": 33,
    "rsvp": 46, "gre": 47, "esp": 50, "ah": 51, "ospf": 89, "encap": 98, "pgm": 113,
    "vrrp": 112, "sctp": 132, "udplite": 136,
}
PROTO_NAMES = {v: k for k, v in PROTO_NUMBERS.items()}

# Protocols for which port_range_min/max constrain the destination port.
PORT_PROTOS = frozenset({6, 17, 33, 132, 136})
ICMP = 1
ANY_PROTO_TOKENS = {None, "", "any", "0"}

# Address space that is *not* "the internet". Traffic from these ranges is
# only considered when the user asks about it explicitly with a cidr: endpoint.
NON_INTERNET = tuple(
    ipaddress.IPv4Network(c)
    for c in (
        "0.0.0.0/8",        # "this network"
        "10.0.0.0/8",       # RFC 1918
        "100.64.0.0/10",    # CGNAT
        "127.0.0.0/8",      # loopback
        "169.254.0.0/16",   # link local
        "172.16.0.0/12",    # RFC 1918
        "192.168.0.0/16",   # RFC 1918
        "224.0.0.0/4",      # multicast
        "240.0.0.0/4",      # reserved + broadcast
    )
)


class UnsupportedProtocol(ValueError):
    pass


def proto_number(proto: Optional[str | int]) -> Optional[int]:
    """Normalise a Neutron protocol value. None means 'any protocol'."""
    if isinstance(proto, int):
        return None if proto == 0 else proto
    if proto is None:
        return None
    p = str(proto).strip().lower()
    if p in ANY_PROTO_TOKENS:
        return None
    if p.isdigit():
        n = int(p)
        if not 0 <= n <= 255:
            raise UnsupportedProtocol(proto)
        return None if n == 0 else n
    if p in PROTO_NUMBERS:
        return PROTO_NUMBERS[p]
    raise UnsupportedProtocol(proto)


def proto_label(n: int) -> str:
    return PROTO_NAMES.get(n, f"ip-proto {n}")


def rule_port_range(rule) -> Optional[tuple[int, int]]:
    """Destination-port (or ICMP type) interval a rule constrains, None if unconstrained."""
    lo, hi = rule.port_range_min, rule.port_range_max
    if lo is None and hi is None:
        return None
    if lo is None:
        lo = hi
    if hi is None:
        hi = lo
    return int(lo), int(hi)


@dataclass(frozen=True)
class PortEP:
    """A Neutron port (usually an instance NIC)."""

    port_id: str


@dataclass(frozen=True)
class ExternalEP:
    """A host outside the cloud.

    ``internet=True`` means any public unicast IPv4 address that is not itself
    part of the cloud's external subnets (those belong to routers and FIPs,
    whose traffic is modelled explicitly). Otherwise the host is anywhere in
    ``cidrs``.
    """

    cidrs: tuple[str, ...] = ()
    internet: bool = False

    @property
    def label(self) -> str:
        return "internet" if self.internet else "cidr:" + ",".join(self.cidrs)


Endpoint = Union[PortEP, ExternalEP]
INTERNET = ExternalEP(internet=True)


def external_contains(ep: ExternalEP, ip: ipaddress.IPv4Address, external_cidrs) -> bool:
    """Concrete membership test for an external endpoint."""
    if ep.internet:
        if any(ip in n for n in NON_INTERNET):
            return False
        return not any(ip in n for n in external_cidrs)
    return any(ip in ipaddress.IPv4Network(c, strict=False) for c in ep.cidrs)


@dataclass(frozen=True)
class ServiceSpec:
    """A (protocol, destination port range) filter used by queries and invariants."""

    proto: Optional[int] = None
    ports: Optional[tuple[int, int]] = None

    @classmethod
    def parse(cls, proto: Optional[str | int] = None, port: Optional[str | int] = None) -> ServiceSpec:
        pn = proto_number(proto) if proto not in (None, "", "any") else None
        rng = None
        if port not in (None, "", "any"):
            s = str(port)
            if "-" in s:
                a, b = s.split("-", 1)
                rng = (int(a), int(b))
            else:
                rng = (int(s), int(s))
            if pn is None:
                raise ValueError("a port was given without a protocol (use --proto tcp|udp|...)")
            if pn not in PORT_PROTOS and pn != ICMP:
                raise ValueError(f"protocol {proto} has no ports")
        return cls(pn, rng)

    def describe(self) -> str:
        if self.proto is None:
            return "any traffic"
        name = proto_label(self.proto)
        if self.ports is None:
            return name
        lo, hi = self.ports
        what = "type" if self.proto == ICMP else "port"
        return f"{name} {what} {lo}" if lo == hi else f"{name} {what}s {lo}-{hi}"

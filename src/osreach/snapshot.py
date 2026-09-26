"""Snapshot schema: a normalised, tool-independent view of Neutron state.

A snapshot is plain JSON so it can be diffed, anonymised, committed as a test
fixture, and analysed offline without credentials to the cloud.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Optional

SCHEMA = "osreach/snapshot/v1"

INSTANCE_OWNER_PREFIX = "compute:"


@dataclass
class Project:
    id: str
    name: str = ""


@dataclass
class Network:
    id: str
    name: str = ""
    project_id: str = ""
    external: bool = False
    shared: bool = False


@dataclass
class Subnet:
    id: str
    network_id: str
    cidr: str
    name: str = ""
    ip_version: int = 4
    gateway_ip: Optional[str] = None


@dataclass
class RouterInterface:
    subnet_id: str
    ip: Optional[str] = None


@dataclass
class RouterGateway:
    network_id: str
    enable_snat: bool = True
    ips: list[str] = field(default_factory=list)


@dataclass
class Router:
    id: str
    name: str = ""
    project_id: str = ""
    admin_state_up: bool = True
    gateway: Optional[RouterGateway] = None
    interfaces: list[RouterInterface] = field(default_factory=list)
    routes: list[dict] = field(default_factory=list)


@dataclass
class Rule:
    id: str
    direction: str  # "ingress" | "egress"
    ethertype: str = "IPv4"
    protocol: Optional[str] = None
    port_range_min: Optional[int] = None
    port_range_max: Optional[int] = None
    remote_ip_prefix: Optional[str] = None
    remote_group_id: Optional[str] = None
    remote_address_group_id: Optional[str] = None
    description: str = ""


@dataclass
class SecurityGroup:
    id: str
    name: str = ""
    project_id: str = ""
    stateful: bool = True
    rules: list[Rule] = field(default_factory=list)


@dataclass
class AddressGroup:
    id: str
    name: str = ""
    addresses: list[str] = field(default_factory=list)


@dataclass
class FixedIP:
    subnet_id: str
    ip: str


@dataclass
class Port:
    id: str
    network_id: str
    name: str = ""
    project_id: str = ""
    device_id: str = ""
    device_owner: str = ""
    device_name: str = ""
    fixed_ips: list[FixedIP] = field(default_factory=list)
    security_group_ids: list[str] = field(default_factory=list)
    port_security_enabled: bool = True
    allowed_address_pairs: list[str] = field(default_factory=list)
    admin_state_up: bool = True


@dataclass
class FloatingIP:
    id: str
    ip: str
    network_id: str = ""
    port_id: Optional[str] = None
    fixed_ip: Optional[str] = None
    router_id: Optional[str] = None
    project_id: str = ""


@dataclass
class Snapshot:
    meta: dict = field(default_factory=dict)
    projects: list[Project] = field(default_factory=list)
    networks: list[Network] = field(default_factory=list)
    subnets: list[Subnet] = field(default_factory=list)
    routers: list[Router] = field(default_factory=list)
    security_groups: list[SecurityGroup] = field(default_factory=list)
    address_groups: list[AddressGroup] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    floating_ips: list[FloatingIP] = field(default_factory=list)

    # ------------------------------------------------------------------ I/O
    def to_dict(self) -> dict:
        return {"schema": SCHEMA, **asdict(self)}

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=False) + "\n")

    @classmethod
    def from_dict(cls, d: dict) -> Snapshot:
        schema = d.get("schema", SCHEMA)
        if schema != SCHEMA:
            raise ValueError(f"unsupported snapshot schema {schema!r} (expected {SCHEMA!r})")
        return cls(
            meta=d.get("meta", {}),
            projects=[_build(Project, x) for x in d.get("projects", [])],
            networks=[_build(Network, x) for x in d.get("networks", [])],
            subnets=[_build(Subnet, x) for x in d.get("subnets", [])],
            routers=[_router(x) for x in d.get("routers", [])],
            security_groups=[_sg(x) for x in d.get("security_groups", [])],
            address_groups=[_build(AddressGroup, x) for x in d.get("address_groups", [])],
            ports=[_port(x) for x in d.get("ports", [])],
            floating_ips=[_build(FloatingIP, x) for x in d.get("floating_ips", [])],
        )

    @classmethod
    def load(cls, path: str | Path) -> Snapshot:
        return cls.from_dict(json.loads(Path(path).read_text()))


def _build(klass, d: dict):
    names = {f.name for f in fields(klass)}
    return klass(**{k: v for k, v in d.items() if k in names})


def _router(d: dict) -> Router:
    r = _build(Router, d)
    if isinstance(r.gateway, dict):
        r.gateway = _build(RouterGateway, r.gateway)
    r.interfaces = [_build(RouterInterface, i) if isinstance(i, dict) else i for i in r.interfaces]
    return r


def _sg(d: dict) -> SecurityGroup:
    sg = _build(SecurityGroup, d)
    sg.rules = [_build(Rule, r) if isinstance(r, dict) else r for r in sg.rules]
    return sg


def _port(d: dict) -> Port:
    p = _build(Port, d)
    p.fixed_ips = [_build(FixedIP, f) if isinstance(f, dict) else f for f in p.fixed_ips]
    return p


# ---------------------------------------------------------------------------
# Topology index
# ---------------------------------------------------------------------------


def v4(addr: Any) -> Optional[ipaddress.IPv4Address]:
    """Parse an IPv4 address, returning None for IPv6 / junk."""
    try:
        a = ipaddress.ip_address(addr)
    except (ValueError, TypeError):
        return None
    return a if isinstance(a, ipaddress.IPv4Address) else None


def v4net(cidr: Any) -> Optional[ipaddress.IPv4Network]:
    """Parse an IPv4 network (host bits tolerated), None for IPv6 / junk."""
    try:
        n = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return None
    return n if isinstance(n, ipaddress.IPv4Network) else None


class Topology:
    """Read-only indexes over a Snapshot, shared by the symbolic and reference semantics."""

    def __init__(self, snap: Snapshot):
        self.snap = snap
        self.projects = {p.id: p for p in snap.projects}
        self.networks = {n.id: n for n in snap.networks}
        self.subnets = {s.id: s for s in snap.subnets}
        self.routers = {r.id: r for r in snap.routers}
        self.sgs = {g.id: g for g in snap.security_groups}
        self.address_groups = {a.id: a for a in snap.address_groups}
        self.ports = {p.id: p for p in snap.ports}

        self.subnet_net: dict[str, ipaddress.IPv4Network] = {}
        for s in snap.subnets:
            n = v4net(s.cidr)
            if n is not None and s.ip_version == 4:
                self.subnet_net[s.id] = n

        self.external_net_ids = {n.id for n in snap.networks if n.external}
        self.external_cidrs = [
            self.subnet_net[s.id]
            for s in snap.subnets
            if s.network_id in self.external_net_ids and s.id in self.subnet_net
        ]

        self.sg_members: dict[str, list[Port]] = {g: [] for g in self.sgs}
        for p in snap.ports:
            for g in p.security_group_ids:
                self.sg_members.setdefault(g, []).append(p)

        self.fips_by_port: dict[str, list[FloatingIP]] = {}
        for f in snap.floating_ips:
            if f.port_id and v4(f.ip) and v4(f.fixed_ip):
                self.fips_by_port.setdefault(f.port_id, []).append(f)

        # router id -> set of attached IPv4 subnet ids
        self.router_subnets: dict[str, list[str]] = {}
        for r in snap.routers:
            self.router_subnets[r.id] = [i.subnet_id for i in r.interfaces if i.subnet_id in self.subnet_net]

    # --------------------------------------------------------------- ports
    def fixed_v4(self, port: Port) -> list[tuple[str, ipaddress.IPv4Address]]:
        out = []
        for f in port.fixed_ips:
            a = v4(f.ip)
            if a is not None:
                out.append((f.subnet_id, a))
        return out

    def aap_v4(self, port: Port) -> list[ipaddress.IPv4Network]:
        return [n for n in (v4net(a) for a in port.allowed_address_pairs) if n is not None]

    def net_subnets(self, network_id: str) -> list[str]:
        return [s.id for s in self.snap.subnets if s.network_id == network_id and s.id in self.subnet_net]

    def is_instance(self, port: Port) -> bool:
        return port.device_owner.startswith(INSTANCE_OWNER_PREFIX)

    def instance_ports(self) -> list[Port]:
        return [p for p in self.snap.ports if self.is_instance(p)]

    def on_external(self, port: Port) -> bool:
        return port.network_id in self.external_net_ids

    def router_up(self, router_id: Optional[str]) -> bool:
        """A FIP/SNAT path through an unknown router is assumed up (over-approximation)."""
        if not router_id:
            return True
        r = self.routers.get(router_id)
        return True if r is None else r.admin_state_up

    def snat_routers(self, port: Port) -> list[tuple[Router, str, list[ipaddress.IPv4Address]]]:
        """(router, attached subnet on the port's network, gateway IPv4s) for SNAT egress."""
        out = []
        mine = set(self.net_subnets(port.network_id))
        for r in self.snap.routers:
            if not r.admin_state_up or r.gateway is None or not r.gateway.enable_snat:
                continue
            gw = [a for a in (v4(i) for i in r.gateway.ips) if a is not None]
            if not gw:
                continue
            for sid in self.router_subnets[r.id]:
                if sid in mine:
                    out.append((r, sid, gw))
        return out

    def routed_pairs(self, src: Port, dst: Port) -> list[tuple[Router, str, str]]:
        """(router, src-side subnet, dst-side subnet) for east-west routing between different networks."""
        if src.network_id == dst.network_id:
            return []
        s_sub = set(self.net_subnets(src.network_id))
        d_sub = set(self.net_subnets(dst.network_id))
        out = []
        for r in self.snap.routers:
            if not r.admin_state_up:
                continue
            attached = self.router_subnets[r.id]
            for ss in attached:
                if ss not in s_sub:
                    continue
                for sd in attached:
                    if sd in d_sub:
                        out.append((r, ss, sd))
        return out

    # -------------------------------------------------------------- labels
    def label(self, port: Port) -> str:
        return port.device_name or port.name or port.id[:8]

    def project_name(self, project_id: str) -> str:
        p = self.projects.get(project_id)
        return p.name if p and p.name else project_id

    def sg_label(self, sg_id: str) -> str:
        g = self.sgs.get(sg_id)
        return g.name if g and g.name else sg_id[:8]

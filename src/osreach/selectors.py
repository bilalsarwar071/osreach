"""Endpoint selectors used on the command line and in policy files.

    internet                 any public IPv4 host outside the cloud
    cidr:198.51.100.0/24     external hosts in a range (comma-separate several)
    vm:web-*                 instance ports whose server name matches the glob
    port:<id or id-prefix>   one port, of any kind
    net:<name glob or id>    instance ports on matching networks
    project:<name glob or id>
    sg:<name glob or id>     instance ports that carry a matching security group
    all | *                  every instance port
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from .common import INTERNET, Endpoint, ExternalEP, PortEP
from .snapshot import Port, Topology, v4net


class SelectorError(ValueError):
    pass


def _match(pattern: str, *candidates: str) -> bool:
    return any(c and (fnmatchcase(c, pattern) or c == pattern) for c in candidates)


def resolve(topo: Topology, selector: str) -> list[Endpoint]:
    sel = selector.strip()
    if sel == "internet":
        return [INTERNET]
    if sel in ("all", "*"):
        return [PortEP(p.id) for p in topo.instance_ports()]
    if ":" not in sel:
        raise SelectorError(f"bad selector {selector!r}; expected e.g. internet, vm:web-*, net:app-net")
    kind, _, pat = sel.partition(":")
    kind = kind.lower()
    if kind == "cidr":
        cidrs = tuple(c.strip() for c in pat.split(",") if c.strip())
        for c in cidrs:
            if v4net(c) is None:
                raise SelectorError(f"bad IPv4 CIDR {c!r}")
        return [ExternalEP(cidrs=cidrs)]
    if kind == "port":
        hits = [p for p in topo.snap.ports if p.id == pat or p.id.startswith(pat) or _match(pat, p.name)]
        return [PortEP(p.id) for p in hits]

    def pick(pred) -> list[Endpoint]:
        return [PortEP(p.id) for p in topo.instance_ports() if pred(p)]

    if kind in ("vm", "instance", "server"):
        return pick(lambda p: _match(pat, p.device_name, p.device_id))
    if kind in ("net", "network"):
        return pick(lambda p: _match(pat, p.network_id, getattr(topo.networks.get(p.network_id), "name", "")))
    if kind == "project":
        return pick(lambda p: _match(pat, p.project_id, topo.project_name(p.project_id)))
    if kind == "sg":
        def has_sg(p: Port) -> bool:
            return any(_match(pat, g, topo.sg_label(g)) for g in p.security_group_ids)
        return pick(has_sg)
    raise SelectorError(f"unknown selector kind {kind!r}")


def resolve_many(topo: Topology, selectors, excludes=()) -> list[Endpoint]:
    if isinstance(selectors, str):
        selectors = [selectors]
    if isinstance(excludes, str):
        excludes = [excludes]
    out: list[Endpoint] = []
    for s in selectors:
        for ep in resolve(topo, s):
            if ep not in out:
                out.append(ep)
    drop = {ep for s in excludes for ep in resolve(topo, s)}
    return [ep for ep in out if ep not in drop]


def endpoint_label(topo: Topology, ep: Endpoint) -> str:
    if isinstance(ep, ExternalEP):
        return ep.label
    p = topo.ports[ep.port_id]
    return topo.label(p)

"""Build a Snapshot from a live cloud through openstacksdk.

Needs admin-level read access to see every project's resources. On Sunbeam:

    sunbeam openrc > admin-openrc && source admin-openrc
    osreach snapshot -o cloud.json

or point ``--cloud`` at an entry in clouds.yaml.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Optional

from .snapshot import (
    AddressGroup,
    FixedIP,
    FloatingIP,
    Network,
    Port,
    Project,
    Router,
    RouterGateway,
    RouterInterface,
    Rule,
    SecurityGroup,
    Snapshot,
    Subnet,
)

ROUTER_INTERFACE_OWNERS = {
    "network:router_interface",
    "network:router_interface_distributed",
    "network:ha_router_replicated_interface",
}


def _g(obj: Any, *names: str, default: Any = None) -> Any:
    """Read the first present attribute/key; tolerant of SDK-version differences."""
    for n in names:
        if isinstance(obj, dict):
            if n in obj and obj[n] is not None:
                return obj[n]
        else:
            v = getattr(obj, n, None)
            if v is not None:
                return v
    return default


def _int(x: Any) -> Optional[int]:
    return None if x is None else int(x)


def normalize(
    *,
    projects=(),
    networks=(),
    subnets=(),
    routers=(),
    security_groups=(),
    address_groups=(),
    ports=(),
    floating_ips=(),
    servers=(),
    meta: Optional[dict] = None,
) -> Snapshot:
    """Convert SDK resources (or plain dicts shaped like the Neutron API) to a Snapshot."""
    server_names = {_g(s, "id"): _g(s, "name", default="") for s in servers}
    ports = list(ports)

    snap = Snapshot(meta=dict(meta or {}))
    snap.projects = [Project(id=_g(p, "id"), name=_g(p, "name", default="")) for p in projects]
    snap.networks = [
        Network(
            id=_g(n, "id"),
            name=_g(n, "name", default=""),
            project_id=_g(n, "project_id", "tenant_id", default=""),
            external=bool(_g(n, "is_router_external", "router:external", default=False)),
            shared=bool(_g(n, "is_shared", "shared", default=False)),
        )
        for n in networks
    ]
    snap.subnets = [
        Subnet(
            id=_g(s, "id"),
            network_id=_g(s, "network_id"),
            cidr=_g(s, "cidr"),
            name=_g(s, "name", default=""),
            ip_version=int(_g(s, "ip_version", default=4)),
            gateway_ip=_g(s, "gateway_ip"),
        )
        for s in subnets
    ]

    interfaces: dict[str, list[RouterInterface]] = {}
    for p in ports:
        if _g(p, "device_owner", default="") in ROUTER_INTERFACE_OWNERS:
            for f in _g(p, "fixed_ips", default=[]) or []:
                interfaces.setdefault(_g(p, "device_id"), []).append(
                    RouterInterface(subnet_id=f["subnet_id"], ip=f.get("ip_address"))
                )
    for r in routers:
        gwi = _g(r, "external_gateway_info")
        gw = None
        if gwi and gwi.get("network_id"):
            gw = RouterGateway(
                network_id=gwi["network_id"],
                enable_snat=bool(gwi.get("enable_snat", True)),
                ips=[x["ip_address"] for x in gwi.get("external_fixed_ips", []) or [] if x.get("ip_address")],
            )
        rid = _g(r, "id")
        snap.routers.append(
            Router(
                id=rid,
                name=_g(r, "name", default=""),
                project_id=_g(r, "project_id", "tenant_id", default=""),
                admin_state_up=bool(_g(r, "is_admin_state_up", "admin_state_up", default=True)),
                gateway=gw,
                interfaces=interfaces.get(rid, []),
                routes=list(_g(r, "routes", default=[]) or []),
            )
        )

    for g in security_groups:
        rules = []
        for r in _g(g, "security_group_rules", default=[]) or []:
            rules.append(
                Rule(
                    id=_g(r, "id"),
                    direction=_g(r, "direction"),
                    ethertype=_g(r, "ethertype", "ether_type", default="IPv4"),
                    protocol=None if _g(r, "protocol") is None else str(_g(r, "protocol")),
                    port_range_min=_int(_g(r, "port_range_min")),
                    port_range_max=_int(_g(r, "port_range_max")),
                    remote_ip_prefix=_g(r, "remote_ip_prefix"),
                    remote_group_id=_g(r, "remote_group_id"),
                    remote_address_group_id=_g(r, "remote_address_group_id"),
                    description=_g(r, "description", default="") or "",
                )
            )
        snap.security_groups.append(
            SecurityGroup(
                id=_g(g, "id"),
                name=_g(g, "name", default=""),
                project_id=_g(g, "project_id", "tenant_id", default=""),
                stateful=bool(_g(g, "stateful", "is_stateful", default=True)),
                rules=rules,
            )
        )

    snap.address_groups = [
        AddressGroup(id=_g(a, "id"), name=_g(a, "name", default=""), addresses=list(_g(a, "addresses", default=[])))
        for a in address_groups
    ]

    for p in ports:
        device_id = _g(p, "device_id", default="") or ""
        snap.ports.append(
            Port(
                id=_g(p, "id"),
                network_id=_g(p, "network_id"),
                name=_g(p, "name", default="") or "",
                project_id=_g(p, "project_id", "tenant_id", default="") or "",
                device_id=device_id,
                device_owner=_g(p, "device_owner", default="") or "",
                device_name=server_names.get(device_id, ""),
                fixed_ips=[FixedIP(subnet_id=f["subnet_id"], ip=f["ip_address"])
                           for f in (_g(p, "fixed_ips", default=[]) or [])],
                security_group_ids=list(_g(p, "security_group_ids", "security_groups", default=[]) or []),
                port_security_enabled=bool(_g(p, "is_port_security_enabled", "port_security_enabled", default=True)),
                allowed_address_pairs=[a["ip_address"] for a in (_g(p, "allowed_address_pairs", default=[]) or [])
                                       if a.get("ip_address")],
                admin_state_up=bool(_g(p, "is_admin_state_up", "admin_state_up", default=True)),
            )
        )

    snap.floating_ips = [
        FloatingIP(
            id=_g(f, "id"),
            ip=_g(f, "floating_ip_address"),
            network_id=_g(f, "floating_network_id", default=""),
            port_id=_g(f, "port_id"),
            fixed_ip=_g(f, "fixed_ip_address"),
            router_id=_g(f, "router_id"),
            project_id=_g(f, "project_id", "tenant_id", default=""),
        )
        for f in floating_ips
    ]
    return snap


def snapshot_from_cloud(cloud: Optional[str] = None, with_servers: bool = True) -> Snapshot:
    try:
        import openstack
    except ImportError as e:  # pragma: no cover - depends on optional extra
        raise SystemExit("openstacksdk is not installed: pip install 'osreach[openstack]'") from e

    conn = openstack.connect(cloud=cloud) if cloud else openstack.connect()
    net = conn.network

    try:
        projects = list(conn.identity.projects())
    except Exception:  # non-admin credentials: names are optional
        projects = []
    try:
        address_groups = list(net.address_groups())
    except Exception:  # older Neutron without the address-group extension
        address_groups = []
    servers = []
    if with_servers:
        try:
            servers = list(conn.compute.servers(all_projects=True))
        except Exception:
            servers = list(conn.compute.servers())

    return normalize(
        projects=projects,
        networks=list(net.networks()),
        subnets=list(net.subnets()),
        routers=list(net.routers()),
        security_groups=list(net.security_groups()),
        address_groups=address_groups,
        ports=list(net.ports()),
        floating_ips=list(net.ips()),
        servers=servers,
        meta={
            "source": "openstacksdk",
            "cloud": cloud or "environment",
            "created": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "sanitized": False,
        },
    )

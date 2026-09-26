"""Generate the synthetic demo cloud used by the README, tests and CI.

    python examples/build_demo.py      # writes examples/demo-before.json and demo-after.json

The topology is invented (addresses from RFC 5737 TEST-NET-3 and RFC 1918)
but shaped like a typical Sunbeam deployment: one provider network marked
external, per-project tenant networks behind routers with SNAT, floating IPs,
and a few realistic mistakes to find.
"""

from __future__ import annotations

import copy
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from osreach.snapshot import (  # noqa: E402
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

NS = uuid.UUID("6f1d0c9e-2f6a-4b9b-9a53-8f2f3c0d0e11")


def uid(kind: str, name: str) -> str:
    return str(uuid.uuid5(NS, f"{kind}/{name}"))


class Builder:
    def __init__(self):
        self.s = Snapshot(meta={"source": "examples/build_demo.py", "sanitized": True})
        self._rule_n = 0

    def project(self, name):
        self.s.projects.append(Project(uid("project", name), name))
        return uid("project", name)

    def network(self, name, project, cidr, external=False):
        nid, sid = uid("net", name), uid("subnet", name)
        self.s.networks.append(Network(nid, name, project, external=external))
        gw = cidr.rsplit(".", 1)[0] + ".1"
        self.s.subnets.append(Subnet(sid, nid, cidr, name + "-subnet", 4, gw))
        return nid, sid

    def router(self, name, project, gw_net=None, gw_ip=None, subnets=()):
        gw = RouterGateway(gw_net, True, [gw_ip]) if gw_net else None
        ifs = [RouterInterface(s, None) for s in subnets]
        self.s.routers.append(Router(uid("router", name), name, project, True, gw, ifs))
        return uid("router", name)

    def sg(self, name, project, rules):
        gid = uid("sg", f"{project}/{name}")
        out = []
        for r in rules:
            self._rule_n += 1
            out.append(Rule(id=uid("rule", f"{name}/{self._rule_n}"), **r))
        self.s.security_groups.append(SecurityGroup(gid, name, project, True, out))
        return gid

    def vm(self, name, project, net, subnet, ip, sgs, port_security=True, aap=()):
        pid = uid("port", name)
        self.s.ports.append(Port(
            id=pid, network_id=net, name=f"{name}-port", project_id=project,
            device_id=uid("server", name), device_owner="compute:nova", device_name=name,
            fixed_ips=[FixedIP(subnet, ip)], security_group_ids=list(sgs),
            port_security_enabled=port_security, allowed_address_pairs=list(aap)))
        return pid

    def fip(self, ip, port, fixed, router, project, ext_net):
        self.s.floating_ips.append(FloatingIP(uid("fip", ip), ip, ext_net, port, fixed, router, project))


def egress_all():
    return [dict(direction="egress", ethertype="IPv4"), dict(direction="egress", ethertype="IPv6")]


def tcp_in(port, **remote):
    return dict(direction="ingress", ethertype="IPv4", protocol="tcp",
                port_range_min=port, port_range_max=port, **remote)


def build_before() -> Snapshot:
    b = Builder()
    admin, web, data, ops = (b.project(n) for n in ("admin", "web-team", "data-team", "ops"))
    public, public_sub = b.network("public", admin, "203.0.113.0/24", external=True)

    # --- web-team: two tiers behind one router --------------------------------
    web_net, web_sub = b.network("web-net", web, "10.10.1.0/24")
    app_net, app_sub = b.network("app-net", web, "10.10.2.0/24")
    web_router = b.router("web-router", web, public, "203.0.113.10", [web_sub, app_sub])

    sg_bastion = b.sg("bastion", web, [tcp_in(22, remote_ip_prefix="0.0.0.0/0"), *egress_all()])
    sg_web = b.sg("web", web, [
        tcp_in(80, remote_ip_prefix="0.0.0.0/0"),
        tcp_in(443, remote_ip_prefix="0.0.0.0/0"),
        tcp_in(22, remote_group_id=uid("sg", f"{web}/bastion")),
        *egress_all(),
    ])
    sg_app = b.sg("app", web, [
        tcp_in(8080, remote_group_id=sg_web),
        tcp_in(22, remote_group_id=sg_bastion),
        dict(direction="ingress", ethertype="IPv4", protocol="icmp", remote_ip_prefix="10.10.0.0/16"),
        *egress_all(),
    ])

    web1 = b.vm("web-1", web, web_net, web_sub, "10.10.1.11", [sg_web])
    web2 = b.vm("web-2", web, web_net, web_sub, "10.10.1.12", [sg_web])
    bastion = b.vm("bastion-1", web, web_net, web_sub, "10.10.1.5", [sg_bastion])
    b.vm("app-1", web, app_net, app_sub, "10.10.2.21", [sg_app])
    debug = b.vm("debug-1", web, app_net, app_sub, "10.10.2.99", [], port_security=False)
    b.fip("203.0.113.21", web1, "10.10.1.11", web_router, web, public)
    b.fip("203.0.113.22", web2, "10.10.1.12", web_router, web, public)
    b.fip("203.0.113.25", bastion, "10.10.1.5", web_router, web, public)
    b.fip("203.0.113.30", debug, "10.10.2.99", web_router, web, public)

    # --- data-team: a database the web tier talks to over the external net ---
    data_net, data_sub = b.network("data-net", data, "10.20.0.0/24")
    data_router = b.router("data-router", data, public, "203.0.113.11", [data_sub])
    sg_db = b.sg("db", data, [
        dict(tcp_in(5432, remote_ip_prefix="10.0.0.0/8"), description="internal clients"),
        dict(tcp_in(5432, remote_ip_prefix="10.20.0.0/24"), description="etl"),
        dict(tcp_in(5432, remote_ip_prefix="203.0.113.10/32"), description="web-team via SNAT"),
        dict(tcp_in(22, remote_ip_prefix="0.0.0.0/0"), description="TODO: restrict"),
        *egress_all(),
    ])
    sg_etl = b.sg("etl", data, egress_all())
    db1 = b.vm("db-1", data, data_net, data_sub, "10.20.0.10", [sg_db])
    b.vm("etl-1", data, data_net, data_sub, "10.20.0.20", [sg_etl])
    b.fip("203.0.113.40", db1, "10.20.0.10", data_router, data, public)

    # --- ops: an isolated management network and an edge VPN box ---------------
    mgmt_net, mgmt_sub = b.network("mgmt-net", ops, "10.30.0.0/24")
    sg_mon = b.sg("monitoring", ops, [
        dict(direction="ingress", ethertype="IPv4", remote_ip_prefix="10.0.0.0/8"), *egress_all()])
    b.vm("monitor-1", ops, mgmt_net, mgmt_sub, "10.30.0.5", [sg_mon])
    sg_edge = b.sg("edge", ops, [
        tcp_in(443, remote_ip_prefix="0.0.0.0/0"),
        dict(direction="ingress", ethertype="IPv4", protocol="udp",
             port_range_min=51820, port_range_max=51820, remote_ip_prefix="0.0.0.0/0"),
        *egress_all(),
    ])
    b.vm("edge-1", ops, public, public_sub, "203.0.113.50", [sg_edge])
    b.sg("legacy-nfs", ops, [dict(direction="ingress", ethertype="IPv4", protocol="tcp",
                                  port_range_min=2049, port_range_max=2049,
                                  remote_group_id=uid("sg", f"{ops}/nfs-clients"))])
    return b.s


def build_after(before: Snapshot) -> Snapshot:
    """A week later: one fix, and two changes that look harmless in isolation."""
    s = copy.deepcopy(before)
    web = uid("project", "web-team")
    sg_app = next(g for g in s.security_groups if g.name == "app")
    sg_db = next(g for g in s.security_groups if g.name == "db")
    # 1. "temporary" debugging rule on the app tier
    sg_app.rules.append(Rule(id=uid("rule", "app/debug"), direction="ingress", ethertype="IPv4", protocol="tcp",
                             port_range_min=1, port_range_max=65535, remote_ip_prefix="0.0.0.0/0",
                             description="temporary: debugging"))
    # 2. someone gives app-1 a floating IP to test a webhook
    app1 = next(p for p in s.ports if p.device_name == "app-1")
    s.floating_ips.append(FloatingIP(uid("fip", "203.0.113.23"), "203.0.113.23", uid("net", "public"),
                                     app1.id, "10.10.2.21", uid("router", "web-router"), web))
    # 3. the fix: SSH to the database is no longer open to the world
    sg_db.rules = [r for r in sg_db.rules if r.port_range_min != 22]
    s.meta = dict(s.meta, note="one week later")
    return s


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    before = build_before()
    before.save(here / "demo-before.json")
    build_after(before).save(here / "demo-after.json")
    print("wrote examples/demo-before.json and examples/demo-after.json")

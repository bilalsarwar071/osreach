"""Tiny helpers for building snapshots in tests, plus a random cloud generator."""

from __future__ import annotations

import ipaddress
import random

from osreach.snapshot import (
    AddressGroup,
    FixedIP,
    FloatingIP,
    Network,
    Port,
    Router,
    RouterGateway,
    RouterInterface,
    Rule,
    SecurityGroup,
    Snapshot,
    Subnet,
)


class Cloud:
    def __init__(self):
        self.s = Snapshot()
        self.n = 0

    def _id(self, kind):
        self.n += 1
        return f"{kind}-{self.n}"

    def net(self, name, cidr, external=False):
        nid = name
        self.s.networks.append(Network(nid, name, external=external))
        self.s.subnets.append(Subnet(name + "-sub", nid, cidr, name + "-sub"))
        return nid

    def router(self, name, nets=(), gateway=None, gw_ip=None, snat=True, up=True):
        gw = RouterGateway(gateway, snat, [gw_ip]) if gateway else None
        self.s.routers.append(Router(name, name, admin_state_up=up, gateway=gw,
                                     interfaces=[RouterInterface(n + "-sub") for n in nets]))
        return name

    def sg(self, name, *rules):
        rs = []
        for r in rules:
            rs.append(Rule(id=self._id("rule"), **r))
        self.s.security_groups.append(SecurityGroup(name, name, rules=rs))
        return name

    def vm(self, name, net, ip, sgs=(), port_security=True, aap=(), up=True):
        self.s.ports.append(Port(id=name, network_id=net, device_owner="compute:nova", device_name=name,
                                 fixed_ips=[FixedIP(net + "-sub", ip)], security_group_ids=list(sgs),
                                 port_security_enabled=port_security, allowed_address_pairs=list(aap),
                                 admin_state_up=up))
        return name

    def fip(self, ip, port, fixed, router=None):
        self.s.floating_ips.append(FloatingIP(self._id("fip"), ip, "public", port, fixed, router))


def ingress(**kw):
    return dict(direction="ingress", ethertype="IPv4", **kw)


def egress(**kw):
    return dict(direction="egress", ethertype="IPv4", **kw)


def tcp(port, **kw):
    return dict(protocol="tcp", port_range_min=port, port_range_max=port, **kw)


# ---------------------------------------------------------------------------
# Random clouds for differential testing
# ---------------------------------------------------------------------------

POOL = ["10.0.0.0/29", "10.0.0.8/29", "10.0.1.0/29", "192.168.0.0/29", "10.0.0.0/29"]  # note the overlap
EXT = "198.51.100.0/29"


def _hosts(cidr):
    return [str(h) for h in ipaddress.ip_network(cidr).hosts()]


def random_cloud(rng: random.Random) -> Snapshot:
    c = Cloud()
    c.net("public", EXT, external=True)
    ext_hosts = _hosts(EXT)
    rng.shuffle(ext_hosts)
    nets = []
    for i in range(rng.randint(2, 3)):
        nets.append(c.net(f"n{i}", rng.choice(POOL)))
    for i in range(rng.randint(1, 2)):
        attached = rng.sample(nets, rng.randint(1, len(nets)))
        has_gw = rng.random() < 0.8
        c.router(f"r{i}", attached, gateway="public" if has_gw else None,
                 gw_ip=ext_hosts.pop() if has_gw else None, snat=rng.random() < 0.8, up=rng.random() < 0.9)

    sg_names = [f"g{i}" for i in range(3)]
    ports = []

    def rand_rule():
        direction = rng.choice(["ingress", "egress"])
        r = dict(direction=direction, ethertype=rng.choice(["IPv4"] * 9 + ["IPv6"]))
        proto = rng.choice([None, "tcp", "tcp", "udp", "icmp", "47", "6"])
        if proto:
            r["protocol"] = proto
            if proto in ("tcp", "udp", "6") and rng.random() < 0.7:
                lo = rng.choice([1, 22, 80, 443, 8000])
                r["port_range_min"], r["port_range_max"] = lo, rng.choice([lo, lo + 10, 65535])
            if proto == "icmp" and rng.random() < 0.5:
                r["port_range_min"] = rng.choice([0, 8])
        k = rng.random()
        if k < 0.35:
            r["remote_ip_prefix"] = rng.choice(["0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/29", EXT,
                                                "198.51.100.4/30", "1.0.0.0/8", "192.168.0.0/16"])
        elif k < 0.6:
            r["remote_group_id"] = rng.choice(sg_names + ["ghost"])
        elif k < 0.7:
            r["remote_address_group_id"] = "ag"
        return r

    for g in sg_names:
        c.sg(g, *[rand_rule() for _ in range(rng.randint(0, 4))])
    c.s.address_groups.append(AddressGroup("ag", "ag", rng.sample(["10.0.0.0/30", "1.2.3.4/32", EXT], 2)))

    for i in range(rng.randint(3, 6)):
        on_ext = rng.random() < 0.15
        net = "public" if on_ext else rng.choice(nets)
        cidr = next(s.cidr for s in c.s.subnets if s.network_id == net)
        ip = rng.choice(_hosts(cidr))
        aap = [rng.choice(["10.0.0.0/30", rng.choice(_hosts(cidr))])] if rng.random() < 0.2 else []
        c.vm(f"p{i}", net, ip, rng.sample(sg_names, rng.randint(0, 2)), port_security=rng.random() < 0.85,
             aap=aap, up=rng.random() < 0.95)
        ports.append((f"p{i}", net, ip))
    for name, net, ip in ports:
        if net != "public" and rng.random() < 0.4 and ext_hosts:
            r = next((r.id for r in c.s.routers if any(i.subnet_id == net + "-sub" for i in r.interfaces)), None)
            c.fip(ext_hosts.pop(), name, ip, r)
    return c.s


def interesting_addresses(snap: Snapshot, rng: random.Random) -> list[str]:
    addrs = {"1.2.3.4", "8.8.8.8", "10.0.0.1", "192.168.0.3", "172.16.0.1"}
    for p in snap.ports:
        addrs.update(f.ip for f in p.fixed_ips)
    for f in snap.floating_ips:
        addrs.update([f.ip, f.fixed_ip])
    for r in snap.routers:
        if r.gateway:
            addrs.update(r.gateway.ips)
    for s in snap.subnets:
        addrs.add(rng.choice(_hosts(s.cidr)))
    return sorted(a for a in addrs if a)

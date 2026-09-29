"""Hand-written scenarios pinning down the intended Neutron semantics."""

import ipaddress
import random

import z3
from cloudkit import Cloud, egress, ingress, tcp

from osreach.analysis import Analyzer
from osreach.common import INTERNET, ExternalEP, PortEP, ServiceSpec, proto_number
from osreach.encode import in_net

SSH = ServiceSpec.parse("tcp", 22)
ANY = ServiceSpec()


def reach(cloud, src, dst, spec=ANY):
    an = Analyzer(cloud.s)
    s = src if not isinstance(src, str) else PortEP(src)
    d = dst if not isinstance(dst, str) else PortEP(dst)
    return an.witness(s, d, spec)


def two_vms_same_net(ingress_rules=(), egress_rules=None):
    egress_rules = [egress()] if egress_rules is None else egress_rules
    c = Cloud()
    c.net("n", "10.0.0.0/24")
    c.sg("src", *egress_rules)
    c.sg("dst", *ingress_rules)
    c.vm("a", "n", "10.0.0.10", ["src"])
    c.vm("b", "n", "10.0.0.20", ["dst"])
    return c


def test_in_net_agrees_with_ipaddress():
    rng = random.Random(1)
    v = z3.BitVec("v", 32)
    for _ in range(300):
        net = ipaddress.IPv4Network((rng.getrandbits(32), rng.randint(0, 32)), strict=False)
        if rng.random() < 0.5:
            a = ipaddress.IPv4Address(rng.getrandbits(32))
        else:
            a = net.network_address + rng.randint(0, net.num_addresses - 1)
        f = z3.substitute(in_net(v, net), (v, z3.BitVecVal(int(a), 32)))
        assert z3.is_true(z3.simplify(f)) == (a in net), (a, net)


def test_protocol_normalisation():
    assert proto_number(None) is None
    assert proto_number("any") is None
    assert proto_number("tcp") == 6
    assert proto_number("6") == 6
    assert proto_number("0") is None
    assert proto_number("icmp") == 1


def test_default_deny():
    assert reach(two_vms_same_net(), "a", "b") is None


def test_l2_allowed_by_ingress_rule():
    w = reach(two_vms_same_net([ingress(**tcp(22))]), "a", "b", SSH)
    assert w is not None
    assert w.path == ["same network n (L2)"]
    assert (w.sent.sip, w.sent.dip) == ("10.0.0.10", "10.0.0.20")


def test_egress_rule_required():
    c = two_vms_same_net([ingress(**tcp(22))], egress_rules=[egress(**tcp(80))])
    assert reach(c, "a", "b", SSH) is None
    assert reach(c, "a", "b", ServiceSpec.parse("tcp", 80)) is None  # ingress only allows 22


def test_port_range_and_protocol():
    c = two_vms_same_net([ingress(protocol="tcp", port_range_min=8000, port_range_max=8010)])
    assert reach(c, "a", "b", ServiceSpec.parse("tcp", 8005))
    assert reach(c, "a", "b", ServiceSpec.parse("tcp", 8011)) is None
    assert reach(c, "a", "b", ServiceSpec.parse("udp", 8005)) is None


def test_icmp_type():
    c = two_vms_same_net([ingress(protocol="icmp", port_range_min=8)])
    assert reach(c, "a", "b", ServiceSpec.parse("icmp", 8))
    assert reach(c, "a", "b", ServiceSpec.parse("icmp", 0)) is None


def test_remote_ip_prefix():
    c = two_vms_same_net([ingress(**tcp(22), remote_ip_prefix="10.0.0.0/28")])
    assert reach(c, "a", "b", SSH)  # 10.0.0.10 is inside /28
    c = two_vms_same_net([ingress(**tcp(22), remote_ip_prefix="10.0.0.16/28")])
    assert reach(c, "a", "b", SSH) is None


def test_remote_group_membership():
    c = two_vms_same_net([ingress(**tcp(22), remote_group_id="src")])
    assert reach(c, "a", "b", SSH)
    c = two_vms_same_net([ingress(**tcp(22), remote_group_id="dst")])
    assert reach(c, "a", "b", SSH) is None


def test_ipv6_rules_do_not_open_ipv4():
    c = two_vms_same_net([dict(direction="ingress", ethertype="IPv6")])
    assert reach(c, "a", "b") is None


def test_port_security_disabled_means_open_and_spoofable():
    c = Cloud()
    c.net("n", "10.0.0.0/24")
    c.sg("open", ingress(), egress())
    c.vm("a", "n", "10.0.0.10", [], port_security=False)
    c.vm("b", "n", "10.0.0.20", ["open"])
    w = reach(c, "a", "b")
    assert w is not None
    # with port security off the source may claim any address
    an = Analyzer(c.s)
    r = an.enc.reach(PortEP("a"), PortEP("b"))
    assert an.model(r.formula, an.enc.out_sip == int(ipaddress.IPv4Address("10.9.9.9"))) is not None
    # ... but not with it on
    c.s.ports[0].port_security_enabled = True
    c.s.ports[0].security_group_ids = ["open"]
    an = Analyzer(c.s)
    r = an.enc.reach(PortEP("a"), PortEP("b"))
    assert an.model(r.formula, an.enc.out_sip == int(ipaddress.IPv4Address("10.9.9.9"))) is None


def test_admin_down_port():
    c = two_vms_same_net([ingress()])
    c.s.ports[1].admin_state_up = False
    assert reach(c, "a", "b") is None


def routed_cloud(up=True):
    c = Cloud()
    c.net("n1", "10.0.1.0/24")
    c.net("n2", "10.0.2.0/24")
    c.net("n3", "10.0.3.0/24")
    c.router("r", ["n1", "n2"], up=up)
    c.sg("all", ingress(), egress())
    c.vm("a", "n1", "10.0.1.10", ["all"])
    c.vm("b", "n2", "10.0.2.10", ["all"])
    c.vm("x", "n3", "10.0.3.10", ["all"])
    return c


def test_routed_east_west():
    w = reach(routed_cloud(), "a", "b")
    assert w is not None and w.path[0].startswith("routed by r")
    assert w.delivered.sip == "10.0.1.10"  # no NAT east-west


def test_no_route_means_no_reach_even_with_open_sgs():
    assert reach(routed_cloud(), "a", "x") is None


def test_router_admin_down():
    assert reach(routed_cloud(up=False), "a", "b") is None


def edge_cloud():
    c = Cloud()
    c.net("public", "203.0.113.0/24", external=True)
    c.net("t1", "10.0.1.0/24")
    c.net("t2", "10.0.2.0/24")
    c.router("r1", ["t1"], gateway="public", gw_ip="203.0.113.1")
    c.router("r2", ["t2"], gateway="public", gw_ip="203.0.113.2")
    c.sg("out", egress())
    c.sg("ssh-world", ingress(**tcp(22)), egress())
    c.sg("ssh-from-r1", ingress(**tcp(22), remote_ip_prefix="203.0.113.1/32"), egress())
    c.sg("ssh-from-out-group", ingress(**tcp(22), remote_group_id="out"), egress())
    c.vm("client", "t1", "10.0.1.5", ["out"])
    c.vm("server", "t2", "10.0.2.5", ["ssh-world"])
    c.fip("203.0.113.50", "server", "10.0.2.5", "r2")
    return c


def test_internet_to_fip():
    w = reach(edge_cloud(), INTERNET, "server", SSH)
    assert w is not None
    assert w.sent.dip == "203.0.113.50" and w.delivered.dip == "10.0.2.5"
    assert not ipaddress.IPv4Address(w.sent.sip).is_private


def test_internet_needs_fip():
    c = edge_cloud()
    c.s.floating_ips.clear()
    assert reach(c, INTERNET, "server", SSH) is None


def test_internet_excludes_private_and_cloud_external_ranges():
    c = edge_cloud()
    c.s.security_groups[1].rules[0].remote_ip_prefix = "10.0.0.0/8"
    assert reach(c, INTERNET, "server", SSH) is None
    c.s.security_groups[1].rules[0].remote_ip_prefix = "203.0.113.0/24"
    assert reach(c, INTERNET, "server", SSH) is None
    # but explicitly asking about a private range works
    c.s.security_groups[1].rules[0].remote_ip_prefix = "10.0.0.0/8"
    assert reach(c, ExternalEP(cidrs=("10.99.0.0/16",)), "server", SSH)


def test_snat_hairpin_translates_source():
    c = edge_cloud()
    c.s.ports[1].security_group_ids = ["ssh-from-r1"]
    w = reach(c, "client", "server", SSH)
    assert w is not None
    assert w.delivered.sip == "203.0.113.1"  # r1's SNAT address
    assert any("SNAT via router r1" in p for p in w.path)


def test_remote_group_does_not_match_after_nat():
    c = edge_cloud()
    c.s.ports[1].security_group_ids = ["ssh-from-out-group"]
    assert reach(c, "client", "server", SSH) is None


def test_no_snat_no_egress():
    c = edge_cloud()
    c.s.routers[0].gateway.enable_snat = False
    assert reach(c, "client", "server", SSH) is None
    assert reach(c, "client", INTERNET) is None


def test_port_to_internet_via_snat():
    w = reach(edge_cloud(), "client", INTERNET, ServiceSpec.parse("tcp", 443))
    assert w is not None and w.delivered.sip == "203.0.113.1"


def test_port_directly_on_external_network():
    c = edge_cloud()
    c.vm("edge", "public", "203.0.113.9", ["ssh-world"])
    w = reach(c, INTERNET, "edge", SSH)
    assert w is not None and w.delivered.dip == "203.0.113.9"


def test_allowed_address_pair_receives_traffic():
    c = two_vms_same_net([ingress()])
    c.s.ports[1].allowed_address_pairs = ["10.0.0.100"]
    an = Analyzer(c.s)
    r = an.enc.reach(PortEP("a"), PortEP("b"))
    assert an.model(r.formula, an.enc.out_dip == int(ipaddress.IPv4Address("10.0.0.100"))) is not None


def test_witness_prefers_addresses_outside_the_cloud():
    """A cloud that numbers a tenant network from public space must not produce confusing witnesses."""
    c = Cloud()
    c.net("public", "203.0.113.0/24", external=True)
    c.net("t", "198.51.100.0/24")
    c.router("r", ["t"], gateway="public", gw_ip="203.0.113.1")
    c.sg("g", ingress(), egress())          # any protocol from anywhere
    c.vm("a", "t", "198.51.100.10", ["g"])
    c.fip("203.0.113.9", "a", "198.51.100.10", "r")
    w = reach(c, INTERNET, "a")
    assert w is not None
    assert ipaddress.IPv4Address(w.sent.sip) not in ipaddress.IPv4Network("198.51.100.0/24")


def test_lint_warns_about_address_group_rules():
    from osreach.snapshot import AddressGroup

    c = two_vms_same_net([ingress(**tcp(22), remote_address_group_id="ag")])
    c.s.address_groups.append(AddressGroup("ag", "admins", ["10.0.0.0/24"]))
    kinds = {f["kind"] for f in Analyzer(c.s).lint()}
    assert "address-group-rule" in kinds

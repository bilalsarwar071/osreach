import json
from pathlib import Path

from osreach.cli import main
from osreach.extract import normalize

EX = Path(__file__).resolve().parents[1] / "examples"


def test_normalize_neutron_api_shapes():
    """Raw Neutron API dicts (as openstacksdk exposes them) normalise correctly."""
    snap = normalize(
        networks=[{"id": "ext", "name": "public", "router:external": True},
                  {"id": "n1", "name": "private", "tenant_id": "p"}],
        subnets=[{"id": "s-ext", "network_id": "ext", "cidr": "203.0.113.0/24", "ip_version": 4},
                 {"id": "s1", "network_id": "n1", "cidr": "10.0.0.0/24", "ip_version": 4}],
        routers=[{"id": "r1", "name": "router", "admin_state_up": True,
                  "external_gateway_info": {
                      "network_id": "ext", "enable_snat": True,
                      "external_fixed_ips": [{"subnet_id": "s-ext", "ip_address": "203.0.113.2"}]}}],
        ports=[
            {"id": "rp", "network_id": "n1", "device_owner": "network:router_interface_distributed",
             "device_id": "r1", "fixed_ips": [{"subnet_id": "s1", "ip_address": "10.0.0.1"}]},
            {"id": "vm", "network_id": "n1", "device_owner": "compute:nova", "device_id": "srv",
             "fixed_ips": [{"subnet_id": "s1", "ip_address": "10.0.0.5"}], "security_groups": ["g"],
             "port_security_enabled": True, "allowed_address_pairs": [{"ip_address": "10.0.0.99", "mac_address": "x"}]},
        ],
        security_groups=[{"id": "g", "name": "web", "stateful": True, "security_group_rules": [
            {"id": "r", "direction": "ingress", "ethertype": "IPv4", "protocol": "tcp",
             "port_range_min": 22, "port_range_max": 22, "remote_ip_prefix": "0.0.0.0/0"}]}],
        floating_ips=[{"id": "f", "floating_ip_address": "203.0.113.9", "fixed_ip_address": "10.0.0.5",
                       "port_id": "vm", "router_id": "r1", "floating_network_id": "ext"}],
        servers=[{"id": "srv", "name": "web-1"}],
    )
    assert snap.networks[0].external and snap.networks[1].project_id == "p"
    assert snap.routers[0].interfaces[0].subnet_id == "s1"
    assert snap.routers[0].gateway.ips == ["203.0.113.2"]
    vm = snap.ports[1]
    assert vm.device_name == "web-1" and vm.security_group_ids == ["g"] and vm.allowed_address_pairs == ["10.0.0.99"]
    assert snap.security_groups[0].rules[0].port_range_min == 22

    from osreach.analysis import Analyzer

    rep = Analyzer(snap).exposure()
    assert rep[0]["name"] == "web-1" and rep[0]["exposures"][0]["service"] == "tcp/22"


def test_cli_exit_codes(capsys):
    before, after, pol = str(EX / "demo-before.json"), str(EX / "demo-after.json"), str(EX / "policy.yaml")
    assert main(["check", before, pol]) == 1
    assert main(["query", before, "--from", "vm:web-1", "--to", "vm:app-1", "--proto", "tcp", "--port", "8080"]) == 0
    assert main(["query", before, "--from", "internet", "--to", "vm:app-1", "--exit-code"]) == 0
    assert main(["diff", before, after, "--exit-code"]) == 1
    assert main(["diff", before, before, "--exit-code"]) == 0
    assert main(["lint", before, "--exit-code"]) == 1
    assert main(["query", before, "--from", "bogus", "--to", "all"]) == 2
    capsys.readouterr()
    assert main(["exposure", before, "--json", "--risky-only"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {e["name"] for e in data} == {"bastion-1", "debug-1", "db-1"}


def test_cli_anonymize_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("OSREACH_ANON_KEY", "k")
    out = tmp_path / "anon.json"
    assert main(["anonymize", str(EX / "demo-before.json"), "-o", str(out), "--keep-names"]) == 0
    assert main(["check", str(out), str(EX / "policy.yaml")]) == 1

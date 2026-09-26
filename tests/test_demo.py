"""End-to-end expectations on the bundled demo cloud."""

from pathlib import Path

import yaml

from osreach.analysis import Analyzer, diff
from osreach.snapshot import Snapshot

EX = Path(__file__).resolve().parents[1] / "examples"


def load(name):
    return Snapshot.load(EX / name)


def test_demo_files_are_up_to_date():
    import sys

    sys.path.insert(0, str(EX))
    import build_demo

    before = build_demo.build_before()
    assert before.to_dict() == load("demo-before.json").to_dict(), "run python examples/build_demo.py"
    assert build_demo.build_after(before).to_dict() == load("demo-after.json").to_dict()


def test_exposure_before():
    rep = {e["name"]: e for e in Analyzer(load("demo-before.json")).exposure()}
    assert set(rep) == {"web-1", "web-2", "bastion-1", "debug-1", "db-1", "edge-1"}
    assert {x["service"] for x in rep["web-1"]["exposures"]} == {"tcp/80", "tcp/443"}
    assert rep["db-1"]["risky"] and not rep["web-1"]["risky"]
    assert rep["debug-1"]["exposures"][0]["rule"] is None  # port security off
    # 5432 is only open to 10/8 and the web router's SNAT address: not the internet
    assert all(x["service"] != "tcp/5432" for x in rep["db-1"]["exposures"])


def test_policy_results_before():
    an = Analyzer(load("demo-before.json"))
    res = {r["name"]: r for r in an.check(yaml.safe_load((EX / "policy.yaml").read_text()))}
    failing = {n for n, r in res.items() if not r["holds"]}
    assert failing == {"no-ssh-from-internet", "web-team-cannot-reach-data-team-except-postgres",
                       "debug-vms-not-exposed"}
    ssh = res["no-ssh-from-internet"]
    assert {v["to"] for v in ssh["violations"]} == {"db-1", "debug-1"}
    cross = res["web-team-cannot-reach-data-team-except-postgres"]
    w = cross["violations"][0]["witness"]
    assert any("via external network" in p for p in w["path"])


def test_policy_results_after():
    an = Analyzer(load("demo-after.json"))
    res = {r["name"]: r for r in an.check(yaml.safe_load((EX / "policy.yaml").read_text()))}
    ssh = res["no-ssh-from-internet"]
    assert {v["to"] for v in ssh["violations"]} == {"app-1", "debug-1"}  # db fixed, app newly exposed


def test_empty_selector_is_a_failure_not_a_pass():
    an = Analyzer(load("demo-before.json"))
    r = an.check_invariant({"name": "x", "expect": "deny", "from": "internet", "to": "vm:does-not-exist"})
    assert not r["holds"] and "no endpoints" in r["error"]


def test_semantic_diff():
    d = diff(load("demo-before.json"), load("demo-after.json")).to_dict()
    grants = [c for c in d["rule_changes"] if c["change"] == "grants"]
    revokes = [c for c in d["rule_changes"] if c["change"] == "revokes"]
    assert [c["security_group"] for c in grants] == ["app"]
    assert [c["security_group"] for c in revokes] == ["db"]
    changes = {(c["from"], c["to"], c["change"]) for c in d["reachability_changes"]}
    assert changes == {("internet", "app-1", "now reachable"), ("internet", "db-1", "no longer reachable")}
    app = next(c for c in d["reachability_changes"] if c["to"] == "app-1")
    assert "tcp/22 (ssh)" in app["sensitive_services"]


def test_diff_of_identical_snapshots_is_empty():
    assert diff(load("demo-before.json"), load("demo-before.json"), pairs=True).empty


def test_lint():
    kinds = {(f["kind"], f.get("security_group")) for f in Analyzer(load("demo-before.json")).lint()}
    assert ("redundant-rule", "db") in kinds
    assert ("dangling-remote-group", "legacy-nfs") in kinds
    assert ("dead-rule", "legacy-nfs") not in kinds  # unused group: reported once, as unused-sg
    assert ("unused-sg", "legacy-nfs") in kinds
    assert ("port-security-disabled", None) in kinds

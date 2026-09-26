import ipaddress
import random
from pathlib import Path

import yaml

from osreach.analysis import Analyzer
from osreach.anonymize import Anonymizer
from osreach.common import NON_INTERNET
from osreach.snapshot import Snapshot

EX = Path(__file__).resolve().parents[1] / "examples"
KEY = b"test-key-not-secret"


def common_prefix(a: int, b: int) -> int:
    x = a ^ b
    return 32 if x == 0 else 32 - x.bit_length()


def test_prefix_preserving_and_injective():
    an = Anonymizer(KEY)
    rng = random.Random(7)
    xs = [rng.getrandbits(32) for _ in range(300)] + [int(ipaddress.IPv4Address("10.0.0.1")),
                                                     int(ipaddress.IPv4Address("10.0.0.2"))]
    ys = [an.ip_int(x) for x in xs]
    assert len(set(ys)) == len(set(xs))
    for i in range(0, len(xs) - 1, 2):
        assert common_prefix(xs[i], xs[i + 1]) == common_prefix(ys[i], ys[i + 1])


def test_special_ranges_preserved():
    an = Anonymizer(KEY)
    rng = random.Random(8)
    for _ in range(2000):
        x = rng.getrandbits(32)
        a, b = ipaddress.IPv4Address(x), ipaddress.IPv4Address(an.ip_int(x))
        for n in NON_INTERNET:
            assert (a in n) == (b in n), (a, b, n)


def test_cidr_maps_to_cidr_of_same_length():
    an = Anonymizer(KEY)
    n = ipaddress.IPv4Network(an.cidr("203.0.113.0/24"))
    assert n.prefixlen == 24
    assert ipaddress.IPv4Address(an.ip("203.0.113.77")) in n
    assert an.cidr("0.0.0.0/0") == "0.0.0.0/0"


def test_key_changes_mapping():
    assert Anonymizer(b"k1").ip("203.0.113.5") != Anonymizer(b"k2").ip("203.0.113.5")


def test_analysis_results_are_invariant_under_anonymisation():
    snap = Snapshot.load(EX / "demo-before.json")
    anon = Anonymizer(KEY, keep_names=True).snapshot(snap)
    assert anon.meta["sanitized"] is True
    assert {p.id for p in anon.ports}.isdisjoint({p.id for p in snap.ports})
    assert {f.ip for f in anon.floating_ips}.isdisjoint({f.ip for f in snap.floating_ips})

    policy = yaml.safe_load((EX / "policy.yaml").read_text())
    a, b = Analyzer(snap), Analyzer(anon)
    ra = [(r["name"], r["holds"], r["violation_count"]) for r in a.check(policy)]
    rb = [(r["name"], r["holds"], r["violation_count"]) for r in b.check(policy)]
    assert ra == rb

    def summary(an):
        return sorted((e["name"], sorted(x["service"] for x in e["exposures"]), e["risky"]) for e in an.exposure())

    assert summary(a) == summary(b)
    assert [f["kind"] for f in a.lint()] == [f["kind"] for f in b.lint()]


def test_names_are_hidden_by_default():
    anon = Anonymizer(KEY).snapshot(Snapshot.load(EX / "demo-before.json"))
    names = {p.device_name for p in anon.ports}
    assert "web-1" not in names and all(n.startswith("vm-") for n in names if n)

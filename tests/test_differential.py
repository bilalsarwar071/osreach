"""Differential testing: the Z3 encoding against the independent reference simulator.

For many random clouds and random concrete packets, "the formula is satisfiable
with the packet fixed" must coincide with "the simulator delivers the packet".
Agreement in both directions checks the encoding is neither missing paths nor
inventing them, relative to the reference semantics.
"""

import ipaddress
import random

from cloudkit import interesting_addresses, random_cloud

from osreach.analysis import Analyzer
from osreach.common import INTERNET, ExternalEP, PortEP
from osreach.reference import Pkt

SEEDS = range(60)
PACKETS_PER_PAIR = 12
PROTOS = [6, 6, 17, 1, 47, 0]
DPORTS = [0, 8, 21, 22, 23, 80, 90, 443, 8000, 8010, 8011, 65535]
EXTRA_EXTERNAL = ExternalEP(cidrs=("10.0.0.0/8",))


def ip(a):
    return int(ipaddress.IPv4Address(a))


def _symbolic(an, src, dst, sip, dip, proto, dport):
    r = an.enc.reach(src, dst)
    if not r.possible:
        return False
    e, o = an.enc, an.obs
    fixed = [o.proto == proto, o.dport == dport, e.out_sip == ip(sip), e.out_dip == ip(dip)]
    return an.model(r.formula, *fixed) is not None


def _concrete(an, src, dst, sip, dip, proto, dport):
    pkt = Pkt(ipaddress.IPv4Address(sip), ipaddress.IPv4Address(dip), proto, dport)
    sim, ports = an.sim, an.topo.ports
    if isinstance(src, PortEP) and isinstance(dst, PortEP):
        return any(p.id == dst.port_id for p, _, _ in sim.send(ports[src.port_id], pkt))
    if isinstance(src, ExternalEP):
        return any(p.id == dst.port_id for p, _ in sim.receive_external(src, pkt))
    return sim.send_external(ports[src.port_id], dst, pkt)


def _own(an, ep):
    if not isinstance(ep, PortEP):
        return ["1.2.3.4", "8.8.4.4", "10.1.2.3"]
    p = an.topo.ports[ep.port_id]
    return [f.ip for f in p.fixed_ips] + [f.ip for f in an.topo.fips_by_port.get(p.id, [])]


def test_encoding_matches_reference_on_random_clouds():
    checked = agreed_true = 0
    for seed in SEEDS:
        rng = random.Random(seed)
        snap = random_cloud(rng)
        an = Analyzer(snap)
        addrs = interesting_addresses(snap, rng)
        eps = [PortEP(p.id) for p in snap.ports] + [INTERNET, EXTRA_EXTERNAL]
        for s in eps:
            for d in eps:
                if s == d or (isinstance(s, ExternalEP) and isinstance(d, ExternalEP)):
                    continue
                near_s = _own(an, s) or addrs
                near_d = _own(an, d) or addrs
                for _ in range(PACKETS_PER_PAIR):
                    # bias towards addresses the endpoints actually own so positives are common
                    sip = rng.choice(near_s) if rng.random() < 0.7 else rng.choice(addrs)
                    dip = rng.choice(near_d) if rng.random() < 0.7 else rng.choice(addrs)
                    proto, dport = rng.choice(PROTOS), rng.choice(DPORTS)
                    sym = _symbolic(an, s, d, sip, dip, proto, dport)
                    con = _concrete(an, s, d, sip, dip, proto, dport)
                    assert sym == con, (seed, s, d, sip, dip, proto, dport, sym, con)
                    checked += 1
                    agreed_true += sym
    assert checked > 5000
    print("differential:", checked, "packets,", agreed_true, "delivered")
    assert agreed_true > 300, "generator too restrictive: almost nothing is reachable"


def test_every_witness_replays_on_random_clouds():
    """Analyzer.witness() replays each model in the simulator and raises on mismatch."""
    found = 0
    for seed in SEEDS:
        rng = random.Random(1000 + seed)
        snap = random_cloud(rng)
        an = Analyzer(snap)
        eps = [PortEP(p.id) for p in snap.ports] + [INTERNET]
        for s in eps:
            for d in eps:
                if s != d and not (isinstance(s, ExternalEP) and isinstance(d, ExternalEP)):
                    found += an.witness(s, d) is not None
    assert found > 50


def test_unsat_means_no_packet_in_reference():
    """When the solver says 'unreachable', brute force a slice of the space to agree."""
    for seed in range(15):
        rng = random.Random(5000 + seed)
        snap = random_cloud(rng)
        an = Analyzer(snap)
        addrs = interesting_addresses(snap, rng)
        ports = [PortEP(p.id) for p in snap.ports]
        for s in ports:
            for d in ports:
                if s == d or an.witness(s, d) is not None:
                    continue
                for sip in addrs:
                    for dip in addrs:
                        for proto, dport in ((6, 22), (17, 80), (1, 8), (47, 0)):
                            assert not _concrete(an, s, d, sip, dip, proto, dport), (seed, s, d, sip, dip)

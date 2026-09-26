"""Analyses built on the encoding: query, exposure, invariant checking, diff, lint."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Optional

import z3

from .common import (
    ICMP,
    INTERNET,
    PORT_PROTOS,
    Endpoint,
    ExternalEP,
    PortEP,
    ServiceSpec,
    UnsupportedProtocol,
    proto_label,
    proto_number,
    rule_port_range,
)
from .encode import Encoder, Observables, Reach, Witness, any_of, extract_witness
from .reference import Pkt, Simulator
from .selectors import endpoint_label, resolve_many
from .snapshot import Rule, SecurityGroup, Snapshot, Topology

SENSITIVE_TCP = {
    22: "ssh", 23: "telnet", 135: "msrpc", 139: "netbios", 445: "smb", 1433: "mssql",
    2375: "docker", 2376: "docker-tls", 2379: "etcd", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 5984: "couchdb", 6379: "redis", 6443: "kube-apiserver",
    8888: "jupyter", 9200: "elasticsearch", 10250: "kubelet", 11211: "memcached",
    11434: "ollama", 27017: "mongodb",
}
SENSITIVE_UDP = {161: "snmp", 11211: "memcached", 623: "ipmi"}
WIDE_RANGE = 1000
ANY_SERVICE = ServiceSpec()


class WitnessReplayError(RuntimeError):
    """The solver produced a witness the reference simulator rejects: a bug in osreach."""


class SolverUnknown(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Presentation helpers (kept here so JSON and text output agree)
# ---------------------------------------------------------------------------


def describe_service(proto: Optional[int], rng: Optional[tuple[int, int]]) -> str:
    if proto is None:
        return "any protocol"
    name = proto_label(proto)
    if rng is None or (proto not in PORT_PROTOS and proto != ICMP):
        return name
    lo, hi = rng
    if proto == ICMP:
        return f"icmp type {lo}"
    return f"{name}/{lo}" if lo == hi else f"{name}/{lo}-{hi}"


def rule_service(rule: Rule) -> tuple[Optional[int], Optional[tuple[int, int]]]:
    try:
        pn = proto_number(rule.protocol)
    except UnsupportedProtocol:
        return (-1, None)
    return pn, rule_port_range(rule)


def describe_rule(topo: Topology, rule: Rule) -> str:
    pn, rng = rule_service(rule)
    svc = f"protocol {rule.protocol!r}" if pn == -1 else describe_service(pn, rng)
    word = "from" if rule.direction == "ingress" else "to"
    if rule.remote_group_id:
        peer = f"members of {topo.sg_label(rule.remote_group_id)}"
    elif rule.remote_address_group_id:
        ag = topo.address_groups.get(rule.remote_address_group_id)
        peer = f"address-group {ag.name if ag and ag.name else rule.remote_address_group_id[:8]}"
    elif rule.remote_ip_prefix:
        peer = rule.remote_ip_prefix
    else:
        peer = "anywhere"
    v6 = " [IPv6]" if rule.ethertype != "IPv4" else ""
    return f"{rule.direction} {svc} {word} {peer}{v6}"


def rule_ref(topo: Topology, sg: SecurityGroup, rule: Rule) -> dict:
    return {"security_group": sg.name or sg.id[:8], "security_group_id": sg.id,
            "rule_id": rule.id, "rule": describe_rule(topo, rule)}


def witness_to_dict(topo: Topology, w: Witness) -> dict:
    return {
        "service": describe_service(w.proto, (w.dport, w.dport)),
        "proto": w.proto,
        "dport": w.dport if (w.proto in PORT_PROTOS or w.proto == ICMP) else None,
        "sent": {"src": w.sent.sip, "dst": w.sent.dip},
        "delivered": {"src": w.delivered.sip, "dst": w.delivered.dip},
        "path": w.path,
        "egress": "port security disabled" if w.egress_open else [rule_ref(topo, g, r) for g, r in w.egress_rules],
        "ingress": "port security disabled" if w.ingress_open else [rule_ref(topo, g, r) for g, r in w.ingress_rules],
    }


def sensitive_hits(proto: Optional[int], rng: Optional[tuple[int, int]]) -> list[str]:
    if proto is None:
        return ["all protocols and ports"]
    table = SENSITIVE_TCP if proto == 6 else SENSITIVE_UDP if proto == 17 else {}
    if not table:
        return []
    if rng is None:
        return [f"all {proto_label(proto)} ports"]
    lo, hi = rng
    hits = [f"{proto_label(proto)}/{p} ({n})" for p, n in sorted(table.items()) if lo <= p <= hi]
    if hi - lo + 1 >= WIDE_RANGE:
        hits.insert(0, f"wide range {lo}-{hi}")
    return hits


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class Analyzer:
    def __init__(self, snap: Snapshot, obs: Optional[Observables] = None, tag: str = ""):
        self.snap = snap
        self.topo = Topology(snap)
        self.sim = Simulator(snap)
        self.obs = obs or Observables.fresh(tag)
        self.enc = Encoder(self.topo, self.obs, tag)
        self.solver = z3.Solver()
        self.solver_calls = 0

    # ----------------------------------------------------------- plumbing
    def preferences(self) -> list[z3.BoolRef]:
        """Soft constraints that make witnesses easier to read; each is kept only if still satisfiable."""
        o = self.obs
        low = z3.Extract(7, 0, o.ext)
        return [
            o.proto == 6,                                   # prefer TCP when the protocol is free
            z3.Implies(o.proto == ICMP, o.dport == 8),      # ICMP echo request
            z3.Implies(o.proto != ICMP, o.dport != 0),      # a real port number
            z3.And(low != 0, low != 255),                   # a host address, not .0 / .255
        ]

    def model(self, *formulas: z3.BoolRef, solver: Optional[z3.Solver] = None,
              nice: bool = False) -> Optional[z3.ModelRef]:
        s = solver or self.solver
        s.push()
        try:
            s.add(*formulas)
            self.solver_calls += 1
            r = s.check()
            if r == z3.unknown:
                raise SolverUnknown(s.reason_unknown())
            if r != z3.sat:
                return None
            m = s.model()
            if nice:
                kept = 0
                for pref in self.preferences():
                    s.push()
                    s.add(pref)
                    self.solver_calls += 1
                    if s.check() == z3.sat:
                        m, kept = s.model(), kept + 1
                    else:
                        s.pop()
                for _ in range(kept):
                    s.pop()
            return m
        finally:
            s.pop()

    def label(self, ep: Endpoint) -> str:
        return endpoint_label(self.topo, ep)

    def resolve(self, selectors, excludes=()) -> list[Endpoint]:
        return resolve_many(self.topo, selectors, excludes)

    def replay(self, reach: Reach, w: Witness) -> None:
        ip = ipaddress.IPv4Address
        sent = Pkt(ip(w.sent.sip), ip(w.sent.dip), w.proto, w.dport)
        got = Pkt(ip(w.delivered.sip), ip(w.delivered.dip), w.proto, w.dport)
        src, dst = reach.src, reach.dst
        if isinstance(src, PortEP) and isinstance(dst, PortEP):
            ok = any(p.id == dst.port_id and q == got for p, q, _ in self.sim.send(self.topo.ports[src.port_id], sent))
        elif isinstance(src, ExternalEP) and isinstance(dst, PortEP):
            ok = any(p.id == dst.port_id and q == got for p, q in self.sim.receive_external(src, sent))
        elif isinstance(src, PortEP) and isinstance(dst, ExternalEP):
            ok = self.sim.send_external(self.topo.ports[src.port_id], dst, sent)
        else:
            ok = False
        if not ok:
            raise WitnessReplayError(
                f"witness {self.label(src)} -> {self.label(dst)} {w} was rejected by the reference simulator; "
                "please report this as a bug"
            )

    def witness(self, src: Endpoint, dst: Endpoint, spec: ServiceSpec = ANY_SERVICE,
                extra: Iterable[z3.BoolRef] = ()) -> Optional[Witness]:
        reach = self.enc.reach(src, dst)
        if not reach.possible:
            return None
        m = self.model(reach.formula, self.obs.constrain(spec), *extra, nice=True)
        if m is None:
            return None
        w = extract_witness(self.enc, reach, m)
        self.replay(reach, w)
        return w

    # -------------------------------------------------------------- query
    def query(self, srcs: list[Endpoint], dsts: list[Endpoint], spec: ServiceSpec) -> list[dict]:
        out = []
        for s in srcs:
            for d in dsts:
                if s == d or (isinstance(s, ExternalEP) and isinstance(d, ExternalEP)):
                    continue
                w = self.witness(s, d, spec)
                out.append({"from": self.label(s), "to": self.label(d), "service": spec.describe(),
                            "reachable": w is not None,
                            "witness": witness_to_dict(self.topo, w) if w else None})
        return out

    # ----------------------------------------------------------- exposure
    def exposure(self, targets: Optional[list[Endpoint]] = None, source: ExternalEP = INTERNET) -> list[dict]:
        targets = targets if targets is not None else [PortEP(p.id) for p in self.topo.instance_ports()]
        report = []
        for ep in targets:
            if not isinstance(ep, PortEP):
                continue
            port = self.topo.ports[ep.port_id]
            reach = self.enc.reach(source, ep)
            if not reach.possible:
                continue
            entries = []
            if not port.port_security_enabled:
                m = self.model(reach.formula, nice=True)
                if m is not None:
                    w = extract_witness(self.enc, reach, m)
                    self.replay(reach, w)
                    entries.append({"rule": None, "service": "any protocol (port security disabled)",
                                    "risk": ["port security disabled: no filtering at all"],
                                    "witness": witness_to_dict(self.topo, w)})
            else:
                for sg, rule, f in self.enc.matching_rules(port, "ingress"):
                    m = self.model(reach.formula, f, nice=True)
                    if m is None:
                        continue
                    w = extract_witness(self.enc, reach, m)
                    self.replay(reach, w)
                    pn, rng = rule_service(rule)
                    entries.append({"rule": rule_ref(self.topo, sg, rule),
                                    "service": describe_service(pn, rng),
                                    "risk": sensitive_hits(pn, rng),
                                    "witness": witness_to_dict(self.topo, w)})
            if entries:
                addrs = [f.ip for f in self.topo.fips_by_port.get(port.id, [])]
                if self.topo.on_external(port):
                    addrs += [str(a) for _, a in self.topo.fixed_v4(port)]
                report.append({"port_id": port.id, "name": self.label(ep),
                               "project": self.topo.project_name(port.project_id),
                               "addresses": addrs, "exposures": entries,
                               "risky": any(e["risk"] for e in entries)})
        return report

    # -------------------------------------------------------------- check
    def check(self, policy: dict, max_witnesses: int = 3) -> list[dict]:
        results = []
        for inv in policy.get("invariants", []):
            results.append(self.check_invariant(inv, max_witnesses))
        return results

    def check_invariant(self, inv: dict, max_witnesses: int = 3) -> dict:
        name = inv.get("name", "<unnamed>")
        expect = inv.get("expect", "deny")
        if expect not in ("deny", "allow"):
            raise ValueError(f"invariant {name}: expect must be 'deny' or 'allow'")
        spec = ServiceSpec.parse(inv.get("proto"), inv.get("port"))
        srcs = self.resolve(inv["from"], inv.get("from_except", ()))
        dsts = self.resolve(inv["to"], inv.get("to_except", ()))
        res = {"name": name, "description": inv.get("description", ""), "expect": expect,
               "service": spec.describe(), "pairs_checked": 0, "violations": [], "violation_count": 0}
        if not srcs or not dsts:
            res["holds"] = False
            res["error"] = (f"selector matched no endpoints (from: {len(srcs)}, to: {len(dsts)}); "
                            "refusing to pass vacuously")
            return res
        for s in srcs:
            for d in dsts:
                if s == d or (isinstance(s, ExternalEP) and isinstance(d, ExternalEP)):
                    continue
                res["pairs_checked"] += 1
                w = self.witness(s, d, spec)
                bad = (w is not None) if expect == "deny" else (w is None)
                if not bad:
                    continue
                res["violation_count"] += 1
                if len(res["violations"]) < max_witnesses:
                    v = {"from": self.label(s), "to": self.label(d)}
                    if w is not None:
                        v["witness"] = witness_to_dict(self.topo, w)
                    else:
                        v["reason"] = f"no {spec.describe()} can be delivered"
                    res["violations"].append(v)
        res["holds"] = res["violation_count"] == 0
        return res

    # --------------------------------------------------------------- lint
    def lint(self) -> list[dict]:
        t, enc, peer = self.topo, self.enc, self.obs.ext
        findings: list[dict] = []

        def add(severity, kind, message, **kw):
            findings.append({"severity": severity, "kind": kind, "message": message, **kw})

        used = {g for p in self.snap.ports for g in p.security_group_ids}
        for sg in self.snap.security_groups:
            if not sg.stateful:
                add("warning", "stateless-sg", f"{sg.name}: stateless security group; osreach models connection "
                    "initiation only, return traffic needs its own rules", security_group=sg.name)
            if sg.id not in used:
                add("info", "unused-sg", f"{sg.name}: not attached to any port", security_group=sg.name)
            for direction in ("ingress", "egress"):
                rules = [r for r in sg.rules if r.direction == direction and r.ethertype == "IPv4"]
                matches = {r.id: enc.rule_match(r, peer) for r in rules}
                redundant: set[str] = set()
                for r in rules:
                    if r.remote_group_id and r.remote_group_id not in t.sgs:
                        add("warning", "dangling-remote-group", f"{sg.name}: {describe_rule(t, r)} refers to a "
                            "security group that is not in the snapshot", security_group=sg.name, rule_id=r.id)
                    if self.model(matches[r.id]) is None:
                        redundant.add(r.id)
                        if sg.id not in used:
                            continue  # the whole group is unused; reported once above
                        add("warning", "dead-rule", f"{sg.name}: {describe_rule(t, r)} can never match "
                            "(empty remote group or address group?)", security_group=sg.name, rule_id=r.id)
                        redundant.add(r.id)
                        continue
                    others = [o for o in rules if o.id != r.id and o.id not in redundant]
                    if not others:
                        continue
                    if self.model(matches[r.id], z3.Not(any_of(matches[o.id] for o in others))) is None:
                        redundant.add(r.id)
                        cover = [o for o in others if self.model(matches[r.id], z3.Not(matches[o.id])) is None]
                        by = describe_rule(t, cover[0]) if cover else "the combination of the other rules"
                        add("info", "redundant-rule", f"{sg.name}: {describe_rule(t, r)} is subsumed by {by}",
                            security_group=sg.name, rule_id=r.id)
        for p in self.snap.ports:
            if not p.port_security_enabled and t.is_instance(p):
                exposed = bool(t.fips_by_port.get(p.id)) or t.on_external(p)
                add("critical" if exposed else "warning", "port-security-disabled",
                    f"{t.label(p)}: port security disabled" + (" on an externally reachable port" if exposed else ""),
                    port_id=p.id)
        v6 = sum(1 for g in self.snap.security_groups for r in g.rules if r.ethertype != "IPv4")
        if v6:
            add("info", "ipv6-not-modelled", f"{v6} IPv6 rules were not analysed (IPv4 only)")
        for w in sorted(set(enc.warnings)):
            add("warning", "model", w)
        order = {"critical": 0, "warning": 1, "info": 2}
        return sorted(findings, key=lambda f: order[f["severity"]])


# ---------------------------------------------------------------------------
# Semantic diff between two snapshots
# ---------------------------------------------------------------------------


@dataclass
class DiffResult:
    sg_added: list[str] = field(default_factory=list)
    sg_removed: list[str] = field(default_factory=list)
    rule_changes: list[dict] = field(default_factory=list)
    reach_changes: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"security_groups_added": self.sg_added, "security_groups_removed": self.sg_removed,
                "rule_changes": self.rule_changes, "reachability_changes": self.reach_changes}

    @property
    def empty(self) -> bool:
        return not (self.sg_added or self.sg_removed or self.rule_changes or self.reach_changes)


def diff(old: Snapshot, new: Snapshot, pairs: bool = False) -> DiffResult:
    obs = Observables.fresh("")
    A = Analyzer(old, obs, "_old")
    B = Analyzer(new, obs, "_new")
    solver = z3.Solver()
    res = DiffResult()
    peer = obs.ext

    old_sgs = {g.id: g for g in old.security_groups}
    new_sgs = {g.id: g for g in new.security_groups}
    res.sg_added = sorted(new_sgs[i].name or i for i in new_sgs.keys() - old_sgs.keys())
    res.sg_removed = sorted(old_sgs[i].name or i for i in old_sgs.keys() - new_sgs.keys())

    def example(m) -> dict:
        pr = m.eval(obs.proto, model_completion=True).as_long()
        dp = m.eval(obs.dport, model_completion=True).as_long()
        ip = str(ipaddress.IPv4Address(m.eval(peer, model_completion=True).as_long()))
        return {"service": describe_service(pr, (dp, dp)), "peer": ip}

    for gid in sorted(old_sgs.keys() & new_sgs.keys()):
        go, gn = old_sgs[gid], new_sgs[gid]
        for direction in ("ingress", "egress"):
            ro = [r for r in go.rules if r.direction == direction]
            rn = [r for r in gn.rules if r.direction == direction]
            mo = {r.id: A.enc.rule_match(r, peer) for r in ro}
            mn = {r.id: B.enc.rule_match(r, peer) for r in rn}
            allow_o, allow_n = any_of(mo.values()), any_of(mn.values())
            for r in rn:
                m = A.model(mn[r.id], z3.Not(allow_o), solver=solver, nice=True)
                if m is not None:
                    res.rule_changes.append({"security_group": gn.name, "direction": direction, "change": "grants",
                                             "rule": describe_rule(B.topo, r), "rule_id": r.id,
                                             "example": example(m)})
            for r in ro:
                m = A.model(mo[r.id], z3.Not(allow_n), solver=solver, nice=True)
                if m is not None:
                    res.rule_changes.append({"security_group": go.name, "direction": direction, "change": "revokes",
                                             "rule": describe_rule(A.topo, r), "rule_id": r.id,
                                             "example": example(m)})

    old_ports = {p.id for p in A.topo.instance_ports()}
    new_ports = {p.id for p in B.topo.instance_ports()}
    endpoints = sorted(old_ports | new_ports)
    todo: list[tuple[Endpoint, Endpoint]] = [(INTERNET, PortEP(p)) for p in endpoints]
    if pairs:
        todo += [(PortEP(a), PortEP(b)) for a in endpoints for b in endpoints if a != b]

    def reach_in(an: Analyzer, ids: set[str], s: Endpoint, d: Endpoint) -> Reach:
        for ep in (s, d):
            if isinstance(ep, PortEP) and ep.port_id not in ids:
                return Reach(s, d, z3.BoolVal(False))
        return an.enc.reach(s, d)

    for s, d in todo:
        r_old = reach_in(A, old_ports, s, d)
        r_new = reach_in(B, new_ports, s, d)
        if not r_old.possible and not r_new.possible:
            continue
        for label, here, there, an in (("now reachable", r_new, r_old, B), ("no longer reachable", r_old, r_new, A)):
            if not here.possible:
                continue
            blocked_there = z3.Not(z3.Exists(there.hidden, there.formula)) if there.possible else z3.BoolVal(True)
            m = A.model(here.formula, blocked_there, solver=solver, nice=True)
            if m is None:
                continue
            w = extract_witness(an.enc, here, m)
            an.replay(here, w)
            notable = [
                f"{proto_label(pn)}/{port} ({svc})"
                for pn, table in ((6, SENSITIVE_TCP), (17, SENSITIVE_UDP))
                for port, svc in sorted(table.items())
                if A.model(here.formula, blocked_there, obs.proto == pn, obs.dport == port, solver=solver) is not None
            ]
            res.reach_changes.append({"from": an.label(s), "to": an.label(d), "change": label,
                                      "sensitive_services": notable,
                                      "witness": witness_to_dict(an.topo, w)})
    return res

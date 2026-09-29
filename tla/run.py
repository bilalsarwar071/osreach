#!/usr/bin/env python3
"""Run every TLA+ model in this directory with TLC and check the results.

    python tla/run.py                 # needs Java 11+ and tla2tools.jar
    TLA2TOOLS_JAR=/path/tla2tools.jar python tla/run.py

Two groups of models:

* migration_*.cfg  SGMigration: is a procedure for changing security groups
                   safe, and under which assumptions? (model checking)
* traces/*.json    SGTrace: which hypotheses about the data plane can explain
                   a recorded sequence of API calls and probe results?
                   (trace validation), plus the outcomes of a proposed
                   experiment, to show that it tells the survivors apart.

Exits non-zero if any result differs from the expectation recorded below.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
HYPS = ["H0", "H2a_all", "H2a_dir", "H2b_all", "H2b_dir", "H3", "H4"]

# ---- expectations ------------------------------------------------------------

MIGRATION = {
    "migration_ingress_safe": "ok",
    "migration_ingress_wrong_order": "KeepAccess",
    "migration_ingress_nowait_fifo": "ok",
    "migration_ingress_nowait_any": "KeepAccess",
    "migration_egress_safe": "ok",
    "migration_egress_wrong_order": "KeepAccess",
    "migration_egress_forgot_default": "DoneMeansGoal",
}

TRACE_EXPECT = {
    "sg-address-group-incident": {"H2a_dir", "H2b_dir", "H3"},
}

# Proposed experiment on a disposable VM "t" whose only group "x" holds fresh rules:
#   probe egress (baseline) -> add an AG egress rule -> probe (A) -> delete it -> probe (B)
EXPERIMENT_EXPECT = {
    "TT": {"H0", "H3"},
    "TF": {"H2b_dir"},
    "FF": {"H2a_dir"},
    "FT": {"H4"},
}


def experiment_trace(a: bool, b: bool) -> dict:
    admin = {"ev": "probe", "vm": "t", "dir": "in", "peer": "admin", "ok": True}
    inet = lambda ok: {"ev": "probe", "vm": "t", "dir": "out", "peer": "internet", "ok": ok}  # noqa: E731
    return {
        "name": f"experiment-{'T' if a else 'F'}{'T' if b else 'F'}",
        "vms": {"t": ["x"]},
        "init_rules": [
            {"id": 1, "g": "x", "dir": "in", "peer": "admin", "kind": "cidr"},
            {"id": 2, "g": "x", "dir": "out", "peer": "any", "kind": "cidr"},
        ],
        "events": [
            admin, inet(True),
            {"ev": "add", "id": 3, "g": "x", "dir": "out", "peer": "internet", "kind": "ag"},
            admin, inet(a),
            {"ev": "del", "id": 3},
            admin, inet(b),
        ],
    }


# ---- TLA+ generation ---------------------------------------------------------


def tla(v) -> str:
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, dict):
        return "[" + ", ".join(f"{k} |-> {tla(x)}" for k, x in v.items() if k != "note") + "]"
    raise TypeError(v)


def trace_module(name: str, t: dict) -> str:
    rules = "{" + ", ".join(tla(r) for r in t["init_rules"]) + "}"
    attach = " @@ ".join(f'({json.dumps(vm)} :> {{{", ".join(json.dumps(g) for g in gs)}}})'
                         for vm, gs in t["vms"].items())
    events = "<<\n    " + ",\n    ".join(tla(e) for e in t["events"]) + "\n  >>"
    return (f"---- MODULE {name} ----\nEXTENDS SGTrace, TLC\n"
            f"TraceDef == {events}\nInitRulesDef == {rules}\nInitAttachDef == {attach}\n====\n")


def trace_cfg(hyp: str) -> str:
    return (f'CONSTANTS\n  Hyp = "{hyp}"\n  Trace <- TraceDef\n  InitRules <- InitRulesDef\n'
            f"  InitAttach <- InitAttachDef\nSPECIFICATION Spec\nINVARIANT NotAccepted\nCHECK_DEADLOCK FALSE\n")


# ---- running TLC -------------------------------------------------------------


def find_jar() -> Path:
    for c in (os.environ.get("TLA2TOOLS_JAR"), HERE / "tla2tools.jar"):
        if c and Path(c).is_file():
            return Path(c)
    sys.exit("tla2tools.jar not found: download it from https://github.com/tlaplus/tlaplus/releases "
             "into tla/ or set TLA2TOOLS_JAR")


def tlc(jar: Path, workdir: Path, module: str, cfg: Path) -> str:
    out = subprocess.run(
        ["java", "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC", "-workers", "1",
         "-metadir", str(workdir / "states" / cfg.stem), "-config", str(cfg), module],
        cwd=workdir, capture_output=True, text=True, timeout=600,
    ).stdout
    if "Model checking completed. No error has been found." in out:
        return "ok"
    m = re.search(r"Invariant (\w+) is violated", out)
    if m:
        return m.group(1)
    raise RuntimeError(f"unexpected TLC output for {cfg.name}:\n{out[-3000:]}")


def main() -> int:
    jar = find_jar()
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for f in ("SGMigration.tla", "MCMigration.tla", "SGTrace.tla"):
            shutil.copy(HERE / f, work / f)

        print("Procedure models (SGMigration)")
        for name, expected in MIGRATION.items():
            got = tlc(jar, work, "MCMigration", HERE / "models" / f"{name}.cfg")
            ok = got == expected
            failures += not ok
            verdict = "no violation" if got == "ok" else f"{got} violated"
            print(f"  {'PASS' if ok else 'FAIL'}  {name:<34} {verdict}")

        def validate(t: dict) -> set[str]:
            mod = "TV_" + re.sub(r"\W", "_", t["name"])
            (work / f"{mod}.tla").write_text(trace_module(mod, t))
            accepted = set()
            for h in HYPS:
                cfg = work / f"{mod}_{h}.cfg"
                cfg.write_text(trace_cfg(h))
                if tlc(jar, work, mod, cfg) == "NotAccepted":
                    accepted.add(h)
            return accepted

        print("\nTrace validation (SGTrace)")
        survivors = set(HYPS)
        for path in sorted((HERE / "traces").glob("*.json")):
            t = json.loads(path.read_text())
            acc = validate(t)
            exp = TRACE_EXPECT.get(t["name"])
            ok = exp is None or acc == exp
            failures += not ok
            survivors &= acc
            print(f"  {'PASS' if ok else 'FAIL'}  {t['name']}  ({len(t['events'])} events)")
            for h in HYPS:
                print(f"          {h:<8} {'accepted' if h in acc else 'rejected'}")

        print(f"\nProposed experiment: which surviving hypothesis ({', '.join(sorted(survivors))}) "
              "does each outcome leave?")
        for outcome, exp in EXPERIMENT_EXPECT.items():
            acc = validate(experiment_trace(outcome[0] == "T", outcome[1] == "T"))
            ok = acc == exp
            failures += not ok
            left = sorted(acc & survivors) or ["none: a new explanation is needed"]
            print(f"  {'PASS' if ok else 'FAIL'}  A={outcome[0]} B={outcome[1]}  ->  {', '.join(left)}")

    print("\nall results as expected" if not failures else f"\n{failures} unexpected result(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

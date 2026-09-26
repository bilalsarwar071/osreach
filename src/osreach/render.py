"""Plain-text rendering of analysis results (JSON output bypasses this)."""

from __future__ import annotations

import os
import sys

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


def red(s): return _c("31", s)  # noqa: E704
def green(s): return _c("32", s)  # noqa: E704
def yellow(s): return _c("33", s)  # noqa: E704
def bold(s): return _c("1", s)  # noqa: E704
def dim(s): return _c("2", s)  # noqa: E704


def _rules(x) -> str:
    if isinstance(x, str):
        return x
    if not x:
        return "-"
    return "; ".join(f"{r['security_group']}: {r['rule']}" for r in x)


def witness(w: dict, indent: str = "    ") -> list[str]:
    lines = [f"{indent}service   {w['service']}"]
    s, d = w["sent"], w["delivered"]
    lines.append(f"{indent}sent      {s['src']} -> {s['dst']}")
    if (s["src"], s["dst"]) != (d["src"], d["dst"]):
        lines.append(f"{indent}delivered {d['src']} -> {d['dst']}")
    for p in w["path"]:
        lines.append(f"{indent}path      {p}")
    if w["egress"] != []:
        lines.append(f"{indent}egress    {_rules(w['egress'])}")
    lines.append(f"{indent}ingress   {_rules(w['ingress'])}")
    return lines


def query(results: list[dict]) -> str:
    out = []
    for r in results:
        head = f"{r['from']} -> {r['to']} ({r['service']}): "
        if r["reachable"]:
            out.append(head + red("REACHABLE"))
            out += witness(r["witness"])
        else:
            out.append(head + green("unreachable"))
    return "\n".join(out)


def exposure(report: list[dict], source: str) -> str:
    if not report:
        return green(f"No instance port is reachable from {source}.")
    out = [bold(f"Reachable from {source}: {len(report)} port(s)"), ""]
    for e in report:
        flag = red("RISK ") if e["risky"] else "     "
        addrs = ", ".join(e["addresses"]) or "-"
        out.append(f"{flag}{bold(e['name'])}  [{e['project']}]  {addrs}")
        for x in e["exposures"]:
            rule = x["rule"]["security_group"] + ": " + x["rule"]["rule"] if x["rule"] else "port security disabled"
            risk = ("  " + yellow("! " + ", ".join(x["risk"]))) if x["risk"] else ""
            ex = x["witness"]
            out.append(f"       - {x['service']:<22} {dim(rule)}{risk}")
            out.append(dim(f"         e.g. {ex['sent']['src']} -> {ex['sent']['dst']} "
                           f"({ex['service']}) via {'; '.join(ex['path'])}"))
        out.append("")
    return "\n".join(out).rstrip()


def check(results: list[dict]) -> str:
    out = []
    for r in results:
        status = green("PASS") if r["holds"] else red("FAIL")
        out.append(f"{status}  {bold(r['name'])}  ({r['expect']} {r['service']}; {r['pairs_checked']} pairs)")
        if r.get("description"):
            out.append(dim(f"      {r['description']}"))
        if r.get("error"):
            out.append(yellow(f"      {r['error']}"))
        for v in r["violations"]:
            out.append(f"      {v['from']} -> {v['to']}" + (f": {v['reason']}" if "reason" in v else ""))
            if "witness" in v:
                out += witness(v["witness"], indent="        ")
        more = r["violation_count"] - len(r["violations"])
        if more > 0:
            out.append(dim(f"      ... and {more} more violating pair(s)"))
    passed = sum(r["holds"] for r in results)
    out.append("")
    out.append(bold(f"{passed}/{len(results)} invariants hold"))
    return "\n".join(out)


def diff(d: dict) -> str:
    out = []
    for g in d["security_groups_added"]:
        out.append(f"+ security group {g}")
    for g in d["security_groups_removed"]:
        out.append(f"- security group {g}")
    if d["rule_changes"]:
        out.append(bold("Security group semantics"))
        for c in d["rule_changes"]:
            mark = red("+ grants ") if c["change"] == "grants" else green("- revokes")
            ex = c["example"]
            out.append(f"  {mark} {c['security_group']}: {c['rule']}")
            word = "from" if c["direction"] == "ingress" else "to"
            out.append(dim(f"             e.g. {ex['service']} {word} {ex['peer']}"))
    if d["reachability_changes"]:
        out.append(bold("Reachability"))
        for c in d["reachability_changes"]:
            mark = red("+") if c["change"] == "now reachable" else green("-")
            out.append(f"  {mark} {c['from']} -> {c['to']}: {c['change']} ({c['witness']['service']})")
            if c.get("sensitive_services"):
                shown = c["sensitive_services"][:8]
                extra = len(c["sensitive_services"]) - len(shown)
                out.append(yellow("      sensitive " + ", ".join(shown) + (f" and {extra} more" if extra > 0 else "")))
            out += witness(c["witness"], indent="      ")
    if not out:
        return green("No semantic difference.")
    return "\n".join(out)


def lint(findings: list[dict]) -> str:
    if not findings:
        return green("No findings.")
    paint = {"critical": red, "warning": yellow, "info": dim}
    return "\n".join(f"{paint[f['severity']](f['severity'].upper().ljust(9))} {f['kind']:<24} {f['message']}"
                     for f in findings)

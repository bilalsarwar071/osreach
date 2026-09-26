"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

from . import __version__, render
from .analysis import Analyzer, diff
from .common import ExternalEP, ServiceSpec
from .selectors import SelectorError
from .snapshot import Snapshot


def _emit(args, data, text: str) -> None:
    if getattr(args, "json", False):
        json.dump(data, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(text)


def cmd_snapshot(args) -> int:
    from .extract import snapshot_from_cloud

    snap = snapshot_from_cloud(args.cloud, with_servers=not args.no_servers)
    snap.save(args.output)
    print(f"wrote {args.output}: {len(snap.ports)} ports, {len(snap.security_groups)} security groups, "
          f"{len(snap.routers)} routers, {len(snap.floating_ips)} floating IPs", file=sys.stderr)
    print("this file describes your cloud's network; run `osreach anonymize` before sharing it", file=sys.stderr)
    return 0


def _read_key(args) -> bytes:
    if args.key_file:
        return Path(args.key_file).read_bytes().strip()
    env = os.environ.get("OSREACH_ANON_KEY")
    if env:
        return env.encode()
    raise SystemExit("an anonymisation key is required: --key-file FILE or OSREACH_ANON_KEY "
                     "(use the same key for snapshots you want to diff)")


def cmd_anonymize(args) -> int:
    from .anonymize import Anonymizer

    anon = Anonymizer(_read_key(args), keep_names=args.keep_names, keep_ips=args.keep_ips)
    anon.snapshot(Snapshot.load(args.snapshot)).save(args.output)
    print(f"wrote {args.output}", file=sys.stderr)
    return 0


def cmd_query(args) -> int:
    an = Analyzer(Snapshot.load(args.snapshot))
    spec = ServiceSpec.parse(args.proto, args.port)
    srcs, dsts = an.resolve(args.src), an.resolve(args.dst)
    if not srcs or not dsts:
        raise SelectorError(f"selector matched nothing (from: {len(srcs)}, to: {len(dsts)})")
    res = an.query(srcs, dsts, spec)
    _emit(args, res, render.query(res))
    return 1 if args.exit_code and any(r["reachable"] for r in res) else 0


def cmd_exposure(args) -> int:
    an = Analyzer(Snapshot.load(args.snapshot))
    source = an.resolve(args.src)
    if len(source) != 1 or not isinstance(source[0], ExternalEP):
        raise SelectorError("--from must be 'internet' or a single cidr: selector")
    targets = an.resolve(args.dst) if args.dst else None
    rep = an.exposure(targets, source[0])
    if args.risky_only:
        rep = [e for e in rep if e["risky"]]
    _emit(args, rep, render.exposure(rep, source[0].label))
    return 1 if args.exit_code and any(e["risky"] for e in rep) else 0


def cmd_check(args) -> int:
    an = Analyzer(Snapshot.load(args.snapshot))
    policy = yaml.safe_load(Path(args.policy).read_text()) or {}
    res = an.check(policy, max_witnesses=args.max_witnesses)
    _emit(args, res, render.check(res))
    return 0 if all(r["holds"] for r in res) else 1


def cmd_diff(args) -> int:
    d = diff(Snapshot.load(args.old), Snapshot.load(args.new), pairs=args.pairs)
    data = d.to_dict()
    _emit(args, data, render.diff(data))
    if args.exit_code:
        grows = any(c["change"] == "now reachable" for c in data["reachability_changes"]) or \
            any(c["change"] == "grants" for c in data["rule_changes"])
        return 1 if grows else 0
    return 0


def cmd_lint(args) -> int:
    an = Analyzer(Snapshot.load(args.snapshot))
    f = an.lint()
    _emit(args, f, render.lint(f))
    return 1 if args.exit_code and any(x["severity"] == "critical" for x in f) else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="osreach", description="SMT-based reachability verification for OpenStack Neutron")
    p.add_argument("--version", action="version", version=f"osreach {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def with_json(sp):
        sp.add_argument("--json", action="store_true", help="machine-readable output")
        return sp

    s = sub.add_parser("snapshot", help="capture Neutron state from a live cloud (needs openstacksdk)")
    s.add_argument("--cloud", help="clouds.yaml entry (default: OS_* environment variables)")
    s.add_argument("-o", "--output", required=True)
    s.add_argument("--no-servers", action="store_true", help="skip Nova lookups for instance names")
    s.set_defaults(fn=cmd_snapshot)

    s = sub.add_parser("anonymize", help="keyed, analysis-preserving anonymisation of a snapshot")
    s.add_argument("snapshot")
    s.add_argument("-o", "--output", required=True)
    s.add_argument("--key-file", help="secret key (or set OSREACH_ANON_KEY)")
    s.add_argument("--keep-names", action="store_true")
    s.add_argument("--keep-ips", action="store_true")
    s.set_defaults(fn=cmd_anonymize)

    s = with_json(sub.add_parser("query", help="can FROM reach TO? prints a witness packet if so"))
    s.add_argument("snapshot")
    s.add_argument("--from", dest="src", required=True, action="append", help="selector (repeatable)")
    s.add_argument("--to", dest="dst", required=True, action="append", help="selector (repeatable)")
    s.add_argument("--proto", help="tcp, udp, icmp, a number, or any")
    s.add_argument("--port", help="port or range, e.g. 22 or 8000-8999 (ICMP: type)")
    s.add_argument("--exit-code", action="store_true", help="exit 1 if anything is reachable")
    s.set_defaults(fn=cmd_query)

    s = with_json(sub.add_parser("exposure", help="which ports and services are reachable from outside"))
    s.add_argument("snapshot")
    s.add_argument("--from", dest="src", default=["internet"], action="append")
    s.add_argument("--to", dest="dst", action="append", help="restrict to these targets")
    s.add_argument("--risky-only", action="store_true")
    s.add_argument("--exit-code", action="store_true", help="exit 1 if any risky exposure is found")
    s.set_defaults(fn=cmd_exposure)

    s = with_json(sub.add_parser("check", help="verify reachability invariants from a YAML policy"))
    s.add_argument("snapshot")
    s.add_argument("policy")
    s.add_argument("--max-witnesses", type=int, default=3)
    s.set_defaults(fn=cmd_check)

    s = with_json(sub.add_parser("diff", help="semantic difference between two snapshots"))
    s.add_argument("old")
    s.add_argument("new")
    s.add_argument("--pairs", action="store_true", help="also compare every instance-to-instance pair")
    s.add_argument("--exit-code", action="store_true", help="exit 1 if access grew")
    s.set_defaults(fn=cmd_diff)

    s = with_json(sub.add_parser("lint", help="redundant/dead rules, disabled port security, ..."))
    s.add_argument("snapshot")
    s.add_argument("--exit-code", action="store_true", help="exit 1 on critical findings")
    s.set_defaults(fn=cmd_lint)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    # argparse appends to the default list; treat an explicit --from as a replacement.
    if args.cmd == "exposure" and len(args.src) > 1:
        args.src = args.src[1:]
    try:
        return args.fn(args)
    except (SelectorError, ValueError, FileNotFoundError) as e:
        print(f"osreach: error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

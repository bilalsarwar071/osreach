#!/usr/bin/env bash
# Nightly osreach report: snapshot, policy check, new/removed VMs, drift, exposure, lint.
#
#   usage: nightly.sh DATA_DIR POLICY.yaml [EXPOSURE_FROM]
#     EXPOSURE_FROM  selector for the exposure section (default: internet),
#                    e.g. cidr:172.16.0.0/16 for "everything on our networks"
#
# Needs OS_* credentials in the environment (e.g. `. ~/admin-openrc`) and the
# osreach virtualenv on PATH. Writes DATA_DIR/reports/YYYY-MM-DD.md and points
# DATA_DIR/reports/latest.md at it. If DATA_DIR/baseline.snapshot.json exists,
# drift from that known-good state is reported too.
#
# Exit status: 0 all good, 1 policy violation or access grew since the last run,
#              2 the snapshot itself failed.
set -uo pipefail

data=${1:?usage: nightly.sh DATA_DIR POLICY.yaml [EXPOSURE_FROM]}
policy=${2:?usage: nightly.sh DATA_DIR POLICY.yaml [EXPOSURE_FROM]}
from=${3:-internet}
umask 077
export NO_COLOR=1
mkdir -p "$data/reports"

day=$(date +%F)
today="$data/$day.snapshot.json"
# the most recent earlier dated snapshot (ignores baseline/step files)
previous=$(ls -1 "$data"/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].snapshot.json 2>/dev/null | grep -v "/$day\." | sort | tail -1)
baseline="$data/baseline.snapshot.json"
report="$data/reports/$day.md"
status=0

if ! osreach snapshot -o "$today" 2>"$report.err"; then
  echo "osreach $day: SNAPSHOT FAILED, see $report.err" | tee /dev/stderr | logger -t osreach 2>/dev/null
  exit 2
fi
rm -f "$report.err"

section() { printf '\n## %s\n\n```\n' "$1"; }
end() { printf '```\n'; }

{
  echo "# osreach nightly report $day"
  echo "snapshot: $today"

  section "Policy invariants ($(basename "$policy"))"
  osreach check "$today" "$policy" || status=1
  end

  section "Instances (NEW = appeared since the previous report)"
  python3 - "$previous" "$today" <<'EOF'
import sys
from osreach.snapshot import Snapshot, Topology
old = Topology(Snapshot.load(sys.argv[1])) if sys.argv[1] else None
new = Topology(Snapshot.load(sys.argv[2]))
old_ids = {p.id for p in old.instance_ports()} if old else set()
seen = set()
for p in sorted(new.instance_ports(), key=lambda p: (new.project_name(p.project_id), new.label(p))):
    seen.add(p.id)
    mark = "NEW " if old and p.id not in old_ids else "    "
    fips = ",".join(f.ip for f in new.fips_by_port.get(p.id, [])) or "-"
    groups = ", ".join(new.sg_label(g) for g in p.security_group_ids) or "-"
    sec = "" if p.port_security_enabled else "  PORT-SECURITY-OFF"
    print(f"{mark}{new.project_name(p.project_id):<12} {new.label(p):<22} fip={fips:<15} groups={groups}{sec}")
if old:
    for p in old.instance_ports():
        if p.id not in seen:
            print(f"GONE {old.project_name(p.project_id):<12} {old.label(p)}")
EOF
  end

  if [[ -n $previous ]]; then
    section "Changes since $(basename "$previous" .snapshot.json)"
    osreach diff "$previous" "$today" --pairs --exit-code || status=1
    end
  fi

  if [[ -f $baseline ]]; then
    section "Drift from the known-good baseline"
    osreach diff "$baseline" "$today"
    end
  fi

  section "Risky exposure from $from"
  osreach exposure "$today" --from "$from" --risky-only
  end

  section "Lint"
  osreach lint "$today"
  end
} > "$report" 2>&1

ln -sfn "$report" "$data/reports/latest.md"
find "$data" -maxdepth 1 -name '[0-9]*.snapshot.json' -mtime +30 -delete
find "$data/reports" -name '*.md' -mtime +90 -delete

verdict=$([[ $status == 0 ]] && echo OK || echo ATTENTION)
echo "osreach $day: $verdict  $report"
logger -t osreach "nightly $day $verdict $report" 2>/dev/null || true
exit $status

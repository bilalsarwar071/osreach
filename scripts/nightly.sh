#!/usr/bin/env bash
# Nightly drift check: snapshot the cloud, verify the policy, diff against yesterday.
#   usage: nightly.sh DATA_DIR POLICY.yaml
# Expects OS_* credentials in the environment (e.g. `. admin-openrc` from `sunbeam openrc`).
# Exit status: 0 = all good, 1 = policy violation or access grew since yesterday.
set -euo pipefail

data_dir=${1:?usage: nightly.sh DATA_DIR POLICY.yaml}
policy=${2:?usage: nightly.sh DATA_DIR POLICY.yaml}
mkdir -p "$data_dir"
umask 077  # snapshots describe your network; keep them private

today="$data_dir/$(date +%F).snapshot.json"
yesterday="$data_dir/$(date -d yesterday +%F).snapshot.json"
status=0

osreach snapshot -o "$today"
osreach check "$today" "$policy" --json > "$today.check.json" || status=1
osreach check "$today" "$policy" || true

if [[ -f "$yesterday" ]]; then
  osreach diff "$yesterday" "$today" --json > "$today.diff.json"
  osreach diff "$yesterday" "$today" --exit-code || status=1
fi

# keep 30 days
find "$data_dir" -name '*.snapshot.json*' -mtime +30 -delete
exit "$status"

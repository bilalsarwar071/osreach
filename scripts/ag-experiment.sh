#!/usr/bin/env bash
# Discriminating experiment for the address-group anomaly (tla/README.md).
#
# Run it ONLY against a disposable test VM. For a few minutes the VM's security
# groups are replaced by a fresh temporary group; everything is restored at the
# end, even if the script fails or you press Ctrl-C.
#
#   usage: scripts/ag-experiment.sh SERVER_ID PROJECT_ID SSH_TARGET ADMIN_CIDR
#   e.g.   scripts/ag-experiment.sh d95e3c15-... 8c5450... ubuntu@172.16.2.84 172.16.1.0/24
#
# Steps (each probe runs from inside the VM over one reused SSH connection):
#   baseline probe -> add an address-group egress rule -> probe A
#                  -> delete that rule                -> probe B
# The result is written as a trace to tla/traces/, then: python tla/run.py
set -uo pipefail

VM=${1:?server id}; AP=${2:?project id}; TARGET=${3:?user@floating-ip}; ADMIN=${4:?admin cidr}
IP=${TARGET#*@}
WAIT=${WAIT:-15}                       # seconds for the data plane to apply a change
CTL="/tmp/osreach-exp-$$"
SSHO=(-o ControlMaster=auto -o ControlPath="$CTL" -o ControlPersist=20m)
STAMP=$(date +%Y%m%d-%H%M)
OUT="$(dirname "$0")/../tla/traces/ag-experiment-$STAMP.json"

say() { printf '\n== %s\n' "$*"; }
probe_internet() {   # true if the VM can reach https://1.1.1.1
  local code
  code=$(ssh "${SSHO[@]}" "$TARGET" 'curl -s -m 5 -o /dev/null -w "%{http_code}" https://1.1.1.1' 2>/dev/null)
  [[ "$code" =~ ^[23] ]] && echo true || echo false
}
probe_admin() {      # true if a NEW TCP connection to port 22 is accepted from here
  nc -z -w 3 "$IP" 22 >/dev/null 2>&1 && echo true || echo false
}

X= AG= R=
ORIG=()
cleanup() {
  say "restoring the VM's original security groups"
  for g in "${ORIG[@]}"; do openstack server add security group "$VM" "$g" 2>/dev/null; done
  [[ -n $X ]] && openstack server remove security group "$VM" "$X" 2>/dev/null
  [[ -n $R ]] && openstack security group rule delete "$R" 2>/dev/null
  [[ -n $X ]] && openstack security group delete "$X" 2>/dev/null
  [[ -n $AG ]] && openstack address group delete "$AG" 2>/dev/null
  ssh -o ControlPath="$CTL" -O exit "$TARGET" 2>/dev/null
  echo "restored: $(openstack server show "$VM" -f value -c security_groups 2>/dev/null | tr '\n' ' ')"
}

say "opening one SSH connection to $TARGET (you may be asked for the password once)"
ssh "${SSHO[@]}" -fN "$TARGET" || { echo "cannot SSH to $TARGET"; exit 1; }

PORT=$(openstack port list --server "$VM" -f value -c ID | head -1)
mapfile -t ORIG < <(openstack port show "$PORT" -f json -c security_group_ids |
                    python3 -c 'import json,sys; print(*json.load(sys.stdin)["security_group_ids"], sep="\n")')
[[ ${#ORIG[@]} -gt 0 ]] || { echo "could not read the VM's security groups"; exit 1; }
echo "original groups: ${ORIG[*]}"
trap cleanup EXIT

say "creating a fresh temporary group (its egress-anywhere rule is created now, before any AG rule)"
X=$(openstack security group create --project "$AP" --description "osreach address-group experiment (temporary)" \
      "osreach-ag-experiment-$STAMP" -f value -c id)
openstack security group rule create --project "$AP" --ingress --protocol tcp --dst-port 22 --remote-ip "$ADMIN" "$X" -f value -c id >/dev/null
EGRESS4=$(openstack security group rule list "$X" --egress -f json |
          python3 -c 'import json,sys; print(sum(r["Ethertype"]=="IPv4" and r["IP Range"]=="0.0.0.0/0" for r in json.load(sys.stdin)))')
[[ "$EGRESS4" == 1 ]] || { echo "expected one IPv4 egress-anywhere rule in the new group, found $EGRESS4"; exit 1; }

say "moving the VM onto the temporary group only"
openstack server add security group "$VM" "$X"
for g in "${ORIG[@]}"; do openstack server remove security group "$VM" "$g"; done
sleep "$WAIT"
A0=$(probe_admin); B0=$(probe_internet); echo "baseline: admin=$A0 internet=$B0"
[[ $B0 == true ]] || echo "WARNING: baseline internet failed; the result will not discriminate cleanly"

say "adding an egress rule that points at an address group"
AG=$(openstack address group create --project "$AP" --address 1.1.1.1/32 "osreach-ag-experiment-$STAMP" -f value -c id)
R=$(openstack security group rule create --project "$AP" --egress --ethertype IPv4 --remote-address-group "$AG" "$X" -f value -c id)
sleep "$WAIT"
A1=$(probe_admin); PA=$(probe_internet); echo "A (AG rule present): admin=$A1 internet=$PA"

say "deleting the address-group rule"
openstack security group rule delete "$R"; R=
sleep "$WAIT"
A2=$(probe_admin); PB=$(probe_internet); echo "B (AG rule deleted): admin=$A2 internet=$PB"

cat > "$OUT" <<EOF
{
  "name": "ag-experiment-$STAMP",
  "description": "Discriminating experiment on a disposable VM, produced by scripts/ag-experiment.sh.",
  "vms": {"t": ["x"]},
  "init_rules": [
    {"id": 1, "g": "x", "dir": "in",  "peer": "admin", "kind": "cidr"},
    {"id": 2, "g": "x", "dir": "out", "peer": "any",   "kind": "cidr"}
  ],
  "events": [
    {"ev": "probe", "vm": "t", "dir": "in",  "peer": "admin",    "ok": $A0},
    {"ev": "probe", "vm": "t", "dir": "out", "peer": "internet", "ok": $B0},
    {"ev": "add", "id": 3, "g": "x", "dir": "out", "peer": "internet", "kind": "ag"},
    {"ev": "probe", "vm": "t", "dir": "in",  "peer": "admin",    "ok": $A1},
    {"ev": "probe", "vm": "t", "dir": "out", "peer": "internet", "ok": $PA},
    {"ev": "del", "id": 3},
    {"ev": "probe", "vm": "t", "dir": "in",  "peer": "admin",    "ok": $A2},
    {"ev": "probe", "vm": "t", "dir": "out", "peer": "internet", "ok": $PB}
  ]
}
EOF
say "trace written to $OUT"
case "$PA$PB" in
  truetrue)   echo "A=works B=works  -> H3: address-group rules are harmless here; the production rules broke for another reason" ;;
  truefalse)  echo "A=works B=fails  -> H2b_dir: deleting an address-group rule breaks the group's older egress rules" ;;
  falsefalse) echo "A=fails B=fails  -> H2a_dir: adding an address-group rule breaks the group's existing egress rules" ;;
  falsetrue)  echo "A=fails B=works  -> none of the surviving hypotheses; a new explanation is needed" ;;
esac
echo "confirm with:  python tla/run.py"

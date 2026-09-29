# Formal models (TLA+)

osreach answers "what can reach what, given this configuration?". The models
here answer two questions it cannot:

1. **Is a *procedure* for changing security groups safe?** Changes reach the
   data plane asynchronously, and a VM's permissions are the union of all its
   groups. Is there a moment during the change when required access is lost?
   And does the end state really meet the goal?
2. **When the real network disagrees with the API, which explanation fits the
   evidence?** This uses *trace validation*: a recorded sequence of API calls
   and probe results is checked against competing specifications of how the
   data plane behaves.

Both come from a real incident on a production cloud, described in
[docs/case-study.md](../docs/case-study.md).

```bash
# Java 11+ and tla2tools.jar (https://github.com/tlaplus/tlaplus/releases)
curl -LO https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
mv tla2tools.jar tla/
python tla/run.py           # ~30 s; exits non-zero if any result is unexpected
```

## 1. `SGMigration.tla`: safe-change procedures

The operator executes a `Plan` of API calls, and a separate `Propagate` action
applies each one to the data plane later. Two assumptions are constants,
because a procedure's safety depends on them:

- `FIFO`: the data plane applies changes in the order they were issued.
- `WaitForProbe`: the operator makes the next call only after a probe (`nc`,
  `curl`) has confirmed that the previous one took effect.

Invariants:
- `KeepAccess`: required access (for example admin SSH, or VM → internet) holds in *every* state.
- `DoneMeansGoal`: once the plan is finished, the unwanted access is gone.
- `Converged`: when nothing is in flight, the data plane matches the API.

| Model (`models/*.cfg`) | Plan | Assumptions | TLC result |
|---|---|---|---|
| `migration_ingress_safe` | add "SSH from admins", then delete "SSH from anyone" | wait for probe | no violation |
| `migration_ingress_wrong_order` | delete first, then add | wait for probe | **KeepAccess violated**: admins locked out |
| `migration_ingress_nowait_fifo` | add, then delete | no wait, FIFO data plane | no violation |
| `migration_ingress_nowait_any` | add, then delete | no wait, unordered data plane | **KeepAccess violated** |
| `migration_egress_safe` | attach `egress-no-internal`, then delete egress-anywhere | wait for probe | no violation |
| `migration_egress_wrong_order` | delete first, then attach | wait for probe | **KeepAccess violated**: VM loses internet |
| `migration_egress_forgot_default` | as the safe plan, but the VM also carries `default` | wait for probe | **DoneMeansGoal violated**: `default` still allows internal access (union semantics) |

The lesson TLC makes precise: "add the new rule, verify, then remove the old
one" is safe under **either** assumption. Skipping the verification is safe
only if the data plane applies changes in order, which is an assumption
worth knowing you are making.

## 2. `SGTrace.tla`: trace validation of an anomaly

**What was observed.** While restricting VM egress, the operator added a
security-group rule that points at an **address group**, then deleted it
again. Afterwards, on two VMs, the *old* "egress anywhere" rule had silently
stopped working, although the API still listed it. A rule created *after*
the address-group rule kept working.

[`traces/sg-address-group-incident.json`](traces/sg-address-group-incident.json)
records the 36 API calls and probe results (anonymised). Every hypothesis
agrees on one directly observed fact, that address-group rules are not
enforced, and differs in what else happens:

| Hypothesis | Meaning | Today's trace |
|---|---|---|
| H0 | nothing else happens | **rejected** |
| H2a_all | adding an AG rule stops all existing rules of the group | **rejected** (SSH into the VM kept working) |
| H2a_dir | …stops existing rules of the same direction | accepted |
| H2b_all | deleting an AG rule stops all older rules of the group | **rejected** |
| H2b_dir | …stops older rules of the same direction | accepted |
| H3 | the rules were already broken before the trace began | accepted |
| H4 | an AG rule shadows its group's same-direction rules while present | **rejected** |

TLC checks each hypothesis by searching for a behaviour of the specification
that reproduces the trace event by event (invariant `NotAccepted` is violated
exactly when one exists). This follows Cirstea, Kuppe, Loillier and Merz,
*Validating Traces of Distributed Programs Against TLA+ Specifications*.

**What the evidence cannot decide, and how to decide it.** Three hypotheses
survive. `run.py` also checks a small experiment on a disposable VM whose only
security group has fresh rules: probe egress, add an address-group egress
rule, probe (A), delete it, probe (B). TLC confirms that each outcome leaves
exactly one survivor:

| A | B | Explanation left |
|---|---|---|
| works | works | H3: address groups are harmless, and the rules were broken earlier for another reason |
| works | fails | H2b_dir: deleting an AG rule breaks older rules |
| fails | fails | H2a_dir: adding an AG rule breaks existing rules |
| fails | works | none: a new hypothesis is needed |

### Running the experiment (on a test VM, never production)

```bash
AP=<project id of the test VM>   VM=<test VM id>   DEF=<its current default group id>
X=$(openstack security group create --project $AP ag-experiment -f value -c id)   # fresh egress-any rules
openstack security group rule create --project $AP --ingress --protocol tcp --dst-port 22 --remote-ip <admin cidr> $X
openstack server add security group $VM $X && openstack server remove security group $VM $DEF
probe() { ssh <vm> 'curl -s -m 5 -o /dev/null -w "%{http_code}\n" https://1.1.1.1'; }
probe                                                    # baseline: expect 200
AG=$(openstack address group create --project $AP --address 1.1.1.1/32 ag-experiment -f value -c id)
R=$(openstack security group rule create --project $AP --egress --ethertype IPv4 --remote-address-group $AG $X -f value -c id)
sleep 10; probe                                          # A
openstack security group rule delete $R; sleep 10; probe # B
# clean up
openstack server add security group $VM $DEF && openstack server remove security group $VM $X
openstack security group delete $X && openstack address group delete $AG
```

Record the result as a new trace in `traces/` and run `python tla/run.py`.
If it confirms H2a_dir or H2b_dir, the trace, the spec and the experiment
together make a precise upstream bug report.

## Limits of the models

These are small, abstract models: one VM or a handful, rules reduced to
(direction, peer class), and probes treated as instantaneous and reliable.
That is deliberate, because the point is to make assumptions and
explanations explicit and machine-checkable. Being "accepted" means
*consistent with the evidence*, not *proven to be the cause*.

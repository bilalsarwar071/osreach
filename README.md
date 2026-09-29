# osreach

**SMT-based reachability verification for OpenStack Neutron.**

`osreach` takes a snapshot of a cloud's security groups, networks, routers and
floating IPs and encodes their combined behaviour as bit-vector formulas for
[Z3](https://github.com/Z3Prover/z3). It then answers the questions operators
actually ask:

* *Can anything on the internet reach port 22 on any VM?*
* *Are these two projects isolated?*
* *What did yesterday's change actually open up?*

Every "yes" comes with a **concrete witness packet**, including the path it
takes and the exact rules that let it through. Every "no" is a **proof over
all packets**, not a sample.

In the spirit of AWS's [Zelkova](https://www.amazon.science/publications/semantic-based-automated-reasoning-for-aws-access-policies-using-smt)
and [Tiros](https://www.amazon.science/publications/reachability-analysis-for-aws-based-networks),
and of [Batfish](https://github.com/batfish/batfish), applied to OpenStack.

```text
$ osreach query examples/demo-before.json --from vm:web-1 --to vm:db-1 --proto tcp --port 22
web-1 -> db-1 (tcp port 22): REACHABLE
    service   tcp/22
    sent      10.10.1.11 -> 203.0.113.40
    delivered 203.0.113.21 -> 10.20.0.10
    path      via external network: source NAT to floating IP 203.0.113.21; destination NAT from floating IP 203.0.113.40
    egress    web: egress any protocol to anywhere
    ingress   db: ingress tcp/22 from 0.0.0.0/0
```

These two VMs live in *different projects* with no shared router, and no
single security group looks wrong. The path runs out through one floating IP
and back in through another, and osreach finds it because it models NAT.

## Used on a real production cloud

On a production Canonical OpenStack (Sunbeam) cloud, osreach found five real
problems, and a probe on the real network confirmed each one. The worst: a
"LAN only" Remote Desktop rule whose CIDR silently contained the cloud's own
external network, an unauthenticated LLM API open to everyone, and VMs able to
reach the firewall's and core switch's management interfaces. osreach then
verified each fix step by step, from **2/6 to 10/10 policy invariants**.

When the OpenStack API and the real data plane disagreed, the session was
recorded as a trace and checked with **TLA+ trace validation** against seven
competing explanations. See **[the case study](docs/case-study.md)** and the
**[formal models](tla/README.md)**.

## Features

| Command | What it does |
|---|---|
| `osreach exposure` | Every instance reachable from the internet (or any CIDR), per service, with the rule responsible and a flag for risky ports |
| `osreach query` | Can FROM reach TO (optionally on a given proto/port)? Prints a witness or proves unreachability |
| `osreach check` | Verifies `deny`/`allow` invariants from a YAML policy; exits 1 on violation, which makes it a CI gate for your cloud |
| `osreach diff` | *Semantic* diff of two snapshots: which rules grant or revoke access, and which endpoint pairs became (un)reachable |
| `osreach lint` | Redundant (subsumed) rules, dead rules, dangling remote groups, disabled port security, unused groups, address-group rules to double-check |
| `osreach snapshot` | Captures Neutron/Nova/Keystone state through openstacksdk (read-only) |
| `osreach anonymize` | Keyed, prefix-preserving anonymisation that provably keeps every analysis result, so private-cloud data can be published |

Endpoint selectors: `internet`, `cidr:198.51.100.0/24`, `vm:web-*`,
`net:app-net`, `project:data-team`, `sg:bastion`, `port:<id>`, `all`.

## Quick start (no cloud needed)

```bash
git clone https://github.com/<you>/osreach && cd osreach
pip install -e '.[dev]'
osreach exposure examples/demo-before.json
osreach check    examples/demo-before.json examples/policy.yaml
osreach diff     examples/demo-before.json examples/demo-after.json
osreach lint     examples/demo-before.json
```

The demo is a synthetic three-project cloud (`examples/build_demo.py`) with
realistic mistakes planted in it.

<details>
<summary><b>Policy check</b>: 3 of 8 invariants fail</summary>

```text
FAIL  no-ssh-from-internet  (deny tcp port 22; 8 pairs)
      internet -> debug-1
        sent      1.0.0.16 -> 203.0.113.30
        delivered 1.0.0.16 -> 10.10.2.99
        path      destination NAT from floating IP 203.0.113.30
        ingress   port security disabled
      internet -> db-1
        ...
        ingress   db: ingress tcp/22 from 0.0.0.0/0
PASS  database-not-public  (deny tcp port 5432; 1 pairs)
PASS  management-network-isolated  (deny any traffic; 8 pairs)
PASS  web-reaches-app  (allow tcp port 8080; 2 pairs)
FAIL  web-team-cannot-reach-data-team-except-postgres  (deny tcp ports 1-5431; 10 pairs)
...
5/8 invariants hold
```

`database-not-public` holds even though `db` allows 5432 from
`203.0.113.10/32`, because that address is the web router's SNAT address, not
an internet host. `management-network-isolated` holds even though its group
allows all of `10.0.0.0/8`, because no router connects it.
</details>

<details>
<summary><b>Semantic diff</b>: a "temporary" rule plus a new floating IP</summary>

```text
Security group semantics
  + grants  app: ingress tcp/1-65535 from 0.0.0.0/0
  - revokes db: ingress tcp/22 from 0.0.0.0/0
Reachability
  - internet -> db-1: no longer reachable (tcp/22)
  + internet -> app-1: now reachable (tcp/8214)
      sensitive tcp/22 (ssh), tcp/23 (telnet), tcp/135 (msrpc), ... and 12 more
      path      destination NAT from floating IP 203.0.113.23
      ingress   app: ingress tcp/1-65535 from 0.0.0.0/0
```

Neither change is alarming on its own. The rule was harmless while `app-1`
had no floating IP, and the floating IP was harmless while the group was tight.
A textual diff shows two small edits. A semantic diff shows the database
tier's neighbour opened to the internet.
</details>

## On your own cloud

See **[docs/sunbeam.md](docs/sunbeam.md)** for Canonical OpenStack. In short:

```bash
pip install -e '.[openstack]'
sunbeam openrc > ~/admin-openrc && . ~/admin-openrc
osreach snapshot -o today.snapshot.json      # stays on your machine: gitignored
osreach exposure today.snapshot.json
```

`scripts/nightly.sh` turns this into daily drift detection.

## Writing a policy

```yaml
invariants:
  - name: no-ssh-from-internet
    expect: deny            # no packet may get through
    from: internet
    to: all
    to_except: [vm:bastion-*]
    proto: tcp
    port: 22
  - name: web-reaches-app
    expect: allow           # every pair must be connected
    from: vm:web-*
    to: vm:app-*
    proto: tcp
    port: 8080
```

A selector that matches nothing makes the invariant **fail** rather than pass
vacuously, since a typo in a selector should not look like a proof.

## How it works

Each connection attempt is a handful of bit-vectors: protocol, destination
port, and the packet's addresses *as sent* and *as delivered* (the two differ
under floating-IP and SNAT translation). Security groups become disjunctions
of prefix/range constraints. Paths (L2, one router hop, out-and-back through
the external network) become a disjunction of cases, each with its NAT
equations. A query is a single QF_BV satisfiability check. Diff and
redundancy checks add a negated existential.

For scale, on a laptop-class machine with a ~1,000-port synthetic cloud,
`exposure` takes about 1 s, and a project-isolation invariant covering
144,000 port pairs takes about 50 s.

The full model, including exactly what is and isn't covered and in which
direction each simplification errs, is in
**[docs/semantics.md](docs/semantics.md)**.

### Why trust it

* **Witness replay.** Every model Z3 returns is re-executed by an
  independent, hop-by-hop reference simulator (`reference.py`) before it is
  printed. Disagreement is an error, never an answer.
* **Differential testing.** The test suite generates random clouds (with
  overlapping CIDRs, disabled port security, allowed-address-pairs,
  admin-down routers and dangling remote groups) and checks that
  *formula SAT ⇔ simulator delivers* on ~25,000 packets.
* **Mutation-checked.** Off-by-one port ranges, ignored router state and
  wrong NAT precedence all make that test fail.
* **Anonymisation is semantics-preserving by test**: policy, exposure and
  lint results are identical before and after.
* **Checked against a real cloud.** Every prediction in the
  [case study](docs/case-study.md) was confirmed with a real `nc`/`curl`/ping
  probe, and the two places where the OpenStack API and the data plane
  disagreed are documented in [docs/semantics.md §9](docs/semantics.md#9-when-the-api-and-the-data-plane-disagree).

## Formal models (TLA+)

[`tla/`](tla/README.md) holds two TLA+ specifications, checked with TLC in CI:

* **`SGMigration`**: is a *procedure* for changing security groups on a live
  VM safe while changes reach the data plane asynchronously? TLC shows that
  "add the new rule, verify with a probe, then remove the old one" preserves
  access, and produces counterexamples for the wrong order, for skipping
  verification without in-order delivery, and for forgetting that a VM's
  permissions are the union of all its groups.
* **`SGTrace`**: trace validation. A recorded sequence of 36 API calls and
  probe results from the production incident is checked against seven
  hypotheses about how the data plane treats address-group rules. Four are
  rejected; for the three that survive, TLC proves that a five-step
  experiment tells them apart.

```bash
python tla/run.py     # needs Java and tla2tools.jar; see tla/README.md
```

## Scope and limitations

The model covers IPv4 through ML2/OVN-style Neutron: security groups
(including remote groups and address groups, although see
[§9](docs/semantics.md#9-when-the-api-and-the-data-plane-disagree) on the latter), port security, anti-spoofing,
allowed-address-pairs, admin state, routers with SNAT, floating IPs and
provider/external networks.

It does not yet cover IPv6, static routes and multi-router transit, Octavia,
FIP port forwarding, FWaaS or QoS. Where the model is an over-approximation,
`deny` proofs remain sound. Where it is an under-approximation, those paths
are invisible. [docs/semantics.md §7](docs/semantics.md#7-approximation-and-what-the-answers-mean)
lists which is which.

## Roadmap

- [x] Trace validation of recorded API calls and probes against TLA+ hypotheses (`tla/`)
- [ ] Run the discriminating address-group experiment and report the result upstream
- [ ] `osreach probe`: turn each witness into a real probe (and an `ovn-trace` call), and record the results as a trace automatically
- [ ] Static routes and multi-hop routing
- [ ] IPv6
- [ ] Octavia listeners and FIP port forwarding
- [ ] Scale: incremental solving and symmetry reduction for clouds with thousands of ports
- [ ] SARIF output for GitHub code scanning

## Development

```bash
pip install -e '.[dev]'
pytest -q          # ~25 s, dominated by the differential test
ruff check .
python examples/build_demo.py   # regenerate demo fixtures after changing the builder
```

Layout: `snapshot.py` (schema and indexes), `encode.py` (Z3 semantics),
`reference.py` (concrete semantics), `analysis.py` (query, exposure, check,
diff, lint), `anonymize.py`, `extract.py` (openstacksdk), `cli.py`; TLA+
models in `tla/`.

## License

Apache-2.0

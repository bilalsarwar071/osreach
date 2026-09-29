# Case study: hardening a production OpenStack cloud with osreach

This is a real session on a production **Canonical OpenStack (Sunbeam)** cloud
deployed with MAAS: 13 nodes (three control, five compute that also run
storage, five storage) with ML2/OVN networking. Project names, VM names and all addresses have
been replaced. The address *structure* is kept, because several of the findings
depend on it.

| Network | Stand-in address | Role |
|---|---|---|
| Generic | `10.20.1.0/24` | MAAS, Juju and Sunbeam controllers, OpenStack APIs, admin client |
| External | `10.20.2.0/24` | floating IPs and router gateways for every project (gateway `.1`, core switch `.2`/`.3`) |
| NOC | `10.20.99.0/24` | admin workstations |
| VPN | `10.30.0.0/24` | SSL-VPN users (admins and normal users share one pool) |
| BMC | `10.40.0.0/24` | server management controllers (iDRAC) |
| Access control | `10.50.0.0/24` | door access and cameras |
| Firewall management | `10.20.100.0/24` | site firewall |

The **production** project runs three VMs: `win-desktop` (Windows), `web` and
`llm` (an Ollama server). A **test** project runs two throwaway VMs. Each
project has its own router, so the only path between projects is out through
one floating IP and back in through another.

## 1. What osreach found (read-only)

One `osreach snapshot` (28 ports, 9 security groups, 5 routers, 7 floating IPs),
followed by `exposure`, `query` and `lint`:

| # | Finding | How osreach showed it |
|---|---|---|
| F1 | Remote Desktop on `win-desktop` allowed from `10.20.0.0/16`, which reads as "our LAN" but **contains the external network**, so every VM in every project could open Remote Desktop to it | `query test-vm → win-desktop`: witness packet sent from the test VM, delivered with source = the test VM's floating IP, path via two NATs |
| F2 | Ollama API (no authentication) open to `0.0.0.0/0`, via the project's `default` group; a dedicated group existed but was never attached | `exposure`, and `lint`: `unused-sg` |
| F3 | SSH open to `0.0.0.0/0` on production and test VMs | `exposure` |
| F4 | Test VMs could reach every production VM | `query --from vm:test-* --to project:prod` |
| F5 | VMs could open connections to MAAS, and (as a real probe later showed) to the **firewall's and core switch's management** | `query --from all --to cidr:<generic>` |

**The real network confirmed every prediction.** Before any change, `nc` from a
test VM reached `win-desktop:3389`, `llm:11434` and MAAS on `:5240`. osreach
names the exact rules responsible, so each confirmation is also a pointer to
the fix.

## 2. Fixing it one verified step at a time

Before each change, the goal was written down as a policy invariant. After
each change came a new snapshot, `osreach diff`, `osreach check`, **and** a
real probe from inside the network.

| Step | Change | Invariants holding | Real-network check |
|---|---|---|---|
| 0 | baseline | 2 / 6 | |
| 1 | Remote Desktop: `10.20.0.0/16` → generic only | 3 / 6 | `nc` test VM → win-desktop:3389 **times out** |
| 2 | SSH on `web`: `0.0.0.0/0` → generic, NOC, VPN (from the actual login sources in the auth log) | 4 / 7 | test VM → web:22 times out; admin SSH works |
| 3 | `llm` moved onto its own group: API only from generic, NOC and project; the `default` group removed from the VM | 7 / 8 | API reachable from the admin client and blocked from the test VM |
| 4 | Egress guard: VMs may reach the internet but not generic, NOC, BMC, access control, firewall or switch addresses | 8 / 10 after two of the three VMs | from inside each VM: DNS and HTTPS work, and MAAS, firewall and switch time out |
| 5 | `win-desktop` ping limited to admin networks | **10 / 10** | ping from the test VM gets no reply |

Two details worth keeping:

- **Semantic diff caught a change nobody made directly.** After `llm` left the
  `default` group, `osreach diff` reported `- revokes default: ingress any
  protocol from members of default`. No rule was edited: the group simply lost
  its last member. A textual diff of rules would show nothing.
- **Security groups can only allow.** "Everything except internal networks"
  had to be written as the complement: 80 CIDR blocks, computed with Python's
  `ipaddress` module and placed in one dedicated group, `egress-no-internal`.
  Because a VM's permissions are the union of its groups, the old
  "egress anywhere" rule had to be removed from **every** group on the VM.
  [`tla/`](../tla/README.md) model-checks why that ordering matters.

## 3. When the model and the network disagreed

The first version of step 4 put the 80 blocks into a Neutron **address group**
and referenced it from one rule. OpenStack accepted it and osreach, reading
the API, reported "internet allowed". But the real probe showed that **all**
egress from the VM was dropped. The change was rolled back within minutes.

Then a second surprise appeared. After the address-group rules were deleted
again, two *other* VMs turned out to have no egress at all, although their
original "egress anywhere" rules were still listed by the API. A rule created
later on a third VM worked fine.

Rather than guess at the cause, the session was recorded as a trace of 36 API
calls and probe results, and checked with TLC against seven competing
specifications of data-plane behaviour ([`tla/`](../tla/README.md)). Four are
ruled out by the evidence, including "address groups are just ignored" and
"everything in the group breaks". Three remain, and a five-step experiment on
a disposable VM is proven to tell them apart. It hasn't been run yet.

## 4. Lessons

1. **CIDR arithmetic is where intent and configuration drift apart.** "LAN
   only" (`/16`) silently included the cloud's own external network (F1). A
   solver checks the arithmetic; a human reviewer rarely does.
2. **Cross-project paths go through NAT, so remote-group rules don't apply to
   them.** Traffic between projects arrives from a floating IP or router
   address. osreach models this explicitly; "each project has its own router"
   isolates nothing on its own.
3. **Write the goal down first, as invariants, including `allow` ones.** The
   `allow` invariants (admin SSH, website, VPN, internet) are what made it safe
   to tighten `deny` rules on production.
4. **Verify the model against the real network.** Twice the API and the data
   plane disagreed. osreach says what should happen; a probe says what does.
   The combination, together with trace validation when they disagree, is the
   methodology.
5. **Some problems belong to the physical network.** The core switch routes
   between the external and generic networks with no filter, and the firewall
   never sees that traffic. Security-group egress rules are an effective
   guardrail, but only a filter on the switch is a hard boundary.

## Reproducing the analysis on your cloud

```bash
osreach snapshot -o today.snapshot.json
osreach exposure today.snapshot.json --from cidr:<your LAN>
osreach lint today.snapshot.json
osreach check today.snapshot.json policy.yaml
```

See [sunbeam.md](sunbeam.md) for credentials, and
[`examples/policy.yaml`](../examples/policy.yaml) for the invariant format.

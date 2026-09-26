# The osreach model of Neutron

This document defines what osreach means by "A can reach B". The Z3 encoding
(`src/osreach/encode.py`) and the reference simulator
(`src/osreach/reference.py`) are two independent implementations of this
definition. The test suite checks that they agree.

## 1. Scope

osreach reasons about **IPv4 connection initiation** through the Neutron objects
that decide it on an ML2/OVN deployment such as Canonical OpenStack (Sunbeam):

| Modelled | Not modelled (yet) |
|---|---|
| Security groups: direction, protocol, port ranges, ICMP type, `remote_ip_prefix`, `remote_group_id`, `remote_address_group_id` | IPv6 (rules are parsed, then ignored) |
| Port security on/off, anti-spoofing, allowed-address-pairs | Router static routes, transit through more than one router |
| Admin state of ports and routers | Octavia load balancers, FIP port forwarding |
| L2 on the same network | FWaaS, QoS, VPNaaS, BGP |
| East-west routing through one router | ICMP code (only the type is checked) |
| Floating IPs (DNAT in, SNAT out), router SNAT, ports directly on external networks | Metadata, DHCP and ARP traffic |

Security groups are stateful, so return traffic is always allowed and only the
first packet of a connection has to be allowed. For stateless groups, return
traffic needs its own rules. `osreach lint` flags stateless groups.

## 2. Packets and observables

A connection attempt is a tuple of bit-vectors:

```
proto : BV8      IP protocol number
dport : BV16     destination port (TCP/UDP/SCTP/DCCP/UDP-Lite); ICMP type for ICMP
ext   : BV32     address of the external peer, when one side is outside the cloud
```

The packet is seen at two points, and the addresses may differ between them
because of NAT:

```
sent      = (out_sip, out_dip)   as it leaves the source port   (egress SG applies here)
delivered = (in_sip,  in_dip)    as it reaches the destination  (ingress SG applies here)
```

`proto` and `dport` are never rewritten, since floating IPs do 1:1 NAT and SNAT
only changes the source port.

## 3. Security groups

For a rule `r` and a peer address `p` (the source for ingress rules, the
destination for egress rules):

```
match(r, p) = ethertype(r) = IPv4
            ∧ (proto(r) = any ∨ proto = proto(r))
            ∧ ports(r) ⊨ dport                      -- only for port protocols / ICMP type
            ∧ remote(r) ∋ p
```

where `remote(r)` is one of:

* the CIDR in `remote_ip_prefix`;
* the union of the CIDRs in the address group;
* the fixed IPs and allowed-address-pairs of every port carrying the group
  named in `remote_group_id`. This is matched against the **pre-NAT fixed
  addresses**, which is why a remote-group rule does not admit a group member
  that arrives through a floating IP;
* everything, when no remote is given.

The verdict at a port is

```
allow(port, dir) = ¬port_security(port) ∨ ⋁ { match(r, peer_dir) | r ∈ SG(port), dir(r) = dir }
```

With no groups and port security on, the verdict is **deny** (the empty
disjunction is false).

## 4. Addresses

```
owns(q, a)      = a ∈ fixed(q) ∨ ∃ c ∈ aap(q). a ∈ c
may_send(q, a)  = ¬port_security(q) ∨ owns(q, a)       -- anti-spoofing
```

"The internet" is every IPv4 address outside the special-purpose ranges
(RFC 1918, CGNAT, loopback, link-local, multicast, reserved) **and** outside
the cloud's own external subnets. Addresses on the external subnets belong to
router gateways and floating IPs, and traffic from them is modelled
explicitly by the external path below. `cidr:` endpoints let you ask about
any other range, for example your corporate LAN.

## 5. Paths

`reach(s, d)` for ports `s ≠ d`, both admin-up:

```
may_send(s, out_sip) ∧ allow(s, egress)[peer := out_dip]
∧ owns(d, in_dip)   ∧ allow(d, ingress)[peer := in_sip]
∧ ( L2 ∨ ROUTED ∨ EXTERNAL )
```

* **L2**: `net(s) = net(d)`, and `delivered = sent`.
* **ROUTED**: for some admin-up router R with subnets `S ⊆ net(s)` and
  `D ⊆ net(d)` attached, where `net(s) ≠ net(d)`:
  `out_sip ∈ S ∧ out_dip ∈ D ∧ delivered = sent` (there is no NAT east-west).
* **EXTERNAL**: the packet leaves through an *egress option* of `s` and
  enters through an *ingress option* of `d`:

  | egress option of `s` | condition | translation |
  |---|---|---|
  | floating IP f | `out_sip = f.fixed`, router of f up | `in_sip = f.ip` |
  | on an external network | – | `in_sip = out_sip` |
  | SNAT via router R | R up, gateway set, `enable_snat`, `out_sip ∈` a subnet of `net(s)` on R, `out_sip` has no FIP | `in_sip = gw(R)` |

  | ingress option of `d` | condition | translation |
  |---|---|---|
  | floating IP f | router of f up | `out_dip = f.ip`, `in_dip = f.fixed` |
  | on an external network | – | `in_dip = out_dip` |

For an external source E: `ext = in_sip = out_sip ∈ E`, some ingress option
of `d` holds, and `owns(d, in_dip) ∧ allow(d, ingress)`.

For an external destination E: `ext = out_dip = in_dip ∈ E`, some egress
option of `s` holds, and `may_send(s, out_sip) ∧ allow(s, egress)`.

All of this is quantifier-free bit-vector logic (QF_BV). A query is one
satisfiability check, and every model is a concrete witness packet.

## 6. Semantic diff

For two snapshots `old` and `new` sharing the observables `(proto, dport, ext)`,
a pair is **newly reachable** when

```
∃ hidden_new. reach_new  ∧  ¬ ∃ hidden_old. reach_old
```

where `hidden` are the four address variables of each snapshot. The inner
existential is a genuine quantifier. Z3 solves these small BV formulas
directly. The same construction with the roles swapped gives "no longer
reachable". Security-group diffs compare `allow_new ∧ ¬allow_old` per rule,
with the peer address as the only free variable.

Redundant-rule lint checks `match(r) ∧ ¬⋁ match(others)` for
unsatisfiability. Rules found redundant are removed from `others` as the
check proceeds, so of two identical rules only one is reported.

## 7. Approximation and what the answers mean

Answers are exact **relative to this model**. Where the model departs from
a real cloud, the direction of the error matters:

* **Over-approximations** (osreach may report reachability that isn't
  real): FWaaS, QoS and upstream firewalls are ignored; the ICMP code is
  ignored; all external networks are assumed to route to each other; a FIP
  whose router is missing from the snapshot is assumed to work. These are safe
  for `deny` invariants: a proof of "unreachable" still holds.
* **Under-approximations** (osreach may miss real paths): static routes,
  multi-router transit, load balancers, FIP port forwarding, IPv6. A `deny`
  result says nothing about these paths. They are listed in the roadmap.

## 8. Why you can trust a witness

1. Every model returned to the user is replayed through the reference
   simulator, a hop-by-hop forwarder written independently of the encoding.
   A mismatch raises `WitnessReplayError` instead of printing an answer.
2. `tests/test_differential.py` generates random clouds (overlapping CIDRs,
   disabled port security, AAPs, admin-down routers, dangling remote groups
   and so on) and checks that the formula with a fixed packet is SAT **iff**
   the simulator delivers that packet, over about 25k packets per run.
3. Mutation check: deliberately breaking the encoding (for example an
   off-by-one in port ranges, ignoring router admin state, or letting SNAT
   apply to FIP-bound addresses) makes the differential test fail.

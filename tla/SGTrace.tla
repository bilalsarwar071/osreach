------------------------------ MODULE SGTrace ------------------------------
(***************************************************************************)
(* Trace validation: which explanation of an observed data-plane anomaly   *)
(* is consistent with what was actually seen?                              *)
(*                                                                          *)
(* A trace is the sequence of API calls an operator made, interleaved with  *)
(* probes (nc / curl / Test-NetConnection) and their outcomes. Each         *)
(* hypothesis Hyp is a different semantics for how the data plane enforces  *)
(* security-group rules. TLC searches for a behaviour of the spec that      *)
(* reproduces the trace step by step:                                       *)
(*                                                                          *)
(*   trace ACCEPTED  <=> TLC reports that invariant NotAccepted is violated *)
(*   trace REJECTED  <=> TLC completes without finding a violation          *)
(*                                                                          *)
(* This follows the approach of Cirstea, Kuppe, Loillier and Merz,          *)
(* "Validating Traces of Distributed Programs Against TLA+ Specifications". *)
(*                                                                          *)
(* Rules are abstracted to [id, g, dir, peer, kind]:                        *)
(*   dir  "in" | "out";  peer "any" | "admin" | "internet" | "internal"      *)
(*   kind "cidr" (remote_ip_prefix) | "ag" (remote_address_group)          *)
(* Ids increase in creation order.                                          *)
(*                                                                          *)
(* Hypotheses (every one assumes address-group rules are never enforced,    *)
(* which was observed directly):                                            *)
(*   H0      nothing else happens                                           *)
(*   H2a_all adding an AG rule to a group stops all of its existing rules   *)
(*   H2a_dir ... stops its existing rules of the same direction             *)
(*   H2b_all deleting an AG rule stops the group's rules that are older     *)
(*   H2b_dir ... that are older and of the same direction                   *)
(*   H3      some rules were already not enforced before the trace began    *)
(*   H4      while a group contains an AG rule, its other rules of the same *)
(*           direction are not enforced; deleting the AG rule restores them *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Hyp, Trace, InitRules, InitAttach

VARIABLES rules, attach, broken, i
vars == <<rules, attach, broken, i>>

InitIds == {r.id : r \in InitRules}

ShadowedByAG(r) ==
    Hyp = "H4" /\ \E a \in rules : a.g = r.g /\ a.kind = "ag" /\ a.dir = r.dir

Enforced(r) == r.kind = "cidr" /\ r.id \notin broken /\ ~ShadowedByAG(r)

Covers(r, dir, peer) == r.dir = dir /\ (r.peer = peer \/ r.peer = "any")

Allows(vm, dir, peer) ==
    \E r \in rules : r.g \in attach[vm] /\ Enforced(r) /\ Covers(r, dir, peer)

Init ==
    /\ rules = InitRules
    /\ attach = InitAttach
    /\ broken \in (IF Hyp = "H3" THEN SUBSET InitIds ELSE {{}})
    /\ i = 1

\* Rules of group g that a hypothesis breaks when AG rule a is added / deleted.
BrokenByAdd(a) ==
    CASE Hyp = "H2a_all" -> {r.id : r \in {x \in rules : x.g = a.g}}
      [] Hyp = "H2a_dir" -> {r.id : r \in {x \in rules : x.g = a.g /\ x.dir = a.dir}}
      [] OTHER           -> {}

BrokenByDel(a) ==
    CASE Hyp = "H2b_all" -> {r.id : r \in {x \in rules : x.g = a.g /\ x.id < a.id}}
      [] Hyp = "H2b_dir" -> {r.id : r \in {x \in rules : x.g = a.g /\ x.id < a.id /\ x.dir = a.dir}}
      [] OTHER           -> {}

Add(e) ==
    LET r == [id |-> e.id, g |-> e.g, dir |-> e.dir, peer |-> e.peer, kind |-> e.kind] IN
    /\ rules' = rules \cup {r}
    /\ broken' = IF r.kind = "ag" THEN broken \cup BrokenByAdd(r) ELSE broken
    /\ UNCHANGED attach

Del(e) ==
    \E r \in rules :
        /\ r.id = e.id
        /\ rules' = rules \ {r}
        /\ broken' = IF r.kind = "ag" THEN broken \cup BrokenByDel(r) ELSE broken
        /\ UNCHANGED attach

Attach(e) ==
    /\ attach' = [attach EXCEPT ![e.vm] = @ \cup {e.g}]
    /\ UNCHANGED <<rules, broken>>

Probe(e) ==
    /\ Allows(e.vm, e.dir, e.peer) = e.ok
    /\ UNCHANGED <<rules, attach, broken>>

Next ==
    /\ i <= Len(Trace)
    /\ LET e == Trace[i] IN
         CASE e.ev = "add"    -> Add(e)
           [] e.ev = "del"    -> Del(e)
           [] e.ev = "attach" -> Attach(e)
           [] e.ev = "probe"  -> Probe(e)
    /\ i' = i + 1

Spec == Init /\ [][Next]_vars

\* Violated exactly when some behaviour reproduces the whole trace.
NotAccepted == i <= Len(Trace)
=============================================================================

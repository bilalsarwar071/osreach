---------------------------- MODULE SGMigration ----------------------------
(***************************************************************************)
(* Changing the security groups of a live VM without a window in which     *)
(* required access is lost.                                                 *)
(*                                                                          *)
(* An operator executes a fixed Plan of API calls. Each call takes effect   *)
(* in the OpenStack API at once, but reaches the data plane (OVN)           *)
(* asynchronously. A VM's verdict is the union of the rules of all groups   *)
(* attached to it: security groups can only allow, never deny.             *)
(*                                                                          *)
(* The model makes two assumptions explicit, because a procedure's safety   *)
(* depends on them:                                                         *)
(*   FIFO          the data plane applies API changes in the order issued   *)
(*   WaitForProbe  the operator issues the next call only after a probe     *)
(*                 (nc, curl, ...) confirmed the previous one took effect   *)
(*                                                                          *)
(* Invariants:                                                              *)
(*   KeepAccess   every (direction, peer) in Keep is allowed in every state *)
(*   DoneMeansGoal once the plan is finished and applied, every             *)
(*                (direction, peer) in Remove is denied                     *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Plan,          \* sequence of [op: {"add","del","attach","detach"}, g: group, r: rule]
    InitRules,     \* [Groups -> SUBSET Rule]; a rule is [dir |-> "in"/"out", peers |-> SUBSET Peer]
    InitAttach,    \* SUBSET Groups attached to the VM
    Keep,          \* set of <<dir, peer>> that must stay allowed throughout
    Remove,        \* set of <<dir, peer>> that must be denied at the end
    FIFO,          \* BOOLEAN
    WaitForProbe   \* BOOLEAN

Groups == DOMAIN InitRules

VARIABLES
    apiRules, apiAttach,   \* what the OpenStack API reports
    dpRules,  dpAttach,    \* what the data plane enforces
    pending,               \* API calls not yet applied to the data plane
    pc                     \* next step of the plan

vars == <<apiRules, apiAttach, dpRules, dpAttach, pending, pc>>

ApplyRules(op, rules) ==
    CASE op.op = "add" -> [rules EXCEPT ![op.g] = @ \cup {op.r}]
      [] op.op = "del" -> [rules EXCEPT ![op.g] = @ \ {op.r}]
      [] OTHER         -> rules

ApplyAttach(op, att) ==
    CASE op.op = "attach" -> att \cup {op.g}
      [] op.op = "detach" -> att \ {op.g}
      [] OTHER            -> att

\* Union semantics: some attached group has some rule matching the traffic.
Allows(rules, att, dir, peer) ==
    \E g \in att : \E r \in rules[g] : r.dir = dir /\ peer \in r.peers

DPAllows(dir, peer) == Allows(dpRules, dpAttach, dir, peer)

Init ==
    /\ apiRules = InitRules /\ dpRules = InitRules
    /\ apiAttach = InitAttach /\ dpAttach = InitAttach
    /\ pending = << >>
    /\ pc = 1

\* The operator issues the next API call of the plan.
Operator ==
    /\ pc <= Len(Plan)
    /\ WaitForProbe => pending = << >>
    /\ apiRules' = ApplyRules(Plan[pc], apiRules)
    /\ apiAttach' = ApplyAttach(Plan[pc], apiAttach)
    /\ pending' = Append(pending, Plan[pc])
    /\ pc' = pc + 1
    /\ UNCHANGED <<dpRules, dpAttach>>

\* The data plane applies one pending change: the oldest one, or any one.
RemoveAt(s, i) == SubSeq(s, 1, i - 1) \o SubSeq(s, i + 1, Len(s))

Propagate ==
    \E i \in 1..Len(pending) :
        /\ FIFO => i = 1
        /\ dpRules' = ApplyRules(pending[i], dpRules)
        /\ dpAttach' = ApplyAttach(pending[i], dpAttach)
        /\ pending' = RemoveAt(pending, i)
        /\ UNCHANGED <<apiRules, apiAttach, pc>>

Next == Operator \/ Propagate

Spec == Init /\ [][Next]_vars

Finished == pc > Len(Plan) /\ pending = << >>

KeepAccess == \A k \in Keep : DPAllows(k[1], k[2])

DoneMeansGoal == Finished => \A x \in Remove : ~DPAllows(x[1], x[2])

\* Sanity: when nothing is in flight, the data plane agrees with the API.
Converged == pending = << >> => (dpRules = apiRules /\ dpAttach = apiAttach)
=============================================================================

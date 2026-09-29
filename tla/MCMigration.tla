---------------------------- MODULE MCMigration ----------------------------
(***************************************************************************)
(* Concrete scenarios for SGMigration, taken from real changes made on a   *)
(* production cloud (see docs/case-study.md). Each .cfg file in this        *)
(* directory picks one scenario and one set of assumptions.                *)
(***************************************************************************)
EXTENDS SGMigration, TLC

NoRule == [dir |-> "none", peers |-> {}]

(* ---- Scenario 1: narrow SSH on a web server from "anyone" to admins ---- *)
SshAnyone == [dir |-> "in", peers |-> {"admin", "tenant"}]   \* tcp/22 from 0.0.0.0/0
SshAdmins == [dir |-> "in", peers |-> {"admin"}]             \* tcp/22 from the admin networks

IngressInit   == "web" :> {SshAnyone}
IngressAttach == {"web"}
IngressKeep   == {<<"in", "admin">>}
IngressRemove == {<<"in", "tenant">>}

IngressAddThenDel == << [op |-> "add", g |-> "web", r |-> SshAdmins],
                        [op |-> "del", g |-> "web", r |-> SshAnyone] >>
IngressDelThenAdd == << [op |-> "del", g |-> "web", r |-> SshAnyone],
                        [op |-> "add", g |-> "web", r |-> SshAdmins] >>

(* ---- Scenario 2: stop a VM reaching internal networks, keep internet ---- *)
AdminIn  == [dir |-> "in",  peers |-> {"admin"}]
EgressAny  == [dir |-> "out", peers |-> {"internet", "internal"}]   \* egress to 0.0.0.0/0
EgressInet == [dir |-> "out", peers |-> {"internet"}]               \* the "everything except internal" list

EgressInit == ("web" :> {AdminIn, EgressAny}) @@ ("eg" :> {EgressInet}) @@ ("default" :> {EgressAny})
EgressAttachOnlyWeb     == {"web"}
EgressAttachWebDefault  == {"web", "default"}   \* the VM also carries the project's default group
EgressKeep   == {<<"out", "internet">>, <<"in", "admin">>}
EgressRemove == {<<"out", "internal">>}

EgressAttachThenDel == << [op |-> "attach", g |-> "eg", r |-> NoRule],
                          [op |-> "del", g |-> "web", r |-> EgressAny] >>
EgressDelThenAttach == << [op |-> "del", g |-> "web", r |-> EgressAny],
                          [op |-> "attach", g |-> "eg", r |-> NoRule] >>
=============================================================================

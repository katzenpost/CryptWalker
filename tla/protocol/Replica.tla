------------------------------ MODULE Replica -------------------------------
(***************************************************************************)
(* One box at one replica, as a set of <<epoch, kind>> entries keyed by    *)
(* the replica epoch they were stored in. A replica keeps the current and  *)
(* previous epochs; a read returns the newest kept entry.                  *)
(*                                                                         *)
(* SpecStored is the storage the group chat spec assumes: every write      *)
(* stores the box at the current epoch, so a rewrite keeps it. A data      *)
(* write over a tombstone is refused. The deployed rule is in              *)
(* impl/KatzenpostReplica.tla.                                             *)
(***************************************************************************)
EXTENDS Integers

Kept(e) == IF e = 0 THEN {0} ELSE {e, e - 1}

\* What a read at epoch now returns: "data", "tomb" or "none" (BoxIDNotFound).
LookIn(s, now) ==
    LET vis == {x \in s : x[1] \in Kept(now)}
    IN IF vis = {} THEN "none"
       ELSE (CHOOSE x \in vis : \A y \in vis : y[1] <= x[1])[2]

PutIn(s, now, k) == {x \in s : x[1] # now} \cup {<<now, k>>}

SpecStored(s, now, k) ==
    IF k = "tomb" THEN PutIn(s, now, "tomb")
    ELSE IF LookIn(s, now) = "tomb" THEN s
    ELSE PutIn(s, now, "data")

=============================================================================

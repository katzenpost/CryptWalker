-------------------------- MODULE KatzenpostReplica -------------------------
(***************************************************************************)
(* Backfill over the replica as katzenpost/replica/state.go stores boxes.  *)
(*                                                                         *)
(* handleReplicaWrite: a data write that matches what is stored succeeds   *)
(* and stores nothing, so the box keeps the epoch it was first stored in;  *)
(* one that differs is refused. handleReplicaTombstone: a tombstone is     *)
(* always stored at the current epoch.                                     *)
(*                                                                         *)
(* ProtocolSpec is the protocol model over the storage the spec assumes;   *)
(* this model refines it only if the deployed replica keeps rewritten      *)
(* boxes the way the spec says.                                            *)
(***************************************************************************)
EXTENDS Backfill

DeployedStored(s, now, k) ==
    IF k = "tomb" THEN PutIn(s, now, "tomb")
    ELSE IF LookIn(s, now) = "none" THEN PutIn(s, now, "data")
    ELSE s

Protocol == INSTANCE Backfill WITH StoredOp <- SpecStored

ProtocolSpec == Protocol!Spec

=============================================================================

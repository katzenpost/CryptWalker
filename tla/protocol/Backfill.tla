------------------------------ MODULE Backfill ------------------------------
(***************************************************************************)
(* One member's stream: backfill, retention, acknowledgements and the      *)
(* reader's scan. See "Opportunistic acknowledgements and backfill" and    *)
(* "Rewrite and scan" in the group chat spec.                              *)
(*                                                                         *)
(* StoredOp is how a replica handles a write: Replica.tla's SpecStored for *)
(* the protocol, impl/KatzenpostReplica.tla's DeployedStored for the       *)
(* replica as deployed.                                                    *)
(*                                                                         *)
(* NaiveAdopt, AckFurthest and KeepHoles choose between the spec as        *)
(* written and the changes these models propose.                           *)
(*                                                                         *)
(* Acknowledgements travel on the reader's own messages, which the owner   *)
(* reads at some later time or never: LearnAck abstracts that whole path.  *)
(***************************************************************************)
EXTENDS Replica, FiniteSets, TLC

CONSTANTS
    Readers,        \* the other members, all reading this stream
    N,              \* positions the owner may write
    MaxEpoch,       \* the last replica epoch explored
    Retention,      \* epochs a Sent-box record is kept after its write
    StoredOp(_, _, _), \* a replica's handling of a write: StoredOp(entries, epoch, kind)
    NaiveAdopt,     \* a scan adopts its first empty probe, even right after the stuck position
    AckFurthest,    \* an ack names the furthest box read, as the spec says, not the end of the unbroken run
    AllowScan,      \* the user may ask for a scan
    KeepHoles       \* a reader keeps polling a position a scan skipped, until it reads it

VARIABLES
    epoch,   \* current replica epoch
    store,   \* store[p]: set of <<epoch, kind>> held for position p
    written, \* positions 0..written-1 have been written by the owner
    wEpoch,  \* wEpoch[p]: epoch of the first write of p
    record,  \* record[p]: the owner's Sent-box record: "none", "plain", "held" (position only) or "gone"
    lastRw,  \* lastRw[p]: last epoch the owner wrote or rewrote p
    online,  \* the owner's client is running
    cursor,  \* cursor[r]: next position r expects
    mode,    \* mode[r]: "reading" or "scanning"
    probe,   \* probe[r]: position a scan looks at next
    seen,    \* seen[r]: positions r has read, data or tombstone
    got,     \* got[r]: positions whose message r has ingested
    acked,   \* acked[r]: how far the owner knows r has read, -1 for nothing
    holes    \* holes[r]: positions a scan skipped that r still polls

vars == <<epoch, store, written, wEpoch, record, lastRw, online,
          cursor, mode, probe, seen, got, acked, holes>>

Pos == 0..(N - 1)
Epochs == 0..MaxEpoch
None == -1

\* What a read of p returns: the newest kept entry, or "none" (BoxIDNotFound).
Look(p) == LookIn(store[p], epoch)

\* The store after a write of kind k ("data" or "tomb") to p.
Stored(p, k) == [store EXCEPT ![p] = StoredOp(store[p], epoch, k)]

Max(S) == CHOOSE m \in S : \A x \in S : x <= m

\* How far r's next ack reaches.
Front(r) ==
    IF seen[r] = {} THEN None
    ELSE IF AckFurthest THEN Max(seen[r])
    ELSE LET run == {p \in seen[r] : \A q \in 0..p : q \in seen[r]}
         IN IF run = {} THEN None ELSE Max(run)

AllAcked(p) == \A r \in Readers : acked[r] >= p

TypeOK ==
    /\ epoch \in Epochs
    /\ store \in [Pos -> SUBSET (Epochs \X {"data", "tomb"})]
    /\ written \in 0..N
    /\ wEpoch \in [Pos -> Epochs]
    /\ record \in [Pos -> {"none", "plain", "held", "gone"}]
    /\ lastRw \in [Pos -> Epochs \cup {None}]
    /\ online \in BOOLEAN
    /\ cursor \in [Readers -> 0..N]
    /\ mode \in [Readers -> {"reading", "scanning"}]
    /\ probe \in [Readers -> 0..N]
    /\ seen \in [Readers -> SUBSET Pos]
    /\ got \in [Readers -> SUBSET Pos]
    /\ acked \in [Readers -> Pos \cup {None}]
    /\ holes \in [Readers -> SUBSET Pos]

Init ==
    /\ epoch = 0
    /\ store = [p \in Pos |-> {}]
    /\ written = 0
    /\ wEpoch = [p \in Pos |-> 0]
    /\ record = [p \in Pos |-> "none"]
    /\ lastRw = [p \in Pos |-> None]
    /\ online = TRUE
    /\ cursor = [r \in Readers |-> 0]
    /\ mode = [r \in Readers |-> "reading"]
    /\ probe = [r \in Readers |-> 0]
    /\ seen = [r \in Readers |-> {}]
    /\ got = [r \in Readers |-> {}]
    /\ acked = [r \in Readers |-> None]
    /\ holes = [r \in Readers |-> {}]

ReaderVars == <<cursor, mode, probe, seen, got, holes>>

(* Time and the replica *)

Tick ==
    /\ epoch < MaxEpoch
    /\ epoch' = epoch + 1
    \* GC: drop what no longer falls in the kept window. Reads and writes
    \* ignore it already; dropping it only keeps the state small.
    /\ store' = [p \in Pos |-> {x \in store[p] : x[1] \in Kept(epoch + 1)}]
    /\ UNCHANGED <<written, wEpoch, record, lastRw, online, acked, ReaderVars>>

(* The stream owner *)

GoOffline == online /\ online' = FALSE /\ UNCHANGED <<epoch, store, written, wEpoch, record, lastRw, acked, ReaderVars>>
GoOnline == ~online /\ online' = TRUE /\ UNCHANGED <<epoch, store, written, wEpoch, record, lastRw, acked, ReaderVars>>

Send ==
    /\ online
    /\ written < N
    /\ store' = Stored(written, "data")
    /\ wEpoch' = [wEpoch EXCEPT ![written] = epoch]
    /\ record' = [record EXCEPT ![written] = "plain"]
    /\ lastRw' = [lastRw EXCEPT ![written] = epoch]
    /\ written' = written + 1
    /\ UNCHANGED <<epoch, online, acked, ReaderVars>>

\* The periodic rewrite, at most once per epoch per box.
Rewrite(p) ==
    /\ online
    /\ record[p] \in {"plain", "held"}
    /\ lastRw[p] < epoch
    /\ IF AllAcked(p)
       THEN /\ store' = Stored(p, "tomb")
            /\ record' = [record EXCEPT ![p] = "held"]
       ELSE /\ store' = Stored(p, "data")
            /\ UNCHANGED record
    /\ lastRw' = [lastRw EXCEPT ![p] = epoch]
    /\ UNCHANGED <<epoch, written, wEpoch, online, acked, ReaderVars>>

\* The bounded retention window.
Discard(p) ==
    /\ record[p] \in {"plain", "held"}
    /\ epoch >= wEpoch[p] + Retention
    /\ record' = [record EXCEPT ![p] = "gone"]
    /\ UNCHANGED <<epoch, store, written, wEpoch, lastRw, online, acked, ReaderVars>>

\* r's ack reaches the owner, carried by some later message of r's.
LearnAck(r) ==
    /\ Front(r) > acked[r]
    /\ acked' = [acked EXCEPT ![r] = Front(r)]
    /\ UNCHANGED <<epoch, store, written, wEpoch, record, lastRw, online, ReaderVars>>

(* A reader: the two-state machine of "Rewrite and scan" *)

Ingest(r, p) ==
    /\ seen' = [seen EXCEPT ![r] = @ \cup {p}]
    /\ got' = [got EXCEPT ![r] = IF Look(p) = "data" THEN @ \cup {p} ELSE @]

Read(r) ==
    /\ mode[r] = "reading"
    /\ cursor[r] < N
    /\ Look(cursor[r]) # "none"
    /\ Ingest(r, cursor[r])
    /\ cursor' = [cursor EXCEPT ![r] = @ + 1]
    /\ UNCHANGED <<mode, probe, holes, epoch, store, written, wEpoch, record, lastRw, online, acked>>

RequestScan(r) ==
    /\ AllowScan
    /\ mode[r] = "reading"
    /\ cursor[r] < N
    /\ mode' = [mode EXCEPT ![r] = "scanning"]
    /\ probe' = [probe EXCEPT ![r] = cursor[r] + 1]
    /\ UNCHANGED <<cursor, seen, got, holes, epoch, store, written, wEpoch, record, lastRw, online, acked>>

ScanFound(r) ==
    /\ mode[r] = "scanning"
    /\ probe[r] < N
    /\ Look(probe[r]) # "none"
    /\ Ingest(r, probe[r])
    /\ probe' = [probe EXCEPT ![r] = @ + 1]
    /\ UNCHANGED <<cursor, mode, holes, epoch, store, written, wEpoch, record, lastRw, online, acked>>

\* BoxIDNotFound at the probe (or the end of the modelled stream): the
\* scan ends. Unless NaiveAdopt, a scan that found nothing past the stuck
\* position leaves the reader where it was.
ScanEnd(r) ==
    /\ mode[r] = "scanning"
    /\ IF probe[r] >= N THEN TRUE ELSE Look(probe[r]) = "none"
    /\ mode' = [mode EXCEPT ![r] = "reading"]
    /\ LET adopt == NaiveAdopt \/ probe[r] > cursor[r] + 1
       IN /\ cursor' = [cursor EXCEPT ![r] = IF adopt THEN probe[r] ELSE @]
          /\ holes' = IF adopt /\ KeepHoles THEN [holes EXCEPT ![r] = @ \cup {cursor[r]}] ELSE holes
    /\ UNCHANGED <<probe, seen, got, epoch, store, written, wEpoch, record, lastRw, online, acked>>

\* A skipped position turns up, restored by the owner's rewrite or written late.
ReadHole(r, p) ==
    /\ p \in holes[r]
    /\ Look(p) # "none"
    /\ Ingest(r, p)
    /\ holes' = [holes EXCEPT ![r] = @ \ {p}]
    /\ UNCHANGED <<cursor, mode, probe, epoch, store, written, wEpoch, record, lastRw, online, acked>>

Next ==
    \/ Tick \/ GoOffline \/ GoOnline \/ Send
    \/ \E p \in Pos : Rewrite(p) \/ Discard(p)
    \/ \E r \in Readers : LearnAck(r) \/ Read(r) \/ RequestScan(r) \/ ScanFound(r) \/ ScanEnd(r)
    \/ \E r \in Readers : \E p \in Pos : ReadHole(r, p)

Spec == Init /\ [][Next]_vars

\* Readers keep reading, acks keep flowing and time moves on. The owner may
\* go offline as often as it likes, but comes back, and a client online
\* again and again gets round to its periodic rewrite (strong fairness).
\* Nothing forces the owner to write or a user to scan.
Fairness ==
    /\ WF_vars(Tick) /\ WF_vars(GoOnline)
    /\ \A p \in Pos : SF_vars(Rewrite(p))
    /\ \A r \in Readers : WF_vars(Read(r)) /\ WF_vars(LearnAck(r)) /\ WF_vars(ScanFound(r)) /\ WF_vars(ScanEnd(r))
    /\ \A r \in Readers : \A p \in Pos : WF_vars(ReadHole(r, p))

FairSpec == Spec /\ Fairness

(* Properties *)

\* "Every position stays populated": a box whose owner wrote or rewrote it
\* in this epoch or the last can be read.
Populated ==
    \A p \in Pos : (record[p] \in {"plain", "held"} /\ lastRw[p] # None /\ lastRw[p] >= epoch - 1)
                   => Look(p) # "none"

\* "Acknowledging a stream's Nth box implies every earlier one has been
\* read": what the owner counts as acknowledged, the reader has.
NoSilentLoss ==
    \A r \in Readers : \A p \in Pos : p <= acked[r] => p \in got[r]

\* A reader never expects a position beyond the one the owner writes next.
NoOvershoot ==
    \A r \in Readers : cursor[r] <= written

\* A tombstone stands only where every reader has acknowledged.
NoPrematureTombstone ==
    \A p \in Pos : Look(p) = "tomb" => AllAcked(p)

\* Every box written reaches every reader, while the owner still holds it.
EventualDelivery ==
    \A r \in Readers : \A p \in Pos :
        [](p < written => <>(p \in got[r] \/ record[p] = "gone"))

\* A user asks for scans only finitely often.
ScansStop == <>[][\A r \in Readers : ~RequestScan(r)]_vars

DeliveryOnceScansStop == ScansStop => EventualDelivery

Symmetry == Permutations(Readers)

=============================================================================

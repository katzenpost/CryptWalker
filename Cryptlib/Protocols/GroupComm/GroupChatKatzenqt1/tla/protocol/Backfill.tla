------------------------------ MODULE Backfill ------------------------------
(***************************************************************************)
(* One member's stream: backfill, retention, acknowledgements and the      *)
(* readers' scans. See "Opportunistic acknowledgements and backfill" and   *)
(* "Rewrite and scan" in the group chat spec.                              *)
(*                                                                         *)
(* A reader stuck where another reader has acknowledged further jumps to   *)
(* the box that reader acknowledged, keeping the positions it skipped for  *)
(* rechecking. A scan with no such acknowledgement to go on reads on from  *)
(* where the reader stands.                                                *)
(*                                                                         *)
(* StoredOp is how a replica handles a write: Replica.tla's SpecStored for *)
(* the protocol, impl/KatzenpostReplica.tla's DeployedStored for the       *)
(* replica as deployed. AckFurthest and PollHoles choose between the spec  *)
(* as written and the changes these models propose.                        *)
(*                                                                         *)
(* Acknowledgements travel on the readers' own messages, which the owner   *)
(* and the other readers read at some later time or never: Publish         *)
(* abstracts that whole path.                                              *)
(***************************************************************************)
EXTENDS Replica, FiniteSets, TLC

CONSTANTS
    Readers,        \* the other members, all reading this stream
    N,              \* positions the owner may write
    MaxEpoch,       \* the last replica epoch explored
    Retention,      \* epochs a Sent-box record is kept after its write
    StoredOp(_, _, _), \* a replica's handling of a write: StoredOp(entries, epoch, kind)
    AckFurthest,    \* an ack names the furthest box read, as the spec says, not the end of the unbroken run
    AutoScan,       \* a stuck reader jumps on another reader's acknowledgement without being asked
    AllowScan,      \* the user may ask for a scan
    PollHoles,      \* a reader polls the positions it skipped until it reads them, not only when it scans
    Window          \* how many positions behind the one it jumped to a reader keeps for rechecking

VARIABLES
    epoch,   \* current replica epoch
    store,   \* store[p]: set of <<epoch, kind>> held for position p
    written, \* positions 0..written-1 have been written by the owner
    wEpoch,  \* wEpoch[p]: epoch of the first write of p
    record,  \* record[p]: the owner's Sent-box record: "none", "plain", "held" (position only) or "gone"
    lastRw,  \* lastRw[p]: last epoch the owner wrote or rewrote p
    online,  \* the owner's client is running
    cursor,  \* cursor[r]: next position r reads
    seen,    \* seen[r]: positions r has read, data or tombstone
    got,     \* got[r]: positions whose message r has ingested
    acked,   \* acked[r]: how far r's published acknowledgements reach, -1 for nothing
    holes    \* holes[r]: positions r skipped and keeps for rechecking

vars == <<epoch, store, written, wEpoch, record, lastRw, online, cursor, seen, got, acked, holes>>

Pos == 0..(N - 1)
Epochs == 0..MaxEpoch
None == -1

Look(p) == LookIn(store[p], epoch)

Stored(p, k) == [store EXCEPT ![p] = StoredOp(store[p], epoch, k)]

Max(S) == CHOOSE m \in S : \A x \in S : x <= m

\* How far r's next acknowledgement reaches.
Front(r) ==
    IF seen[r] = {} THEN None
    ELSE IF AckFurthest THEN Max(seen[r])
    ELSE LET run == {p \in seen[r] : \A q \in 0..p : q \in seen[r]}
         IN IF run = {} THEN None ELSE Max(run)

\* The furthest box another reader has acknowledged: what r has heard.
Heard(r) == Max({acked[o] : o \in Readers \ {r}} \cup {None})

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
    /\ seen = [r \in Readers |-> {}]
    /\ got = [r \in Readers |-> {}]
    /\ acked = [r \in Readers |-> None]
    /\ holes = [r \in Readers |-> {}]

ReaderVars == <<cursor, seen, got, holes>>
OwnerVars == <<written, wEpoch, record, lastRw, online>>

(* Time and the replica *)

Tick ==
    /\ epoch < MaxEpoch
    /\ epoch' = epoch + 1
    \* Drop what no longer falls in the kept window. Reads and writes ignore
    \* it already; dropping it only keeps the state small.
    /\ store' = [p \in Pos |-> {x \in store[p] : x[1] \in Kept(epoch + 1)}]
    /\ UNCHANGED <<OwnerVars, acked, ReaderVars>>

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

\* The periodic rewrite, at most once per epoch per box. A box every reader
\* has acknowledged is rewritten as a tombstone.
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

(* A reader *)

\* r publishes how far it has read, on some later message of its own.
Publish(r) ==
    /\ Front(r) > acked[r]
    /\ acked' = [acked EXCEPT ![r] = Front(r)]
    /\ UNCHANGED <<epoch, store, OwnerVars, ReaderVars>>

Ingest(r, p) ==
    /\ seen' = [seen EXCEPT ![r] = @ \cup {p}]
    /\ got' = [got EXCEPT ![r] = IF Look(p) = "data" THEN @ \cup {p} ELSE @]

Read(r) ==
    /\ cursor[r] < N
    /\ Look(cursor[r]) # "none"
    /\ Ingest(r, cursor[r])
    /\ cursor' = [cursor EXCEPT ![r] = @ + 1]
    /\ UNCHANGED <<holes, epoch, store, OwnerVars, acked>>

\* Stuck where another reader has acknowledged further: jump to the box it
\* acknowledged, keeping the last Window positions skipped.
JumpTo(r) ==
    LET t == Heard(r)
    IN /\ cursor[r] < N
       /\ Look(cursor[r]) = "none"
       /\ t > cursor[r]
       /\ holes' = [holes EXCEPT ![r] = @ \cup {p \in cursor[r]..(t - 1) : p >= t - Window}]
       /\ cursor' = [cursor EXCEPT ![r] = t]

Jump(r) ==
    /\ AutoScan
    /\ JumpTo(r)
    /\ UNCHANGED <<seen, got, epoch, store, OwnerVars, acked>>

Recheck(r, p) ==
    /\ p \in holes[r]
    /\ Look(p) # "none"
    /\ Ingest(r, p)
    /\ holes' = [holes EXCEPT ![r] = @ \ {p}]

\* A skipped position turns up and is polled, when readers poll them.
Poll(r, p) ==
    /\ PollHoles
    /\ Recheck(r, p)
    /\ UNCHANGED <<cursor, epoch, store, OwnerVars, acked>>

\* The user asks for a scan: everything kept is rechecked, then the reader
\* jumps if it can, and otherwise reads on from where it stands.
Scan(r) ==
    /\ AllowScan
    /\ LET back == {p \in holes[r] : Look(p) # "none"}
           kept == holes[r] \ back
       IN /\ seen' = [seen EXCEPT ![r] = @ \cup back]
          /\ got' = [got EXCEPT ![r] = @ \cup {p \in back : Look(p) = "data"}]
          /\ IF cursor[r] < N /\ Look(cursor[r]) = "none" /\ Heard(r) > cursor[r]
             THEN /\ holes' = [holes EXCEPT ![r] = kept \cup
                        {p \in cursor[r]..(Heard(r) - 1) : p >= Heard(r) - Window}]
                  /\ cursor' = [cursor EXCEPT ![r] = Heard(r)]
             ELSE /\ holes' = [holes EXCEPT ![r] = kept]
                  /\ UNCHANGED cursor
    /\ UNCHANGED <<epoch, store, OwnerVars, acked>>

Next ==
    \/ Tick \/ GoOffline \/ GoOnline \/ Send
    \/ \E p \in Pos : Rewrite(p) \/ Discard(p)
    \/ \E r \in Readers : Publish(r) \/ Read(r) \/ Jump(r) \/ Scan(r)
    \/ \E r \in Readers : \E p \in Pos : Poll(r, p)

Spec == Init /\ [][Next]_vars

\* Readers keep reading and publishing, and time moves on. The owner may go
\* offline as often as it likes, but comes back, and a client online again
\* and again gets round to its periodic rewrite (strong fairness). Nothing
\* forces the owner to write or a user to scan.
Fairness ==
    /\ WF_vars(Tick) /\ WF_vars(GoOnline)
    /\ \A p \in Pos : SF_vars(Rewrite(p))
    /\ \A r \in Readers : WF_vars(Read(r)) /\ WF_vars(Publish(r)) /\ WF_vars(Jump(r))
    /\ \A r \in Readers : \A p \in Pos : WF_vars(Poll(r, p))

FairSpec == Spec /\ Fairness

(* Properties *)

\* "Every position stays populated": a box whose owner wrote or rewrote it
\* in this epoch or the last can be read.
Populated ==
    \A p \in Pos : (record[p] \in {"plain", "held"} /\ lastRw[p] # None /\ lastRw[p] >= epoch - 1)
                   => Look(p) # "none"

\* "Acknowledging a stream's Nth box implies every earlier one has been
\* read": what a reader acknowledges, it has.
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
ScansStop == <>[][\A r \in Readers : ~Scan(r)]_vars

DeliveryOnceScansStop == ScansStop => EventualDelivery

Symmetry == Permutations(Readers)

=============================================================================

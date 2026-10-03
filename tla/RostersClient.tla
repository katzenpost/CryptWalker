--------------------------- MODULE RostersClient ---------------------------
(***************************************************************************)
(* A client's send path over Rosters.tla, as katzenqt's acks.py runs it.   *)
(*                                                                         *)
(* A message takes its acknowledgements when it is queued and numbers     *)
(* anyone only when it is written. An induction builds the reply to the    *)
(* new member from what is written so far, and queues the Introduction;   *)
(* the new member gets the reply when the Introduction is written, the    *)
(* two going in one all-or-nothing write. A queued message may be          *)
(* cancelled.                                                              *)
(*                                                                         *)
(* Each Bug flag undoes one fix from katzenqt#108:                         *)
(*   BugNoWaitAcks       6f06a4b: an induction need not wait for queued    *)
(*                       messages that carry acknowledgements;             *)
(*   BugNoWaitIntro      b88abff: an induction need not wait for a queued  *)
(*                       Introduction;                                     *)
(*   BugCancelKeepsAcks  f2e4c01: cancelling a message keeps the           *)
(*                       acknowledgements it took, and what waits on them. *)
(***************************************************************************)
EXTENDS Rosters

CONSTANTS BugNoWaitAcks, BugNoWaitIntro, BugCancelKeepsAcks, MaxQueue

VARIABLES
    outbox,  \* outbox[m]: m's queued messages, oldest first
    taken,   \* taken[m][y]: how far m's queued or written messages acknowledge y's stream (acked_index)
    owed,    \* owed[m]: ids of m's messages an induction waits for (OutgoingAcks rows)
    nextId

cvars == <<vars, outbox, taken, owed, nextId>>

Ids == 0..(2 * MaxLen * Cardinality(Members))

\* A queued message. Text carries no reply; an Introduction carries the
\* reply as built when the induction began.
Text(acks, id) == [acks |-> acks, intro |-> NoOne, id |-> id,
                   own |-> <<>>, hread |-> [y \in Members |-> 0], hknow |-> {},
                   hbase |-> [y \in Members |-> <<"none">>]]

Queued(m) == {outbox[m][k] : k \in DOMAIN outbox[m]}

\* How far m's written and queued messages acknowledge y, or where m began reading it.
Claimed(m, y) ==
    LET i == IndexOf(roster[m], y)
        levels == {a[2] : a \in {b \in UNION {q.acks : q \in Queued(m)} : b[1] = i}}
                  \cup {AckedBy(m, y), floor[m][y]}
    IN IF y \notin Range(roster[m]) THEN floor[m][y]
       ELSE CHOOSE l \in levels : \A k \in levels : k <= l

PendingC(m) == {y \in Range(roster[m]) \ {m} : read[m][y] > taken[m][y]}

Room(m) == Len(stream[m]) + Len(outbox[m]) < MaxLen /\ Len(outbox[m]) < MaxQueue

CInit ==
    /\ Init
    /\ outbox = [m \in Members |-> <<>>]
    /\ taken = [m \in Members |-> [y \in Members |-> 0]]
    /\ owed = [m \in Members |-> {}]
    /\ nextId = 0

\* Queue a text message with every acknowledgement pending.
Attach(m) ==
    /\ m \in joined
    /\ Room(m)
    /\ LET acks == {<<IndexOf(roster[m], y), read[m][y]>> : y \in PendingC(m)}
       IN /\ outbox' = [outbox EXCEPT ![m] = Append(@, Text(acks, nextId))]
          /\ taken' = [taken EXCEPT ![m] = [y \in Members |->
                          IF y \in PendingC(m) THEN read[m][y] ELSE @[y]]]
          /\ owed' = IF acks # {} THEN [owed EXCEPT ![m] = @ \cup {nextId}] ELSE owed
    /\ nextId' = nextId + 1
    /\ UNCHANGED vars

\* Begin inducting n: build the reply from what is written, queue the Introduction.
Induct(i, n) ==
    /\ i \in joined /\ n \in Joiners \ joined
    /\ \A m \in Members : \A q \in Queued(m) : q.intro # n
    /\ Room(i)
    /\ BugNoWaitAcks \/ owed[i] = {}
    /\ BugNoWaitIntro \/ \A q \in Queued(i) : q.intro = NoOne
    /\ LET own == Append(roster[i], n)
           hand == HandSet(i) \ {n}
           msg == [acks |-> {}, intro |-> n, id |-> nextId, own |-> own,
                   hread |-> [y \in Members |-> IF y \in hand THEN ReadPos(i, y) ELSE 0],
                   hknow |-> (IF Extended THEN know[i] ELSE {}),
                   hbase |-> [y \in Members |-> IF y \in hand THEN HandedBase(i, n, y, own) ELSE <<"none">>]]
       IN outbox' = [outbox EXCEPT ![i] = Append(@, msg)]
    /\ nextId' = nextId + 1
    /\ UNCHANGED <<vars, taken, owed>>

\* Write the oldest queued message to the stream.
Write(m) ==
    /\ outbox[m] # <<>>
    /\ LET msg == Head(outbox[m])
           grown == Grown(m, roster[m], msg.acks)
           pos == Len(stream[m]) + 1
           n == msg.intro
       IN /\ stream' = [stream EXCEPT ![m] = Append(@, [acks |-> msg.acks, intro |-> n])]
          /\ outbox' = [outbox EXCEPT ![m] = Tail(@)]
          /\ owed' = [owed EXCEPT ![m] = @ \ {msg.id}]
          /\ IF n = NoOne
             THEN /\ roster' = [roster EXCEPT ![m] = grown]
                  /\ UNCHANGED <<joined, read, know, base, promised, introducer, floor, taken>>
             ELSE LET hread == [msg.hread EXCEPT ![m] = pos]
                  IN /\ roster' = [roster EXCEPT ![m] = Append(grown, n), ![n] = msg.own]
                     /\ joined' = joined \cup {n}
                     /\ promised' = [promised EXCEPT ![n] = Len(msg.own) - 1]
                     /\ introducer' = [introducer EXCEPT ![n] = m]
                     /\ read' = [read EXCEPT ![n] = hread]
                     /\ floor' = [floor EXCEPT ![n] = hread]
                     /\ taken' = [taken EXCEPT ![n] = hread]
                     /\ know' = [know EXCEPT ![n] =
                                   msg.hknow \cup (IF Extended THEN {<<m, q>> : q \in 1..pos} ELSE {<<m, pos>>})]
                     /\ base' = [base EXCEPT ![n] = msg.hbase, ![m][n] = <<"given", msg.own>>]
    /\ UNCHANGED nextId

\* Cancel a queued text message. Its acknowledgements are owed again on
\* the next message, unless BugCancelKeepsAcks.
Cancel(m, k) ==
    /\ k \in DOMAIN outbox[m]
    /\ outbox[m][k].intro = NoOne
    /\ LET rest == [j \in 1..(Len(outbox[m]) - 1) |-> IF j < k THEN outbox[m][j] ELSE outbox[m][j + 1]]
       IN /\ outbox' = [outbox EXCEPT ![m] = rest]
          /\ IF BugCancelKeepsAcks
             THEN UNCHANGED <<taken, owed>>
             ELSE /\ owed' = [owed EXCEPT ![m] = @ \ {outbox[m][k].id}]
                  /\ taken' = [taken EXCEPT ![m] = [y \in Members |->
                       LET i == IndexOf(roster[m], y)
                           levels == {a[2] : a \in {b \in UNION {rest[j].acks : j \in DOMAIN rest} : b[1] = i}}
                                     \cup {AckedBy(m, y), floor[m][y]}
                       IN IF y \in Range(roster[m]) THEN CHOOSE l \in levels : \A x \in levels : x <= l
                          ELSE @[y]]]
    /\ UNCHANGED <<vars, nextId>>

CNext ==
    \/ \E m, y \in Members : Read(m, y) /\ UNCHANGED <<outbox, taken, owed, nextId>>
    \/ \E m \in Members : Attach(m) \/ Write(m)
    \/ \E i, n \in Members : Induct(i, n)
    \/ \E m \in Members : \E k \in 1..MaxQueue : Cancel(m, k)

CSpec == CInit /\ [][CNext]_cvars

(* Properties *)

\* A client never counts as acknowledged what no written or queued message says.
NoLostAck == \A m \in joined : \A y \in Members : taken[m][y] <= Claimed(m, y)

\* An induction never waits on a message that will not be written.
NoStaleWait == \A m \in Members : owed[m] \subseteq {q.id : q \in Queued(m)}

CQuiet == Quiet /\ \A m \in Members : outbox[m] = <<>>

CConverged ==
    CQuiet => \A m, x \in joined : m # x =>
        LET f == Follow(m, x) IN f.ok /\ ~f.stuck /\ f.seq = roster[x]

=============================================================================

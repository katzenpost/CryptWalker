------------------------------ MODULE Katzenqt ------------------------------
(***************************************************************************)
(* katzenqt's send path, as acks.py and voucher.py run it, over the        *)
(* protocol model GroupChat.tla.                                           *)
(*                                                                         *)
(* A message takes its acknowledgements when it is queued and numbers     *)
(* anyone only when it is written. An induction fixes the roster it will   *)
(* promise the new member from what is written so far, and queues the     *)
(* Introduction; the new member gets the reply when the Introduction is    *)
(* written, the two going in one all-or-nothing write. A queued message    *)
(* may be cancelled.                                                       *)
(*                                                                         *)
(* katzenqt builds the whole reply when the induction begins. Here only    *)
(* the promised roster is fixed then; the rest is read off at the write,   *)
(* as the protocol does. An earlier view of read positions is still a     *)
(* valid reply, and the promised roster is what #108's bugs got wrong.     *)
(*                                                                         *)
(* katzenqt keeps its read and write positions itself and passes them to  *)
(* kpclientd with each request, BACAP's stateless API: read[m][y] is that  *)
(* state, and the daemon holds none.                                       *)
(*                                                                         *)
(* ProtocolSpec is GroupChat's Spec: every write katzenqt makes must be a  *)
(* step the protocol allows.                                               *)
(*                                                                         *)
(* Each Bug flag undoes one fix from katzenqt#108:                         *)
(*   BugNoWaitAcks       6f06a4b: an induction need not wait for queued    *)
(*                       messages that carry acknowledgements;             *)
(*   BugNoWaitIntro      b88abff: an induction need not wait for a queued  *)
(*                       Introduction;                                     *)
(*   BugCancelKeepsAcks  f2e4c01: cancelling a message keeps the           *)
(*                       acknowledgements it took, and what waits on them. *)
(***************************************************************************)
EXTENDS GroupChat

CONSTANTS BugNoWaitAcks, BugNoWaitIntro, BugCancelKeepsAcks, MaxQueue

VARIABLES
    outbox,  \* outbox[m]: m's queued messages, oldest first
    taken,   \* taken[m][y]: how far m's queued or written messages acknowledge y's stream (acked_index)
    owed     \* owed[m]: ids of m's messages an induction waits for (OutgoingAcks rows)

cvars == <<vars, outbox, taken, owed>>

\* A queued message. An Introduction carries the roster its reply promises.
Text(acks, id) == [acks |-> acks, intro |-> NoOne, id |-> id, own |-> <<>>]

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

\* The smallest id not queued or waited on: ids need only tell m's own messages apart.
FreshId(m) == CHOOSE i \in 0..(MaxQueue + MaxLen) :
                  /\ i \notin owed[m] /\ i \notin {q.id : q \in Queued(m)}
                  /\ \A j \in 0..(i - 1) : j \in owed[m] \/ j \in {q.id : q \in Queued(m)}

CInit ==
    /\ Init
    /\ outbox = [m \in Members |-> <<>>]
    /\ taken = [m \in Members |-> [y \in Members |-> 0]]
    /\ owed = [m \in Members |-> {}]

\* Queue a text message with every acknowledgement pending.
Attach(m) ==
    /\ m \in joined
    /\ Room(m)
    /\ LET acks == {<<IndexOf(roster[m], y), read[m][y]>> : y \in PendingC(m)}
       IN /\ outbox' = [outbox EXCEPT ![m] = Append(@, Text(acks, FreshId(m)))]
          /\ taken' = [taken EXCEPT ![m] = [y \in Members |->
                          IF y \in PendingC(m) THEN read[m][y] ELSE @[y]]]
          /\ owed' = IF acks # {} THEN [owed EXCEPT ![m] = @ \cup {FreshId(m)}] ELSE owed
    /\ UNCHANGED vars

\* Begin inducting n: fix the roster to promise from what is written, queue the Introduction.
Induct(i, n) ==
    /\ i \in joined /\ n \in Joiners \ joined
    /\ \A m \in Members : \A q \in Queued(m) : q.intro # n
    /\ Room(i)
    /\ BugNoWaitAcks \/ owed[i] = {}
    /\ BugNoWaitIntro \/ \A q \in Queued(i) : q.intro = NoOne
    /\ outbox' = [outbox EXCEPT ![i] = Append(@,
                    [acks |-> {}, intro |-> n, id |-> FreshId(i), own |-> Append(roster[i], n)])]
    /\ UNCHANGED <<vars, taken, owed>>

\* Write the oldest queued message to the stream.
Write(m) ==
    /\ outbox[m] # <<>>
    /\ LET msg == Head(outbox[m])
           grown == Grown(m, roster[m], msg.acks)
           n == msg.intro
       IN /\ outbox' = [outbox EXCEPT ![m] = Tail(@)]
          /\ owed' = [owed EXCEPT ![m] = @ \ {msg.id}]
          /\ IF n = NoOne
             THEN /\ stream' = [stream EXCEPT ![m] = Append(@, [acks |-> msg.acks, intro |-> NoOne])]
                  /\ roster' = [roster EXCEPT ![m] = grown]
                  /\ UNCHANGED <<joined, read, know, base, promised, introducer, floor, taken>>
             ELSE /\ IntroduceWith(m, n, msg.acks, Append(grown, n), msg.own)
                  /\ taken' = [taken EXCEPT ![n] = read'[n]]

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
    /\ UNCHANGED vars

CNext ==
    \/ \E m, y \in Members : Read(m, y) /\ UNCHANGED <<outbox, taken, owed>>
    \/ \E m \in Members : Attach(m) \/ Write(m)
    \/ \E i, n \in Members : Induct(i, n)
    \/ \E m \in Members : \E k \in 1..MaxQueue : Cancel(m, k)

CSpec == CInit /\ [][CNext]_cvars

(* Properties *)

\* Every write katzenqt makes is a step the protocol allows.
ProtocolSpec == Spec

\* A client never counts as acknowledged what no written or queued message says.
NoLostAck == \A m \in joined : \A y \in Members : taken[m][y] <= Claimed(m, y)

\* An induction never waits on a message that will not be written.
NoStaleWait == \A m \in Members : owed[m] \subseteq {q.id : q \in Queued(m)}

CQuiet == Quiet /\ \A m \in Members : outbox[m] = <<>>

CConverged ==
    CQuiet => \A m, x \in joined : m # x =>
        LET f == Follow(m, x) IN f.ok /\ ~f.stuck /\ f.seq = roster[x]

=============================================================================

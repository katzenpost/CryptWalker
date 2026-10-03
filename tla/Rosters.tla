------------------------------ MODULE Rosters ------------------------------
(***************************************************************************)
(* Rosters and acknowledgements across a group. See "Rosters" in the group *)
(* chat spec.                                                              *)
(*                                                                         *)
(* Every member numbers the members it knows; nobody states a number. A    *)
(* message names the streams it acknowledges by the sender's roster index; *)
(* the rest of the group works out each sender's roster by watching what   *)
(* it acknowledges. Watching follows katzenqt's rosters.follow: a roster   *)
(* begins at a base, and every known message of its owner is replayed in   *)
(* stream order, stopping at the first acknowledgement the watcher cannot  *)
(* yet read. Storage is reliable here; Backfill.tla covers its loss.       *)
(*                                                                         *)
(* Positions count from 1. An acknowledgement <<i, r>> says the sender has *)
(* read r boxes of the stream at its roster index i (indexes count from    *)
(* 0); it covers an Introduction at position q when q <= r.                *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    FounderSeq,   \* founders, in the order they all number themselves
    Joiners,      \* members who may be inducted later
    NoOne,        \* "this message introduces nobody"
    MaxLen,       \* the most messages a stream holds
    Extended,     \* the reply to a new member carries what katzenqt hands over, not the spec's Rosters alone
    AcksOnIntro,  \* an Introduction may carry acknowledgements
    AckAll        \* a message acknowledges every stream newly read, as far as read, as katzenqt does

Founders == {FounderSeq[i] : i \in DOMAIN FounderSeq}
Members == Founders \cup Joiners

VARIABLES
    stream,     \* stream[m]: m's messages, [acks |-> set of <<index, reached>>, intro |-> member or NoOne]
    joined,     \* members in the group
    roster,     \* roster[m]: m's own roster
    read,       \* read[m][y]: boxes of y's stream m has read through
    know,       \* know[m]: <<y, q>> whose message m has read or was handed
    base,       \* base[m][x]: where m's copy of x's roster begins
    promised,   \* promised[n]: the roster index n's reply gave it
    introducer, \* introducer[n]: who inducted n
    floor       \* floor[m][y]: where m began reading y's stream; nothing before it is m's to acknowledge

vars == <<stream, joined, roster, read, know, base, promised, introducer, floor>>

Range(s) == {s[i] : i \in DOMAIN s}
IndexOf(s, e) == (CHOOSE i \in DOMAIN s : s[i] = e) - 1
IsPrefix(s, t) == Len(s) <= Len(t) /\ SubSeq(t, 1, Len(s)) = s
Min(a, b) == IF a < b THEN a ELSE b
NoDup(s) == \A i, j \in DOMAIN s : s[i] = s[j] => i = j

ReadPos(m, y) == IF y = m THEN Len(stream[m]) ELSE read[m][y]
Knows(m, y, q) == y = m \/ <<y, q>> \in know[m]

(* Growing a roster through one message's acknowledgements (rosters.grow) *)

\* Members introduced on y's stream at positions 1..r that m knows of, in stream order.
IntrosOn(m, y, r) ==
    LET qs == SelectSeq([q \in 1..Min(r, Len(stream[y])) |-> q],
                        LAMBDA q : Knows(m, y, q) /\ stream[y][q].intro # NoOne)
    IN [k \in 1..Len(qs) |-> stream[y][qs[k]].intro]

RECURSIVE AppendNew(_, _)
AppendNew(s, more) ==
    IF more = <<>> THEN s
    ELSE AppendNew(IF Head(more) \in Range(s) THEN s ELSE Append(s, Head(more)), Tail(more))

\* `acks` is read against `from`, the roster as it stood before the message.
RECURSIVE GrowAt(_, _, _, _, _)
GrowAt(m, from, acks, i, acc) ==
    IF i >= Len(from) THEN acc
    ELSE GrowAt(m, from, acks, i + 1,
                IF \E a \in acks : a[1] = i
                THEN AppendNew(acc, IntrosOn(m, from[i + 1], (CHOOSE a \in acks : a[1] = i)[2]))
                ELSE acc)

Grown(m, from, acks) == GrowAt(m, from, acks, 0, from)

(* Following another member's roster (rosters.follow) *)

Readable(m, seq, acks) ==
    \A a \in acks : a[1] < Len(seq) /\ a[2] <= ReadPos(m, seq[a[1] + 1])

\* Replay x's messages p+1..lim on top of seq. Once stuck, nothing more is applied.
RECURSIVE Replay(_, _, _, _, _, _)
Replay(m, x, seq, p, lim, stuck) ==
    IF p >= lim THEN [seq |-> seq, stuck |-> stuck]
    ELSE LET q == p + 1
             msg == stream[x][q]
         IN IF stuck \/ ~Knows(m, x, q) THEN Replay(m, x, seq, q, lim, stuck)
            ELSE IF msg.acks # {} /\ ~Readable(m, seq, msg.acks)
                 THEN Replay(m, x, seq, q, lim, TRUE)
            ELSE LET s1 == IF msg.acks = {} THEN seq ELSE Grown(m, seq, msg.acks)
                     s2 == IF msg.intro # NoOne /\ msg.intro \notin Range(s1)
                           THEN Append(s1, msg.intro) ELSE s1
                 IN Replay(m, x, s2, q, lim, FALSE)

Fail == [ok |-> FALSE, seq |-> <<>>, stuck |-> TRUE]

\* m's copy of x's roster, counting x's messages through position lim.
RECURSIVE FollowThrough(_, _, _)
FollowThrough(m, x, lim) ==
    LET b == base[m][x]
        upto == Min(lim, ReadPos(m, x))
        From(s) == LET r == Replay(m, x, s, 0, upto, FALSE)
                   IN [ok |-> TRUE, seq |-> r.seq, stuck |-> r.stuck]
    IN CASE b[1] = "founder" -> From(FounderSeq)
         [] b[1] = "given" -> From(b[2])
         [] b[1] = "inherit" ->
              IF ReadPos(m, b[2]) < b[3] THEN Fail
              ELSE LET f == FollowThrough(m, b[2], b[3])
                   IN IF ~f.ok \/ f.stuck THEN Fail ELSE From(f.seq)
         [] OTHER -> Fail

Follow(m, x) == IF x = m THEN [ok |-> TRUE, seq |-> roster[m], stuck |-> FALSE]
                ELSE FollowThrough(m, x, ReadPos(m, x))

(* Acknowledgements a member may attach *)

AllAcks(m) == UNION {stream[m][q].acks : q \in DOMAIN stream[m]}

AckedBy(m, y) ==
    IF y \notin Range(roster[m]) THEN 0
    ELSE LET levels == {a[2] : a \in {b \in AllAcks(m) : b[1] = IndexOf(roster[m], y)}}
         IN IF levels = {} THEN 0 ELSE CHOOSE l \in levels : \A k \in levels : k <= l

Pending(m) == {y \in Range(roster[m]) \ {m} : read[m][y] > AckedBy(m, y) /\ read[m][y] > floor[m][y]}

\* Any choice of streams newly read, each acknowledged at a level reached since its last one.
AckChoices(m) ==
    IF AckAll THEN {{<<IndexOf(roster[m], y), read[m][y]>> : y \in Pending(m)}}
    ELSE UNION {{{<<IndexOf(roster[m], y), lv[y]>> : y \in S} :
             lv \in {f \in [S -> 1..MaxLen] : \A y \in S : AckedBy(m, y) < f[y] /\ f[y] <= read[m][y]}} :
           S \in SUBSET Pending(m)}

TypeOK ==
    /\ joined \subseteq Members
    /\ \A m \in Members : Len(stream[m]) <= MaxLen

Init ==
    /\ stream = [m \in Members |-> <<>>]
    /\ joined = Founders
    /\ roster = [m \in Members |-> IF m \in Founders THEN FounderSeq ELSE <<>>]
    /\ read = [m \in Members |-> [y \in Members |-> 0]]
    /\ know = [m \in Members |-> {}]
    /\ base = [m \in Members |-> [x \in Members |->
                 IF m \in Founders /\ x \in Founders /\ m # x THEN <<"founder">> ELSE <<"none">>]]
    /\ promised = [m \in Members |-> 0]
    /\ introducer = [m \in Members |-> m]
    /\ floor = [m \in Members |-> [y \in Members |-> 0]]

(* Actions *)

Send(m) ==
    /\ m \in joined
    /\ Len(stream[m]) < MaxLen
    /\ \E acks \in AckChoices(m) :
         /\ stream' = [stream EXCEPT ![m] = Append(@, [acks |-> acks, intro |-> NoOne])]
         /\ roster' = [roster EXCEPT ![m] = Grown(m, @, acks)]
    /\ UNCHANGED <<joined, read, know, base, promised, introducer, floor>>

\* m reads the next box of y's stream. Reading an Introduction of a member
\* it does not know starts its copy of that member's roster.
Read(m, y) ==
    /\ m \in joined /\ y \in joined /\ m # y
    /\ base[m][y][1] # "none"
    /\ read[m][y] < Len(stream[y])
    /\ LET q == read[m][y] + 1
           n == stream[y][q].intro
       IN /\ read' = [read EXCEPT ![m][y] = q]
          /\ know' = [know EXCEPT ![m] = @ \cup {<<y, q>>}]
          /\ base' = IF n # NoOne /\ n # m /\ base[m][n][1] = "none"
                     THEN [base EXCEPT ![m][n] = <<"inherit", y, q>>]
                     ELSE base
    /\ UNCHANGED <<stream, joined, roster, promised, introducer, floor>>

\* Who an introducer hands a new member: its roster, then anyone it reads
\* but has not numbered.
HandSet(i) == Range(roster[i]) \cup {y \in joined : base[i][y][1] # "none"}

\* What the new member n's copy of y's roster begins as.
HandedBase(i, n, y, own) ==
    IF y = i THEN <<"given", own>>
    ELSE LET f == Follow(i, y)
         IN IF f.ok THEN <<"given", f.seq>>
            ELSE IF Extended THEN base[i][y] ELSE <<"none">>

\* i inducts n: the Introduction on i's stream and the reply to n, all or nothing.
Introduce(i, n) ==
    /\ i \in joined /\ n \in Joiners \ joined
    /\ Len(stream[i]) < MaxLen
    /\ \E acks \in (IF AcksOnIntro THEN AckChoices(i) ELSE {{}}) :
         LET grown == Grown(i, roster[i], acks)
             own == Append(grown, n)
             pos == Len(stream[i]) + 1
             hand == HandSet(i) \ {n}
         IN /\ stream' = [stream EXCEPT ![i] = Append(@, [acks |-> acks, intro |-> n])]
            /\ roster' = [roster EXCEPT ![i] = own, ![n] = own]
            /\ joined' = joined \cup {n}
            /\ promised' = [promised EXCEPT ![n] = Len(own) - 1]
            /\ introducer' = [introducer EXCEPT ![n] = i]
            /\ read' = [read EXCEPT ![n] = [y \in Members |->
                          IF y = i THEN pos ELSE IF y \in hand THEN ReadPos(i, y) ELSE 0]]
            /\ floor' = [floor EXCEPT ![n] = read'[n]]
            /\ know' = [know EXCEPT ![n] =
                          (IF Extended THEN know[i] \cup {<<i, q>> : q \in 1..pos} ELSE {<<i, pos>>})]
            /\ base' = [base EXCEPT
                          ![n] = [y \in Members |-> IF y \in hand THEN HandedBase(i, n, y, own) ELSE <<"none">>],
                          ![i][n] = <<"given", own>>]

Next ==
    \/ \E m \in Members : Send(m)
    \/ \E m, y \in Members : Read(m, y)
    \/ \E i, n \in Members : Introduce(i, n)

Spec == Init /\ [][Next]_vars

(* Properties *)

RosterNoDup == \A m \in joined : NoDup(roster[m])

\* What a watcher can tell of a roster is right as far as it goes.
RosterPrefix ==
    \A m, x \in joined : m # x =>
        LET f == Follow(m, x) IN f.ok => IsPrefix(f.seq, roster[x])

\* The roster index the reply promised is the one the introducer gave.
InductionIndex ==
    \A n \in joined \ Founders :
        /\ n \in Range(roster[introducer[n]])
        /\ IndexOf(roster[introducer[n]], n) = promised[n]
        /\ IndexOf(roster[n], n) = promised[n]

\* Once everyone has read everything, every watcher can tell every roster.
Quiet == \A m, y \in joined : m # y => read[m][y] = Len(stream[y])

Converged ==
    Quiet => \A m, x \in joined : m # x =>
        LET f == Follow(m, x) IN f.ok /\ ~f.stuck /\ f.seq = roster[x]

Symmetry == Permutations(Joiners)

=============================================================================

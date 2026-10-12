------------------------------ MODULE Katzenqt ------------------------------
(***************************************************************************)
(* katzenqt's send path, as the group state machine (groupchat/group.py)  *)
(* and its adapter (acks.py) run it, over the protocol model GroupChat.tla.*)
(*                                                                         *)
(* A message is composed, then written. A control message numbers whoever *)
(* can be numbered when it is composed, at indexes after everything        *)
(* written or still pending; it takes effect in the roster only when       *)
(* written. katzenqt abandons only content (a cancelled upload, or the     *)
(* whole conversation), which numbers nobody, so content is left out.      *)
(*                                                                         *)
(* An induction composes whatever control is owed and holds: no more is    *)
(* composed until the Introduction. Each stream starts the new member      *)
(* where the introducer had read it at the hold. Once nothing is pending,  *)
(* the reply is built from the roster written, and the Introduction is     *)
(* composed, ending the hold. The new member joins when it is written.     *)
(*                                                                         *)
(* The hold keeps acknowledgements back too; Backfill.tla covers those.   *)
(*                                                                         *)
(* Each flag undoes one guard:                                             *)
(*   BugNoWait       the reply need not wait for pending messages;         *)
(*   AbandonControl  a control message or Introduction may be abandoned:   *)
(*                   its members are owed numbering again, as abandoned()  *)
(*                   does, but the indexes reserved after it stay taken.   *)
(***************************************************************************)
EXTENDS GroupChat

CONSTANTS BugNoWait, AbandonControl

VARIABLES
    pending, \* pending[m]: m's composed messages, oldest first
    holding, \* holding[m]: the member m is inducting, or NoOne
    starts,  \* starts[m]: where m had read each stream when it held
    reply,   \* reply[m]: what the new member gets when the Introduction is written
    gap      \* some member wrote a roster index past the end of its roster

cvars == <<vars, pending, holding, starts, reply, gap>>

PendingRange(m) == {pending[m][k] : k \in DOMAIN pending[m]}

\* Members m has numbered, or will once what is pending is written.
Numbering(m) == Range(roster[m]) \cup UNION {Range(p.newcomers) : p \in PendingRange(m)}

\* The next index of m's roster, counting what is pending.
Size(m) == LET reserved == {p.first + Len(p.newcomers) : p \in PendingRange(m)}
           IN CHOOSE s \in reserved \cup {Len(roster[m])} : \A r \in reserved \cup {Len(roster[m])} : r <= s

Room(m) == Len(stream[m]) + Len(pending[m]) < MaxLen

Inducting(n) == \E m \in Members : holding[m] = n \/ \E p \in PendingRange(m) : p.intro = n

\* m composes the control message it owes, if any.
Staged(m) ==
    LET who(u) == Named(intros[m], u[1], u[2])
        stale == {u \in unnumbered[m] : who(u) \in Numbering(m)}
        can == unnumbered[m] \ stale
        order == CHOOSE o \in [1..Cardinality(can) -> can] : Range(o) = can
        size == Size(m)
    IN [refs |-> order,
        first |-> size,
        nums |-> {<<size + k - 1, who(order[k])>> : k \in 1..Cardinality(can)},
        newcomers |-> [k \in 1..Cardinality(can) |-> who(order[k])],
        intro |-> NoOne,
        iat |-> owesIat[m],
        done |-> stale \cup can]

Owes(m) == LET s == Staged(m) IN s.nums # {} \/ s.iat # None

Compose(m) ==
    /\ m \in joined
    /\ holding[m] = NoOne
    /\ Room(m)
    /\ Owes(m)
    /\ pending' = [pending EXCEPT ![m] = Append(@, Staged(m))]
    /\ unnumbered' = [unnumbered EXCEPT ![m] = @ \ Staged(m).done]
    /\ owesIat' = [owesIat EXCEPT ![m] = None]
    /\ UNCHANGED <<stream, joined, roster, read, ent, keys, intros, started, awaiting, introducer, skipped,
                   holding, starts, reply, gap>>

\* i begins inducting n: anything owed is composed first.
BeginInduction(i, n) ==
    /\ i \in joined /\ n \in Joiners \ joined
    /\ holding[i] = NoOne /\ ~Inducting(n)
    /\ IF Owes(i)
       THEN /\ Room(i)
            /\ pending' = [pending EXCEPT ![i] = Append(@, Staged(i))]
            /\ unnumbered' = [unnumbered EXCEPT ![i] = @ \ Staged(i).done]
            /\ owesIat' = [owesIat EXCEPT ![i] = None]
       ELSE UNCHANGED <<pending, unnumbered, owesIat>>
    /\ holding' = [holding EXCEPT ![i] = n]
    /\ starts' = [starts EXCEPT ![i] = read[i]]
    /\ UNCHANGED <<stream, joined, roster, read, ent, keys, intros, started, awaiting, introducer, skipped, reply, gap>>

\* i hands over the reply and composes the Introduction, ending the hold.
HandOver(i) ==
    /\ holding[i] # NoOne
    /\ BugNoWait \/ pending[i] = <<>>
    /\ Room(i)
    /\ LET n == holding[i]
           mine == {<<k - 1, roster[i][k]>> : k \in DOMAIN roster[i]}
           given(x) == {<<e[1], <<e[2]>>>> : e \in {e \in (IF x = i THEN mine ELSE View(i, x)) : e[2] # NoOne}}
       IN /\ pending' = [pending EXCEPT ![i] = Append(@,
                [refs |-> <<>>, first |-> Size(i), nums |-> {<<Size(i)>>}, newcomers |-> <<n>>,
                 intro |-> n, iat |-> None, done |-> {}])]
          /\ reply' = [reply EXCEPT ![i] =
                [roster |-> roster[i],
                 ent |-> [x \in Members |-> IF x # n /\ x \in Range(roster[i]) THEN given(x) ELSE {}],
                 intros |-> IF HandIntroductions THEN {t \in intros[i] : t[3] \in Range(roster[i])} ELSE {},
                 keys |-> Range(roster[i]) \cup {n},
                 read |-> starts[i]]]
    /\ holding' = [holding EXCEPT ![i] = NoOne]
    /\ UNCHANGED <<vars, starts, gap>>

CancelInduction(i) ==
    /\ holding[i] # NoOne
    /\ holding' = [holding EXCEPT ![i] = NoOne]
    /\ UNCHANGED <<vars, pending, starts, reply, gap>>

\* m writes its oldest pending message.
Write(m) ==
    /\ pending[m] # <<>>
    /\ LET p == Head(pending[m])
           box == <<m, Len(stream[m]) + 1>>
           n == p.intro
           fresh == n # NoOne /\ n \notin joined
           r == reply[m]
       IN /\ pending' = [pending EXCEPT ![m] = Tail(@)]
          /\ stream' = [stream EXCEPT ![m] = Append(@, [numbers |-> p.nums, intro |-> n, iat |-> p.iat])]
          /\ gap' = (gap \/ (p.newcomers # <<>> /\ p.first # Len(roster[m])))
          /\ LET r1 == [roster EXCEPT ![m] = @ \o p.newcomers]
             IN roster' = IF fresh THEN [r1 EXCEPT ![n] = Append(r.roster, n)] ELSE r1
          /\ LET e1 == [ent EXCEPT ![m][m] = @ \cup {<<p.first + k - 1, <<p.newcomers[k]>>>> :
                                                     k \in DOMAIN p.newcomers}]
             IN ent' = IF fresh THEN [e1 EXCEPT ![n] = r.ent] ELSE e1
          /\ LET i1 == IF n = NoOne THEN intros ELSE [intros EXCEPT ![m] = @ \cup {<<m, box, n>>}]
             IN intros' = IF fresh THEN [i1 EXCEPT ![n] = r.intros] ELSE i1
          /\ LET k1 == IF n = NoOne THEN keys ELSE [keys EXCEPT ![m] = @ \cup {n}]
             IN keys' = IF fresh THEN [k1 EXCEPT ![n] = r.keys] ELSE k1
          /\ read' = IF fresh THEN [read EXCEPT ![n] = [y \in Members |-> IF y = m THEN box[2] - 1 ELSE r.read[y]]]
                     ELSE read
          /\ joined' = IF fresh THEN joined \cup {n} ELSE joined
          /\ introducer' = IF fresh THEN [introducer EXCEPT ![n] = m] ELSE introducer
    /\ UNCHANGED <<started, unnumbered, owesIat, awaiting, skipped, holding, starts, reply>>

\* m's pending message k will never be written: whoever it numbered is owed
\* numbering again.
Abandon(m, k) ==
    /\ AbandonControl
    /\ k \in DOMAIN pending[m]
    /\ LET p == pending[m][k]
       IN /\ pending' = [pending EXCEPT ![m] = SubSeq(@, 1, k - 1) \o SubSeq(@, k + 1, Len(@))]
          /\ unnumbered' = [unnumbered EXCEPT ![m] = @ \cup Range(p.refs)]
    /\ UNCHANGED <<stream, joined, roster, read, ent, keys, intros, started, owesIat, awaiting, introducer, skipped,
                   holding, starts, reply, gap>>

CInit ==
    /\ Init
    /\ pending = [m \in Members |-> <<>>]
    /\ holding = [m \in Members |-> NoOne]
    /\ starts = [m \in Members |-> [y \in Members |-> 0]]
    /\ reply = [m \in Members |-> <<>>]
    /\ gap = FALSE

CNext ==
    \/ \E m, y \in Members : (Read(m, y) \/ Skip(m, y)) /\ UNCHANGED <<pending, holding, starts, reply, gap>>
    \/ \E m \in Members : Compose(m) \/ Write(m) \/ HandOver(m) \/ CancelInduction(m)
    \/ \E m \in Members : \E k \in 1..MaxLen : Abandon(m, k)
    \/ \E i, n \in Members : BeginInduction(i, n)

CSpec == CInit /\ [][CNext]_cvars

(* Properties *)

\* Every index a member writes is the next of its roster.
NoGap == ~gap

CQuiet == Quiet /\ \A m \in Members : pending[m] = <<>> /\ holding[m] = NoOne

CConverged ==
    CQuiet => \A m, x \in joined : m # x =>
        \A i \in 0..(Len(roster[x]) - 1) : At(View(m, x), i) = roster[x][i + 1]

=============================================================================

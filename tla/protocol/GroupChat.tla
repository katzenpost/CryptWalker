----------------------------- MODULE GroupChat -----------------------------
(***************************************************************************)
(* Rosters across a group, with explicit numbering. See "Rosters" in the   *)
(* group chat spec.                                                        *)
(*                                                                         *)
(* A box's MessageBoxIndex is opaque: here it is <<owner, q>>, unique to   *)
(* one box of one stream, and the protocol only compares two for           *)
(* equality. Only a reader stepping through a stream uses q, to find the  *)
(* next box, as BACAP steps an index forward.                              *)
(*                                                                         *)
(* A member numbers another by announcing it in the Numbers of a control   *)
(* message: the index assigned, its introducer's index in the sender's     *)
(* roster, and the MessageBoxIndex of the Introduction. An Introduction    *)
(* numbers the member it introduces with the index alone. A new member     *)
(* says where it joined with IntroducedAt, once it has read its            *)
(* Introduction; its roster began as its introducer's, up to the index the *)
(* introducer gave it. An introducer cannot tell which invitation a member *)
(* took, so it too waits for the member's IntroducedAt. A box a watcher    *)
(* skips (a hole, a jump, content its owner deleted) leaves indexes        *)
(* unresolved, never misplaced.                                            *)
(*                                                                         *)
(* A watcher resolves each Numbers entry as it reads it, as a client does: *)
(* to a member's key, to the Introduction that names it, or to nothing.    *)
(*                                                                         *)
(* HandIntroductions chooses whether the reply to a new member hands over  *)
(* the Introductions its introducer has read, as well as the rosters.      *)
(* UseIntroducedAt chooses whether a watcher waits for IntroducedAt to     *)
(* know where a member's roster began, or takes the first Introduction of  *)
(* it that it reads.                                                       *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    FounderSeq,        \* founders, in the order they all number themselves
    Joiners,           \* members who may be inducted later
    NoOne,             \* "this message introduces nobody", and "not known"
    MaxLen,            \* the most messages a stream holds
    HandIntroductions, \* the reply to a new member carries the Introductions read
    UseIntroducedAt,   \* a member's roster begins where its IntroducedAt says
    AllowSkip          \* a reader may pass a box without reading it

Founders == {FounderSeq[i] : i \in DOMAIN FounderSeq}
Members == Founders \cup Joiners
None == <<>>
Depth == Cardinality(Members)

VARIABLES
    stream,     \* stream[m]: m's messages: [numbers, intro, iat]
    joined,     \* members in the group
    roster,     \* roster[m]: m's own roster
    read,       \* read[m][y]: boxes of y's stream m has passed
    ent,        \* ent[m][x]: <<index, value>> m has for x's roster; value is <<key>>, <<introducer, box>> or None
    intros,     \* intros[m]: <<introducer, box, member>> for each Introduction m has read or been handed
    started,    \* started[m][x]: <<introducer, index>>: x's roster began as the introducer's through index; or None
    unnumbered, \* unnumbered[m]: <<introducer, box>> of Introductions read whose member m has not numbered
    owesIat,    \* owesIat[m]: the box of m's Introduction, to announce in IntroducedAt; None once sent
    awaiting,   \* awaiting[m][x]: the box x's IntroducedAt named before m read it; or None
    introducer, \* introducer[n]: who inducted n
    skipped     \* some reader has passed a box without reading it

vars == <<stream, joined, roster, read, ent, intros, started, unnumbered, owesIat, awaiting, introducer, skipped>>

Range(s) == {s[i] : i \in DOMAIN s}
IndexOf(s, e) == (CHOOSE i \in DOMAIN s : s[i] = e) - 1
NoDup(s) == \A i, j \in DOMAIN s : s[i] = s[j] => i = j

(* What a watcher can tell of a roster, from its entries E, Introductions I *)
(* and starts S.                                                           *)

\* Who the Introduction in box b, by introducer by, introduced.
Named(I, by, b) == IF \E t \in I : t[1] = by /\ t[2] = b THEN (CHOOSE t \in I : t[1] = by /\ t[2] = b)[3] ELSE NoOne

RECURSIVE Res(_, _, _, _, _, _)
Res(E, I, S, x, k, d) ==
    IF \E e \in E[x] : e[1] = k
    THEN LET v == (CHOOSE e \in E[x] : e[1] = k)[2]
         IN CASE Len(v) = 1 -> v[1]
              [] Len(v) = 2 -> Named(I, v[1], v[2])
              [] OTHER -> NoOne
    ELSE IF S[x] # None /\ k <= S[x][2] /\ d > 0 THEN Res(E, I, S, S[x][1], k, d - 1)
    ELSE NoOne

RECURSIVE Idx(_, _, _, _)
Idx(E, S, x, d) ==
    {e[1] : e \in E[x]} \cup
        (IF S[x] # None /\ d > 0 THEN {k \in Idx(E, S, S[x][1], d - 1) : k <= S[x][2]} ELSE {})

IndexIn(E, I, S, x, n) ==
    LET ks == {k \in Idx(E, S, x, Depth) : Res(E, I, S, x, k, Depth) = n}
    IN IF ks = {} THEN -1 ELSE CHOOSE k \in ks : TRUE

\* n's roster began as i's, through the index i gave n, if that is known.
Begin(E, I, S, n, i) ==
    LET k == IndexIn(E, I, S, i, n)
    IN IF k < 0 THEN S ELSE [S EXCEPT ![n] = <<i, k>>]

View(m, x) ==
    {<<k, Res(ent[m], intros[m], started[m], x, k, Depth)>> : k \in Idx(ent[m], started[m], x, Depth)}

\* The member at index i among entries, a set of <<index, member>>.
At(entries, i) == IF \E e \in entries : e[1] = i THEN (CHOOSE e \in entries : e[1] = i)[2] ELSE NoOne

(* State *)

TypeOK ==
    /\ joined \subseteq Members
    /\ \A m \in Members : Len(stream[m]) <= MaxLen

Init ==
    /\ stream = [m \in Members |-> <<>>]
    /\ joined = Founders
    /\ roster = [m \in Members |-> IF m \in Founders THEN FounderSeq ELSE <<>>]
    /\ read = [m \in Members |-> [y \in Members |-> 0]]
    /\ ent = [m \in Members |-> [x \in Members |->
                IF m \in Founders /\ x \in Founders
                THEN {<<i - 1, <<FounderSeq[i]>>>> : i \in DOMAIN FounderSeq} ELSE {}]]
    /\ intros = [m \in Members |-> {}]
    /\ started = [m \in Members |-> [x \in Members |-> None]]
    /\ unnumbered = [m \in Members |-> {}]
    /\ owesIat = [m \in Members |-> None]
    /\ awaiting = [m \in Members |-> [x \in Members |-> None]]
    /\ introducer = [m \in Members |-> m]
    /\ skipped = FALSE

(* Reading *)

\* m has y's read cap: handed it, or read an Introduction of y.
Follows(m, y) == ent[m][y] # {} \/ started[m][y] # None \/ \E t \in intros[m] : t[3] = y

\* m reads the next box of y's stream.
Read(m, y) ==
    /\ m \in joined /\ y \in joined /\ m # y
    /\ Follows(m, y)
    /\ read[m][y] < Len(stream[y])
    /\ LET q == read[m][y] + 1
           box == <<y, q>>
           msg == stream[y][q]
           n == msg.intro
           E0 == ent[m]
           I0 == intros[m]
           S0 == started[m]
           value(e) ==
               IF Len(e) = 1 THEN IF n # NoOne THEN <<y, box>> ELSE None
               ELSE LET by == Res(E0, I0, S0, y, e[2], Depth)
                    IN IF by = NoOne THEN None ELSE <<by, e[3]>>
           E1 == [E0 EXCEPT ![y] = @ \cup {<<e[1], value(e)>> :
                                            e \in {e \in msg.numbers : ~\E f \in E0[y] : f[1] = e[1]}}]
           I1 == IF n = NoOne THEN I0 ELSE I0 \cup {<<y, box, n>>}
           \* an Introduction an IntroducedAt named before m read it
           waited == UseIntroducedAt /\ n # NoOne /\ awaiting[m][n] = box
           \* without IntroducedAt, the first Introduction read
           first == ~UseIntroducedAt /\ n # NoOne /\ n # m /\ S0[n] = None /\ n \notin Founders
           S1 == IF waited \/ first THEN Begin(E1, I1, S0, n, y) ELSE S0
           \* the Introduction y's IntroducedAt names, if m has read it
           iatKnown == UseIntroducedAt /\ msg.iat # None /\ \E t \in I1 : t[2] = msg.iat /\ t[3] = y
           S2 == IF iatKnown THEN Begin(E1, I1, S1, y, (CHOOSE t \in I1 : t[2] = msg.iat /\ t[3] = y)[1])
                 ELSE S1
           isNew == n # NoOne /\ n # m /\ n \notin Range(roster[m])
                    /\ ~\E u \in unnumbered[m] : Named(I0, u[1], u[2]) = n
       IN /\ read' = [read EXCEPT ![m][y] = q]
          /\ ent' = [ent EXCEPT ![m] = E1]
          /\ intros' = [intros EXCEPT ![m] = I1]
          /\ started' = [started EXCEPT ![m] = S2]
          /\ unnumbered' = IF isNew THEN [unnumbered EXCEPT ![m] = @ \cup {<<y, box>>}] ELSE unnumbered
          /\ owesIat' = IF n = m /\ y = introducer[m] /\ owesIat[m] = None
                        THEN [owesIat EXCEPT ![m] = box] ELSE owesIat
          /\ awaiting' =
               LET a1 == IF waited THEN [awaiting[m] EXCEPT ![n] = None] ELSE awaiting[m]
                   a2 == IF UseIntroducedAt /\ msg.iat # None /\ ~iatKnown
                         THEN [a1 EXCEPT ![y] = msg.iat] ELSE a1
               IN [awaiting EXCEPT ![m] = a2]
    /\ UNCHANGED <<stream, joined, roster, introducer, skipped>>

\* m passes the next box of y's stream without reading it.
Skip(m, y) ==
    /\ AllowSkip
    /\ m \in joined /\ y \in joined /\ m # y
    /\ Follows(m, y)
    /\ read[m][y] < Len(stream[y])
    /\ read' = [read EXCEPT ![m][y] = @ + 1]
    /\ skipped' = TRUE
    /\ UNCHANGED <<stream, joined, roster, ent, intros, started, unnumbered, owesIat, awaiting, introducer>>

(* Writing *)

\* m sends a control message: numbering whoever it can, and its IntroducedAt.
Number(m) ==
    /\ m \in joined
    /\ Len(stream[m]) < MaxLen
    /\ LET who(u) == Named(intros[m], u[1], u[2])
           stale == {u \in unnumbered[m] : who(u) \in Range(roster[m])}
           can == {u \in unnumbered[m] \ stale : u[1] \in Range(roster[m])}
       IN /\ can # {} \/ owesIat[m] # None
          /\ \E order \in [1..Cardinality(can) -> can] :
               /\ Range(order) = can
               /\ LET size == Len(roster[m])
                      nums == {<<size + k - 1, IndexOf(roster[m], order[k][1]), order[k][2]>> :
                               k \in 1..Cardinality(can)}
                      newcomers == [k \in 1..Cardinality(can) |-> who(order[k])]
                  IN /\ stream' = [stream EXCEPT ![m] =
                                     Append(@, [numbers |-> nums, intro |-> NoOne, iat |-> owesIat[m]])]
                     /\ roster' = [roster EXCEPT ![m] = @ \o newcomers]
                     /\ ent' = [ent EXCEPT ![m][m] = @ \cup {<<size + k - 1, <<newcomers[k]>>>> :
                                                             k \in 1..Cardinality(can)}]
          /\ unnumbered' = [unnumbered EXCEPT ![m] = @ \ (can \cup stale)]
          /\ owesIat' = [owesIat EXCEPT ![m] = None]
    /\ UNCHANGED <<joined, read, intros, started, awaiting, introducer, skipped>>

\* i introduces n. A new member gets the reply: i's roster with n after it,
\* each member's roster as i can tell it, and the Introductions i has read.
\* A member already in the group is only announced again.
Introduce(i, n) ==
    /\ i \in joined /\ n \in Joiners /\ n # i
    /\ Len(stream[i]) < MaxLen
    /\ \A t \in intros[i] : t[3] # n \/ n \notin joined
    /\ LET box == <<i, Len(stream[i]) + 1>>
           fresh == n \notin Range(roster[i])
           nums == IF fresh THEN {<<Len(roster[i])>>} ELSE {}
           own == IF fresh THEN Append(roster[i], n) ELSE roster[i]
           mine == {<<k - 1, own[k]>> : k \in DOMAIN own}
           given(x) == {<<e[1], <<e[2]>>>> : e \in {e \in (IF x = i THEN mine ELSE View(i, x)) : e[2] # NoOne}}
       IN /\ stream' = [stream EXCEPT ![i] = Append(@, [numbers |-> nums, intro |-> n, iat |-> None])]
          /\ roster' = IF n \in joined THEN [roster EXCEPT ![i] = own]
                       ELSE [roster EXCEPT ![i] = own, ![n] = Append(roster[i], n)]
          /\ intros' = IF n \in joined THEN [intros EXCEPT ![i] = @ \cup {<<i, box, n>>}]
                       ELSE [intros EXCEPT ![i] = @ \cup {<<i, box, n>>},
                                           ![n] = IF HandIntroductions THEN intros[i] ELSE {}]
          /\ ent' = IF n \in joined THEN [ent EXCEPT ![i][i] = given(i)]
                    ELSE [ent EXCEPT ![i][i] = given(i),
                                     ![n] = [x \in Members |->
                                               IF x # n /\ x \in Range(roster[i]) THEN given(x) ELSE {}]]
          /\ read' = IF n \in joined THEN read
                     ELSE [read EXCEPT ![n] = [y \in Members |-> IF y = i THEN box[2] - 1 ELSE read[i][y]]]
          /\ joined' = joined \cup {n}
          /\ introducer' = IF n \in joined THEN introducer ELSE [introducer EXCEPT ![n] = i]
          /\ UNCHANGED <<started, unnumbered, owesIat, awaiting, skipped>>

Next ==
    \/ \E m \in Members : Number(m)
    \/ \E m, y \in Members : Read(m, y) \/ Skip(m, y)
    \/ \E i, n \in Members : Introduce(i, n)

Spec == Init /\ [][Next]_vars

(* Properties *)

RosterNoDup == \A m \in joined : NoDup(roster[m])

\* Whoever a watcher can name at an index of a roster is whoever its owner
\* put there.
RosterAgree ==
    \A m, x \in joined : m # x => \A e \in View(m, x) :
        e[2] # NoOne => e[1] < Len(roster[x]) /\ roster[x][e[1] + 1] = e[2]

\* The roster index a new member takes is the one its introducer gives it.
InductionIndex ==
    \A n \in joined \ Founders : IndexOf(roster[introducer[n]], n) = IndexOf(roster[n], n)

\* Once everyone has read everything, nothing is skipped, and everyone has
\* numbered whoever it can and said where it joined, every watcher can name
\* every member of every roster.
Quiet ==
    /\ ~skipped
    /\ \A m, y \in joined : m # y => read[m][y] = Len(stream[y])
    /\ \A m \in joined : owesIat[m] = None /\ unnumbered[m] = {}

Converged ==
    Quiet => \A m, x \in joined : m # x =>
        \A i \in 0..(Len(roster[x]) - 1) : At(View(m, x), i) = roster[x][i + 1]

\* Messages written across the group, for bounding a model run.
RECURSIVE SumLen(_, _)
SumLen(f, S) == IF S = {} THEN 0 ELSE LET x == CHOOSE x \in S : TRUE IN Len(f[x]) + SumLen(f, S \ {x})

Symmetry == Permutations(Joiners)

=============================================================================

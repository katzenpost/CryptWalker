---- MODULE Backfill_TTrace_1791062332 ----
EXTENDS Sequences, TLCExt, Toolbox, Backfill, Backfill_TEConstants, Naturals, TLC

_expression ==
    LET Backfill_TEExpression == INSTANCE Backfill_TEExpression
    IN Backfill_TEExpression!expression
----

_trace ==
    LET Backfill_TETrace == INSTANCE Backfill_TETrace
    IN Backfill_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        cursor = ((r1 :> 0 @@ r2 :> 0))
        /\
        wEpoch = ((0 :> 0 @@ 1 :> 0 @@ 2 :> 0))
        /\
        lastRw = ((0 :> 1 @@ 1 :> -1 @@ 2 :> -1))
        /\
        epoch = (2)
        /\
        store = ((0 :> {} @@ 1 :> {} @@ 2 :> {}))
        /\
        got = ((r1 :> {} @@ r2 :> {}))
        /\
        acked = ((r1 :> -1 @@ r2 :> -1))
        /\
        seen = ((r1 :> {} @@ r2 :> {}))
        /\
        probe = ((r1 :> 0 @@ r2 :> 0))
        /\
        mode = ((r1 :> "reading" @@ r2 :> "reading"))
        /\
        record = ((0 :> "plain" @@ 1 :> "none" @@ 2 :> "none"))
        /\
        online = (TRUE)
        /\
        written = (1)
    )
----

_init ==
    /\ epoch = _TETrace[1].epoch
    /\ mode = _TETrace[1].mode
    /\ written = _TETrace[1].written
    /\ store = _TETrace[1].store
    /\ wEpoch = _TETrace[1].wEpoch
    /\ probe = _TETrace[1].probe
    /\ lastRw = _TETrace[1].lastRw
    /\ cursor = _TETrace[1].cursor
    /\ online = _TETrace[1].online
    /\ record = _TETrace[1].record
    /\ got = _TETrace[1].got
    /\ acked = _TETrace[1].acked
    /\ seen = _TETrace[1].seen
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ epoch  = _TETrace[i].epoch
        /\ epoch' = _TETrace[j].epoch
        /\ mode  = _TETrace[i].mode
        /\ mode' = _TETrace[j].mode
        /\ written  = _TETrace[i].written
        /\ written' = _TETrace[j].written
        /\ store  = _TETrace[i].store
        /\ store' = _TETrace[j].store
        /\ wEpoch  = _TETrace[i].wEpoch
        /\ wEpoch' = _TETrace[j].wEpoch
        /\ probe  = _TETrace[i].probe
        /\ probe' = _TETrace[j].probe
        /\ lastRw  = _TETrace[i].lastRw
        /\ lastRw' = _TETrace[j].lastRw
        /\ cursor  = _TETrace[i].cursor
        /\ cursor' = _TETrace[j].cursor
        /\ online  = _TETrace[i].online
        /\ online' = _TETrace[j].online
        /\ record  = _TETrace[i].record
        /\ record' = _TETrace[j].record
        /\ got  = _TETrace[i].got
        /\ got' = _TETrace[j].got
        /\ acked  = _TETrace[i].acked
        /\ acked' = _TETrace[j].acked
        /\ seen  = _TETrace[i].seen
        /\ seen' = _TETrace[j].seen

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("Backfill_TTrace_1791062332.json", _TETrace)

=============================================================================

 Note that you can extract this module `Backfill_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `Backfill_TEExpression.tla` file takes precedence 
  over the module `Backfill_TEExpression` below).

---- MODULE Backfill_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, Backfill, Backfill_TEConstants, Naturals, TLC

expression == 
    [
        \* To hide variables of the `Backfill` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        epoch |-> epoch
        ,mode |-> mode
        ,written |-> written
        ,store |-> store
        ,wEpoch |-> wEpoch
        ,probe |-> probe
        ,lastRw |-> lastRw
        ,cursor |-> cursor
        ,online |-> online
        ,record |-> record
        ,got |-> got
        ,acked |-> acked
        ,seen |-> seen
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_epochUnchanged |-> epoch = epoch'
        
        \* Format the `epoch` variable as Json value.
        \* ,_epochJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(epoch)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_epochModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].epoch # _TETrace[s-1].epoch
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE Backfill_TETrace ----
\*EXTENDS IOUtils, Backfill, Backfill_TEConstants, TLC
\*
\*trace == IODeserialize("Backfill_TTrace_1791062332.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE Backfill_TETrace ----
EXTENDS Backfill, Backfill_TEConstants, TLC

trace == 
    <<
    ([cursor |-> (r1 :> 0 @@ r2 :> 0),wEpoch |-> (0 :> 0 @@ 1 :> 0 @@ 2 :> 0),lastRw |-> (0 :> -1 @@ 1 :> -1 @@ 2 :> -1),epoch |-> 0,store |-> (0 :> {} @@ 1 :> {} @@ 2 :> {}),got |-> (r1 :> {} @@ r2 :> {}),acked |-> (r1 :> -1 @@ r2 :> -1),seen |-> (r1 :> {} @@ r2 :> {}),probe |-> (r1 :> 0 @@ r2 :> 0),mode |-> (r1 :> "reading" @@ r2 :> "reading"),record |-> (0 :> "none" @@ 1 :> "none" @@ 2 :> "none"),online |-> TRUE,written |-> 0]),
    ([cursor |-> (r1 :> 0 @@ r2 :> 0),wEpoch |-> (0 :> 0 @@ 1 :> 0 @@ 2 :> 0),lastRw |-> (0 :> 0 @@ 1 :> -1 @@ 2 :> -1),epoch |-> 0,store |-> (0 :> {<<0, "data">>} @@ 1 :> {} @@ 2 :> {}),got |-> (r1 :> {} @@ r2 :> {}),acked |-> (r1 :> -1 @@ r2 :> -1),seen |-> (r1 :> {} @@ r2 :> {}),probe |-> (r1 :> 0 @@ r2 :> 0),mode |-> (r1 :> "reading" @@ r2 :> "reading"),record |-> (0 :> "plain" @@ 1 :> "none" @@ 2 :> "none"),online |-> TRUE,written |-> 1]),
    ([cursor |-> (r1 :> 0 @@ r2 :> 0),wEpoch |-> (0 :> 0 @@ 1 :> 0 @@ 2 :> 0),lastRw |-> (0 :> 0 @@ 1 :> -1 @@ 2 :> -1),epoch |-> 1,store |-> (0 :> {<<0, "data">>} @@ 1 :> {} @@ 2 :> {}),got |-> (r1 :> {} @@ r2 :> {}),acked |-> (r1 :> -1 @@ r2 :> -1),seen |-> (r1 :> {} @@ r2 :> {}),probe |-> (r1 :> 0 @@ r2 :> 0),mode |-> (r1 :> "reading" @@ r2 :> "reading"),record |-> (0 :> "plain" @@ 1 :> "none" @@ 2 :> "none"),online |-> TRUE,written |-> 1]),
    ([cursor |-> (r1 :> 0 @@ r2 :> 0),wEpoch |-> (0 :> 0 @@ 1 :> 0 @@ 2 :> 0),lastRw |-> (0 :> 1 @@ 1 :> -1 @@ 2 :> -1),epoch |-> 1,store |-> (0 :> {<<0, "data">>} @@ 1 :> {} @@ 2 :> {}),got |-> (r1 :> {} @@ r2 :> {}),acked |-> (r1 :> -1 @@ r2 :> -1),seen |-> (r1 :> {} @@ r2 :> {}),probe |-> (r1 :> 0 @@ r2 :> 0),mode |-> (r1 :> "reading" @@ r2 :> "reading"),record |-> (0 :> "plain" @@ 1 :> "none" @@ 2 :> "none"),online |-> TRUE,written |-> 1]),
    ([cursor |-> (r1 :> 0 @@ r2 :> 0),wEpoch |-> (0 :> 0 @@ 1 :> 0 @@ 2 :> 0),lastRw |-> (0 :> 1 @@ 1 :> -1 @@ 2 :> -1),epoch |-> 2,store |-> (0 :> {} @@ 1 :> {} @@ 2 :> {}),got |-> (r1 :> {} @@ r2 :> {}),acked |-> (r1 :> -1 @@ r2 :> -1),seen |-> (r1 :> {} @@ r2 :> {}),probe |-> (r1 :> 0 @@ r2 :> 0),mode |-> (r1 :> "reading" @@ r2 :> "reading"),record |-> (0 :> "plain" @@ 1 :> "none" @@ 2 :> "none"),online |-> TRUE,written |-> 1])
    >>
----


=============================================================================

---- MODULE Backfill_TEConstants ----
EXTENDS Backfill

CONSTANTS r1, r2

=============================================================================

---- CONFIG Backfill_TTrace_1791062332 ----
CONSTANTS
    Readers = { r1 , r2 }
    N = 3
    MaxEpoch = 4
    Retention = 3
    RefreshOnMatch = FALSE
    NaiveAdopt = FALSE
    AckFurthest = TRUE
    r1 = r1
    r2 = r2

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Sat Oct 03 21:18:53 UTC 2026
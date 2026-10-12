module

public import Veil

/-!
The safety half of `tla/protocol/Backfill.tla`, for any number of readers and positions. It
allows more than the TLA+ model, so its safety properties hold there too: epochs are unbounded and
a box is its current and previous slot, `Discard` may come at any time, polling, scans and jumps
are always enabled, a reader keeps every position it skips, and a scan's jump is a separate `Jump`
step.
-/

veil module Backfill

type reader
type pos
instantiate ord : TotalOrderWithMinimum pos
open TotalOrderWithMinimum

-- What a replica slot holds for a box.
enum box = { empty, data, tomb }
-- The owner's Sent-box record of a position.
enum entry = { unsent, plain, held, gone }

-- An ack names the furthest box read, as the spec says, rather than the end
-- of the unbroken run.
immutable individual ackFurthest : Bool

-- The replica: what each box holds in the current and the previous epoch.
function cur : pos → box
function prv : pos → box

-- The stream owner.
relation wrote : pos → Bool
function record : pos → entry
relation rwCur : pos → Bool
relation rwPrv : pos → Bool
individual online : Bool

-- The readers.
function cursor : reader → pos
relation atEnd : reader → Bool
relation seen : reader → pos → Bool
relation got : reader → pos → Bool
relation holes : reader → pos → Bool
-- `ackd r p`: r's published acknowledgements reach position `p`.
relation ackd : reader → pos → Bool

#gen_state

-- Positions are discrete: any position below another has a next one.
assumption [discrete] ∀ (x y : pos), lt x y → ∃ z, next x z

-- What a read returns: the newest kept slot.
ghost relation looksEmpty (p : pos) := cur p == empty ∧ prv p == empty
ghost relation looksData (p : pos) := cur p == data ∨ (cur p == empty ∧ prv p == data)
ghost relation looksTomb (p : pos) := cur p == tomb ∨ (cur p == empty ∧ prv p == tomb)

-- How far `r`'s next acknowledgement reaches.
ghost relation front (r : reader) (p : pos) :=
  (ackFurthest ∧ ∃ q, seen r q ∧ le p q) ∨ (¬ ackFurthest ∧ ∀ q, le q p → seen r q)

-- `t` is the furthest box another reader has acknowledged.
ghost relation heard (r : reader) (t : pos) :=
  (∃ o, o ≠ r ∧ ackd o t) ∧ ∀ o q, o ≠ r ∧ ackd o q → le q t

ghost relation allAcked (p : pos) := ∀ r, ackd r p

after_init {
  cur P := empty
  prv P := empty
  wrote P := false
  record P := unsent
  rwCur P := false
  rwPrv P := false
  online := true
  cursor R := zero
  atEnd R := false
  seen R P := false
  got R P := false
  holes R P := false
  ackd R P := false
}

/-! ## Time and the replica -/

action Tick {
  prv P := cur P
  cur P := empty
  rwPrv P := rwCur P
  rwCur P := false
}

-- A write as the spec's replica handles it (`SpecStored`): a data write over
-- a tombstone is refused.
procedure store (p : pos) (k : box) {
  if k == tomb then
    cur p := tomb
  else
    if ¬ (cur p == tomb ∨ (cur p == empty ∧ prv p == tomb)) then
      cur p := data
}

/-! ## The stream owner -/

action GoOffline {
  require online
  online := false
}

action GoOnline {
  require ¬ online
  online := true
}

action Send {
  require online
  require ∃ p, ¬ wrote p ∧ ∀ q, lt q p → wrote q
  let p :| ¬ wrote p ∧ ∀ q, lt q p → wrote q
  store p data
  record p := plain
  rwCur p := true
  wrote p := true
}

-- The periodic rewrite, at most once per epoch per box. A box every reader
-- has acknowledged is rewritten as a tombstone.
action Rewrite (p : pos) {
  require online
  require record p == plain ∨ record p == held
  require ¬ rwCur p
  if allAcked p then
    store p tomb
    record p := held
  else
    store p data
  rwCur p := true
}

-- The retention window, at any time.
action Discard (p : pos) {
  require record p == plain ∨ record p == held
  record p := gone
}

/-! ## A reader -/

-- `r` publishes how far it has read, on some later message of its own.
action Publish (r : reader) {
  require ∃ p, front r p ∧ ¬ ackd r p
  ackd r P := decide $ front r P
}

procedure ingest (r : reader) (p : pos) {
  seen r p := true
  if looksData p then
    got r p := true
}

action Read (r : reader) {
  require ¬ atEnd r
  require ¬ looksEmpty (cursor r)
  ingest r (cursor r)
  if ∃ q, next (cursor r) q then
    let q :| next (cursor r) q
    cursor r := q
  else
    atEnd r := true
}

-- Jump to the furthest box another reader has acknowledged, keeping the
-- positions skipped for rechecking. The pick spells out `heard r t`: the model
-- checker cannot run a pick through a ghost relation.
procedure jumpTo (r : reader) {
  let t :| (∃ o, o ≠ r ∧ ackd o t) ∧ ∀ o q, o ≠ r ∧ ackd o q → le q t
  holes r P := decide $ holes r P ∨ (le (cursor r) P ∧ lt P t)
  cursor r := t
}

-- A reader stuck where another reader has acknowledged further.
ghost relation stuck (r : reader) :=
  ¬ atEnd r ∧ looksEmpty (cursor r) ∧ ∃ t, heard r t ∧ lt (cursor r) t

action Jump (r : reader) {
  require stuck r
  jumpTo r
}

-- A skipped position turns up and is polled.
action Poll (r : reader) (p : pos) {
  require holes r p
  require ¬ looksEmpty p
  ingest r p
  holes r p := false
}

-- The user asks for a scan: everything kept is rechecked. The jump that
-- follows in `Backfill.tla` is a `Jump` step here.
action Scan (r : reader) {
  seen r P := decide $ seen r P ∨ (holes r P ∧ ¬ looksEmpty P)
  got r P := decide $ got r P ∨ (holes r P ∧ looksData P)
  holes r P := decide $ holes r P ∧ looksEmpty P
}

/-! ## Properties -/

-- "Every position stays populated": a box its owner wrote or rewrote in this
-- epoch or the last can be read.
safety [populated]
  (record P == plain ∨ record P == held) ∧ (rwCur P ∨ rwPrv P) → ¬ looksEmpty P

-- What a reader acknowledges, it has.
safety [no_silent_loss] ¬ ackFurthest → (ackd R P → got R P)

-- A reader never expects a position beyond the one the owner writes next.
safety [no_overshoot] ¬ atEnd R ∧ lt P (cursor R) → wrote P
safety [no_overshoot_end] atEnd R → wrote P

-- A tombstone stands only where every reader has acknowledged.
safety [no_premature_tombstone] looksTomb P → allAcked P

-- Auxiliary invariants, to make the above inductive.
invariant [wrote_closed] wrote P ∧ lt Q P → wrote Q
invariant [record_wrote] record P != unsent → wrote P
invariant [cur_wrote] cur P != empty → wrote P
invariant [prv_wrote] prv P != empty → wrote P
invariant [seen_wrote] seen R P → wrote P
invariant [rw_cur] rwCur P → cur P != empty
invariant [rw_prv] rwPrv P → prv P != empty
invariant [ackd_front] ackd R P → front R P
invariant [seen_got] ¬ ackFurthest → (seen R P → got R P)

set_option veil.smt.trust false

#gen_spec

-- Declare the verification conditions as theorems, so their axioms can be
-- checked below.
#gen_theorems

#check_invariants

#model_check { reader := Fin 2, pos := Fin 3 } { ackFurthest := false }

-- The assumptions are satisfiable.
sat trace { }

-- Under the spec's rule an ack names a box its reader jumped over: the
-- counterexample TLC finds for `MC_Backfill_SpecAckRule.cfg`.
sat trace [spec_ack_rule_loses] {
  Send
  Read
  Tick
  Tick
  Send
  Read
  Publish
  Jump
  Read
  Publish
  assert (ackFurthest ∧ ∃ r p, ackd r p ∧ ¬ got r p)
}

end Backfill

-- Every verification condition, proved with the solver's answers rebuilt in
-- Lean, rests on Lean's own axioms only.
open Lean in
run_cmd do
  let env ← getEnv
  let own := [``propext, ``Classical.choice, ``Quot.sound]
  let mut n := 0
  for (name, info) in env.constants.map₂.toList do
    unless (`Backfill).isPrefixOf name && info matches .thmInfo _ do continue
    n := n + 1
    for ax in ← collectAxioms name do
      unless own.contains ax do
        throwError "{name} depends on {ax}"
  if n == 0 then throwError "no Backfill theorems"
  logInfo m!"{n} Backfill theorems rest on Lean's own axioms only"

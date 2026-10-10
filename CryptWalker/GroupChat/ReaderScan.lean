/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Logic.Function.Iterate
import Mathlib.Data.List.Basic

/-! # Reading one stream: the walk, the recheck window and each box read

See "Rewrite and scan" in the group chat spec, and katzenqt's `groupchat/reader.py` (`found`,
`walked`, `_forget`) and the driver's walk (`groupchat/sim.py`, `walk`), which this follows.

A box's index `I` is opaque: compared only for equality, and moved forward only by BACAP's
`next`. So one index comes before another exactly when stepping forward from the first meets
the second (`Before`), and a reader finds a box another member acknowledged by walking to it.

* `walk_target`, `walk_skipped`, `walk_furthest`: a walk that finds a target says how many steps
  it took, which proves the target comes after where it started; it keeps the last indexes it
  stepped past, in order; and no target lies further within the walk's limit.
* `found_data`: a box read gives a message to ingest only when it held one.
* `recheck_once`: a kept box read with data is ingested and no longer kept, so it is not
  ingested twice.
* `forget_window`: a reader keeps a box for rechecking only while it is within the window
  behind it, counted in boxes the reader has passed itself. -/

namespace CryptWalker.GroupChat.ReaderScan

variable {I : Type} [DecidableEq I] (next : I → I)

/-- `b` comes after `a` on their stream. -/
def Before (a b : I) : Prop := ∃ n, 0 < n ∧ next^[n] a = b

/-! ## The walk -/

/-- Step forward `n` more times from `index`, having passed `passed`, remembering the last target
met and what had been passed before it. -/
def walkFrom (targets : List I) : ℕ → I → List I → Option (I × List I) → Option (I × List I)
  | 0, _, _, found => found
  | n + 1, index, passed, found =>
    walkFrom targets n (next index) (passed ++ [index])
      (if index ∈ targets then some (index, passed) else found)

/-- Walk forward from `start` through `limit` indexes to the furthest of `targets` met: that
target, the last `keep` indexes stepped past on the way, and the steps taken. -/
def walk (targets : List I) (start : I) (limit keep : ℕ) : Option (I × List I × ℕ) :=
  (walkFrom next targets limit start [] none).map fun f =>
    (f.1, f.2.drop (f.2.length - keep), f.2.length)

/-- The indexes `start`, `next start`, ... : the first `n` of the stream from `start`. -/
def stepsFrom (start : I) (n : ℕ) : List I := (List.range n).map fun j => next^[j] start

omit [DecidableEq I] in
theorem stepsFrom_succ (start : I) (n : ℕ) :
    stepsFrom next start (n + 1) = stepsFrom next start n ++ [next^[n] start] := by
  simp [stepsFrom, List.range_succ]

/-- What a walk remembers: a target, met after exactly the indexes passed before it. -/
def Met (targets : List I) (start : I) (f : I × List I) : Prop :=
  f.1 ∈ targets ∧ f.2 = stepsFrom next start f.2.length ∧ next^[f.2.length] start = f.1

theorem walkFrom_spec (targets : List I) (start : I) :
    ∀ (n : ℕ) (p : ℕ) (found : Option (I × List I)),
      (∀ f, found = some f → Met next targets start f ∧ f.2.length < p) →
      (∀ j, (∀ f, found = some f → f.2.length < j) → j < p → next^[j] start ∉ targets) →
      ∀ f, walkFrom next targets n (next^[p] start) (stepsFrom next start p) found = some f →
        Met next targets start f ∧ f.2.length < p + n ∧
          ∀ j, f.2.length < j → j < p + n → next^[j] start ∉ targets := by
  intro n
  induction n with
  | zero =>
    intro p found hf hnone f hw
    simp only [walkFrom] at hw
    subst hw
    obtain ⟨hm, hlt⟩ := hf _ rfl
    exact ⟨hm, by omega, fun j hj hjp => hnone j (fun g hg => by cases hg; exact hj) hjp⟩
  | succ n ih =>
    intro p found hf hnone f hw
    simp only [walkFrom] at hw
    rw [← Function.iterate_succ_apply' next p, ← stepsFrom_succ] at hw
    have := ih (p + 1) _ ?_ ?_ f hw
    · refine ⟨this.1, by omega, fun j hj hjp => this.2.2 j hj (by omega)⟩
    · intro g hg
      split_ifs at hg with ht
      · cases hg
        refine ⟨⟨ht, ?_, ?_⟩, ?_⟩ <;> simp [stepsFrom]
      · obtain ⟨hm, hlt⟩ := hf g hg
        exact ⟨hm, by omega⟩
    · intro j hj hjp
      split_ifs at hj with ht
      · have := hj _ rfl
        simp [stepsFrom] at this
        omega
      · rcases Nat.lt_succ_iff_lt_or_eq.1 hjp with hjp | rfl
        · exact hnone j hj hjp
        · exact ht

/-- **A walk proves order**: the target it finds is the start stepped forward exactly as many
times as the walk reports, within its limit. -/
theorem walk_target {targets : List I} {start : I} {limit keep : ℕ} {t : I} {skipped : List I}
    {steps : ℕ} (h : walk next targets start limit keep = some (t, skipped, steps)) :
    t ∈ targets ∧ next^[steps] start = t ∧ steps < limit ∧ (0 < steps → Before next start t) := by
  unfold walk at h
  obtain ⟨f, hw, hf⟩ := Option.map_eq_some_iff.1 h
  obtain ⟨⟨hmem, -, hstep⟩, hlt, -⟩ :=
    walkFrom_spec next targets start limit 0 none (by simp) (by simp) f (by simpa [stepsFrom] using hw)
  simp only [Prod.mk.injEq] at hf
  obtain ⟨rfl, -, rfl⟩ := hf
  exact ⟨hmem, hstep, by omega, fun hpos => ⟨_, hpos, hstep⟩⟩

/-- The indexes a walk keeps are the last `keep` it stepped past, in the order it passed them. -/
theorem walk_skipped {targets : List I} {start : I} {limit keep : ℕ} {t : I} {skipped : List I}
    {steps : ℕ} (h : walk next targets start limit keep = some (t, skipped, steps)) :
    skipped = (stepsFrom next start steps).drop (steps - keep) := by
  unfold walk at h
  obtain ⟨f, hw, hf⟩ := Option.map_eq_some_iff.1 h
  obtain ⟨⟨-, hpassed, -⟩, -⟩ :=
    walkFrom_spec next targets start limit 0 none (by simp) (by simp) f (by simpa [stepsFrom] using hw)
  simp only [Prod.mk.injEq] at hf
  obtain ⟨-, rfl, rfl⟩ := hf
  rw [← hpassed]

/-- **A walk goes to the furthest target**: none lies between it and the walk's limit. -/
theorem walk_furthest {targets : List I} {start : I} {limit keep : ℕ} {t : I} {skipped : List I}
    {steps : ℕ} (h : walk next targets start limit keep = some (t, skipped, steps)) :
    ∀ j, steps < j → j < limit → next^[j] start ∉ targets := by
  unfold walk at h
  obtain ⟨f, hw, hf⟩ := Option.map_eq_some_iff.1 h
  obtain ⟨-, -, hfar⟩ :=
    walkFrom_spec next targets start limit 0 none (by simp) (by simp) f (by simpa [stepsFrom] using hw)
  simp only [Prod.mk.injEq] at hf
  obtain ⟨-, -, rfl⟩ := hf
  simpa using hfar

/-! ## Reading a box -/

inductive Mode | idle | reading | scanning
  deriving DecidableEq

/-- What reading a box found. -/
inductive Result | data (payload : List UInt8) | tombstone | notFound
  deriving DecidableEq

structure Reader (I : Type) where
  next : I
  passed : ℕ
  kept : List (I × ℕ)
  mode : Mode

/-- Keep only boxes within `window` of how far the reader has passed. -/
def forget (window : ℕ) (r : Reader I) : Reader I :=
  { r with kept := r.kept.filter fun e => r.passed ≤ e.2 + window }

/-- Take one box read: a message to ingest, if any, and the reader after it. -/
def found (window : ℕ) (r : Reader I) (index : I) (res : Result) (nxt : Option I) :
    Option (List UInt8) × Reader I :=
  match r.kept.find? (fun e => e.1 = index) with
  | some e =>
    match res with
    | .data p => (some p, { r with kept := r.kept.erase e })
    | _ => (none, r)
  | none =>
    if index ≠ r.next ∨ r.mode = .idle then (none, r) else
    match res, nxt with
    | .notFound, _ => (none, { r with mode := .idle })
    | _, none => (none, { r with mode := .idle })
    | res, some n =>
      let kept := if res = .tombstone then r.kept ++ [(index, r.passed)] else r.kept
      (match res with | .data p => some p | _ => none,
       forget window { r with kept := kept, next := n, passed := r.passed + 1 })

theorem found_data {window : ℕ} {r : Reader I} {index : I} {res : Result} {nxt : Option I}
    {p : List UInt8} (h : (found window r index res nxt).1 = some p) : res = .data p := by
  unfold found at h
  split at h
  · cases res <;> simp_all
  · split_ifs at h
    cases res <;> cases nxt <;> simp_all

/-- **A recheck ingests a kept box once**: read with data, it is no longer kept. -/
theorem recheck_once {window : ℕ} {r : Reader I} {index : I} {at_ : ℕ} {p : List UInt8}
    {nxt : Option I} (hk : (index, at_) ∈ r.kept) :
    let out := found window r index (.data p) nxt
    out.1 = some p ∧ out.2.kept.length + 1 = r.kept.length := by
  unfold found
  cases he : r.kept.find? (fun e => e.1 = index) with
  | none =>
    have := List.find?_eq_none.1 he _ hk
    simp at this
  | some e =>
    have hmem := List.mem_of_find?_eq_some he
    simp only [true_and]
    have := List.length_erase_of_mem hmem
    have hpos := List.length_pos_of_mem hmem
    omega

omit [DecidableEq I] in
/-- **The recheck window**: a reader keeps a box only while it is within `window` boxes of how
far it has passed. -/
theorem forget_window (window : ℕ) (r : Reader I) :
    ∀ e ∈ (forget window r).kept, (forget window r).passed ≤ e.2 + window := by
  intro e he
  simp only [forget, List.mem_filter, decide_eq_true_eq] at he
  exact he.2

/-- `BoxIDNotFound` at the box a reader expects stops it there, to be read again later. -/
theorem not_found_stops {window : ℕ} {r : Reader I} {nxt : Option I}
    (hk : ∀ e ∈ r.kept, e.1 ≠ r.next) (hm : r.mode ≠ .idle) :
    found window r r.next .notFound nxt = (none, { r with mode := .idle }) := by
  unfold found
  have : r.kept.find? (fun e => e.1 = r.next) = none :=
    List.find?_eq_none.2 fun e he => by simpa using hk e he
  rw [this]
  simp [hm]

end CryptWalker.GroupChat.ReaderScan

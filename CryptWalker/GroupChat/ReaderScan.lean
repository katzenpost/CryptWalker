/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Logic.Function.Iterate
import Mathlib.Data.List.Basic

/-! # The walk to an acknowledged box

See "Rewrite and scan" in the group chat spec, and katzenqt's `groupchat/walk.py`, which this
follows. The reader itself, and the proof that what it acknowledges it has read, are in
`Member/Reader.lean` and `Member/ReaderProofs.lean`.

A box's index `I` is moved forward only by BACAP's `next`, and each step adds one to its `Idx64`
(`counter`). An acknowledgement names a box by its `Idx64` alone, so a reader reaches it by
advancing its own index to that `Idx64`, with no search.

* `walk_target`, `walk_skipped`, `walk_furthest`, `walk_none`: a walk that finds a target says
  how many steps ahead it is, which proves the target comes after where it started; it keeps the
  last indexes before it, in order; no target lies further within the walk's limit; and a walk
  that finds none has none within its limit.
* `walk_eq_walkBoxes`: for boxes of the reader's own stream, naming them by `Idx64` finds the
  same box, the same indexes before it and the same distance as naming them by their whole
  index and stepping forward until meeting one. -/

namespace CryptWalker.GroupChat.ReaderScan

variable {I : Type} (next : I → I) (counter : I → ℕ)

/-- `b` comes after `a` on their stream. -/
def Before (a b : I) : Prop := ∃ n, 0 < n ∧ next^[n] a = b

/-- The indexes `start`, `next start`, ... : the first `n` of the stream from `start`. -/
def stepsFrom (start : I) (n : ℕ) : List I := (List.range n).map fun j => next^[j] start

/-- The last `keep` of the `steps` indexes from `start`, or all of them for `keep = 0`. -/
def keptOf (start : I) (steps keep : ℕ) : List I :=
  (stepsFrom next start steps).drop (if keep = 0 then 0 else steps - keep)

/-! ## The walk -/

/-- Advance from `start` to the box at the furthest of `targets` fewer than `limit` boxes ahead:
that box, the last `keep` indexes before it (all of them for `keep = 0`), and how many steps
ahead it is. -/
def walk (targets : List ℕ) (start : I) (limit keep : ℕ) : Option (I × List I × ℕ) :=
  ((targets.filter fun t => counter start ≤ t && t < counter start + limit).max?).map fun t =>
    let steps := t - counter start
    (next^[steps] start, keptOf next start steps keep, steps)

/-- The walk of the opaque indexes katzenqt#108 acknowledged with: step forward from `start`,
comparing whole indexes, to the furthest of `boxes` met within `limit` steps. -/
def walkBoxes [DecidableEq I] (boxes : List I) (start : I) (limit keep : ℕ) :
    Option (I × List I × ℕ) :=
  (((List.range limit).filter fun j => next^[j] start ∈ boxes).max?).map fun steps =>
    (next^[steps] start, keptOf next start steps keep, steps)

variable {next counter}

/-- What BACAP guarantees of `Idx64`: each step forward adds one. -/
def Counts (next : I → I) (counter : I → ℕ) : Prop := ∀ i, counter (next i) = counter i + 1

theorem counter_iterate (hc : Counts next counter) (i : I) :
    ∀ n, counter (next^[n] i) = counter i + n
  | 0 => rfl
  | n + 1 => by
    rw [Function.iterate_succ_apply', hc, counter_iterate hc i n]; omega

theorem le_of_max {l : List ℕ} {a b : ℕ} (h : l.max? = some a) (hb : b ∈ l) : b ≤ a :=
  (List.max?_eq_some_iff.1 h).2 b hb

theorem walk_some {targets : List ℕ} {start : I} {limit keep : ℕ} {b : I} {skipped : List I}
    {steps : ℕ} (h : walk next counter targets start limit keep = some (b, skipped, steps)) :
    ∃ t, (targets.filter fun t => counter start ≤ t && t < counter start + limit).max? = some t ∧
      steps = t - counter start ∧ b = next^[steps] start ∧ skipped = keptOf next start steps keep := by
  unfold walk at h
  obtain ⟨t, ht, he⟩ := Option.map_eq_some_iff.1 h
  simp only [Prod.mk.injEq] at he
  obtain ⟨rfl, rfl, rfl⟩ := he
  exact ⟨t, ht, rfl, rfl, rfl⟩

/-- **A walk proves order**: the box it finds carries one of the targets, and is the start
stepped forward exactly as many times as the walk reports, within its limit. -/
theorem walk_target (hc : Counts next counter) {targets : List ℕ} {start : I} {limit keep : ℕ}
    {b : I} {skipped : List I} {steps : ℕ}
    (h : walk next counter targets start limit keep = some (b, skipped, steps)) :
    counter b ∈ targets ∧ next^[steps] start = b ∧ steps < limit ∧
      (0 < steps → Before next start b) := by
  obtain ⟨t, ht, rfl, rfl, -⟩ := walk_some h
  have hmem := List.max?_mem ht
  simp only [List.mem_filter, Bool.and_eq_true, decide_eq_true_eq] at hmem
  obtain ⟨hmem, hge, hlt⟩ := hmem
  refine ⟨?_, rfl, by omega, fun hpos => ⟨_, hpos, rfl⟩⟩
  rw [counter_iterate hc]
  convert hmem using 1; omega

/-- The indexes a walk keeps are the last `keep` before the box it finds, in the order a reader
stepping forward would pass them. -/
theorem walk_skipped {targets : List ℕ} {start : I} {limit keep : ℕ} {b : I} {skipped : List I}
    {steps : ℕ} (h : walk next counter targets start limit keep = some (b, skipped, steps)) :
    skipped = (stepsFrom next start steps).drop (if keep = 0 then 0 else steps - keep) := by
  obtain ⟨-, -, -, -, rfl⟩ := walk_some h
  rfl

/-- **A walk goes to the furthest target**: none lies between it and the walk's limit. -/
theorem walk_furthest (hc : Counts next counter) {targets : List ℕ} {start : I} {limit keep : ℕ}
    {b : I} {skipped : List I} {steps : ℕ}
    (h : walk next counter targets start limit keep = some (b, skipped, steps)) :
    ∀ j, steps < j → j < limit → counter (next^[j] start) ∉ targets := by
  obtain ⟨t, ht, rfl, -, -⟩ := walk_some h
  have hmem := List.max?_mem ht
  simp only [List.mem_filter, Bool.and_eq_true, decide_eq_true_eq] at hmem
  intro j hj hjl hin
  rw [counter_iterate hc] at hin
  have := le_of_max ht (b := counter start + j) (by simp [hin]; omega)
  omega

/-- **A walk that finds nothing has nothing to find** within its limit. -/
theorem walk_none (hc : Counts next counter) {targets : List ℕ} {start : I} {limit keep : ℕ}
    (h : walk next counter targets start limit keep = none) :
    ∀ j, j < limit → counter (next^[j] start) ∉ targets := by
  unfold walk at h
  rw [Option.map_eq_none_iff, List.max?_eq_none_iff] at h
  intro j hj hin
  rw [counter_iterate hc] at hin
  have : counter start + j ∈ targets.filter fun t => counter start ≤ t && t < counter start + limit := by
    simp [hin]; omega
  simp [h] at this

/-! ## Naming a box by `Idx64` finds the box its whole index names -/

/-- `b` is a box of the stream that begins at `s0`. -/
def OnStream (next : I → I) (s0 b : I) : Prop := ∃ n, next^[n] s0 = b

/-- On one stream, two boxes with the same `Idx64` are the same box. -/
theorem eq_of_counter_eq (hc : Counts next counter) {s0 a b : I} (ha : OnStream next s0 a)
    (hb : OnStream next s0 b) (h : counter a = counter b) : a = b := by
  obtain ⟨m, rfl⟩ := ha
  obtain ⟨n, rfl⟩ := hb
  rw [counter_iterate hc, counter_iterate hc] at h
  rw [show m = n by omega]

/-- Two lists with the same members have the same greatest. -/
theorem max?_congr {l₁ l₂ : List ℕ} (h : ∀ x, x ∈ l₁ ↔ x ∈ l₂) : l₁.max? = l₂.max? := by
  cases h₁ : l₁.max? with
  | none =>
    rw [List.max?_eq_none_iff] at h₁; subst h₁
    symm; rw [List.max?_eq_none_iff, List.eq_nil_iff_forall_not_mem]
    intro x hx; simpa using (h x).2 hx
  | some a =>
    have ha := (h a).1 (List.max?_mem h₁)
    cases hb : l₂.max? with
    | none => rw [List.max?_eq_none_iff] at hb; simp [hb] at ha
    | some b =>
    congr 1
    have hab := le_of_max hb ha
    have hba := le_of_max h₁ ((h b).2 (List.max?_mem hb))
    rw [show a = b by omega]

theorem max?_map_sub {l : List ℕ} {c : ℕ} (h : ∀ x ∈ l, c ≤ x) :
    (l.map (· - c)).max? = l.max?.map (· - c) := by
  cases hm : l.max? with
  | none => rw [List.max?_eq_none_iff] at hm; simp [hm]
  | some t =>
    rw [Option.map_some, List.max?_eq_some_iff]
    refine ⟨List.mem_map_of_mem (List.max?_mem hm), ?_⟩
    intro x hx
    obtain ⟨y, hy, rfl⟩ := List.mem_map.1 hx
    have := le_of_max hm hy
    have := h y hy
    omega

/-- **The compact acknowledgement names the same box.** When every acknowledged box is on the
reader's stream, which `start` is on, the walk by `Idx64` finds the same box, keeps the same
indexes, and reports the same distance as the walk comparing whole indexes. -/
theorem walk_eq_walkBoxes [DecidableEq I] (hc : Counts next counter) {s0 start : I}
    (hstart : OnStream next s0 start) {boxes : List I} (hon : ∀ b ∈ boxes, OnStream next s0 b)
    (limit keep : ℕ) :
    walk next counter (boxes.map counter) start limit keep = walkBoxes next boxes start limit keep := by
  obtain ⟨k, rfl⟩ := hstart
  set here := counter (next^[k] s0) with hhere
  set met := (boxes.map counter).filter fun t => here ≤ t && t < here + limit with hmet
  have honj : ∀ j, OnStream next s0 (next^[j] (next^[k] s0)) :=
    fun j => ⟨j + k, Function.iterate_add_apply next j k s0⟩
  have key : ∀ j, j ∈ met.map (· - here) ↔
      j ∈ (List.range limit).filter fun j => next^[j] (next^[k] s0) ∈ boxes := by
    intro j
    rw [List.mem_map, List.mem_filter, List.mem_range, decide_eq_true_eq]
    constructor
    · rintro ⟨t, ht, rfl⟩
      rw [hmet, List.mem_filter] at ht
      obtain ⟨ht, hr⟩ := ht
      simp only [Bool.and_eq_true, decide_eq_true_eq] at hr
      obtain ⟨b, hb, rfl⟩ := List.mem_map.1 ht
      refine ⟨by omega, ?_⟩
      have heq : next^[counter b - here] (next^[k] s0) = b := by
        apply eq_of_counter_eq hc (honj _) (hon b hb)
        rw [counter_iterate hc]; omega
      rwa [heq]
    · rintro ⟨hj, hb⟩
      refine ⟨counter (next^[j] (next^[k] s0)), ?_, ?_⟩
      · rw [hmet, List.mem_filter]
        refine ⟨List.mem_map_of_mem hb, ?_⟩
        simp only [Bool.and_eq_true, decide_eq_true_eq]
        rw [counter_iterate hc]; omega
      · rw [counter_iterate hc]; omega
  have hge : ∀ x ∈ met, here ≤ x := by
    intro x hx
    rw [hmet, List.mem_filter] at hx
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hx
    exact hx.2.1
  have hsteps : met.max?.map (· - here) =
      ((List.range limit).filter fun j => next^[j] (next^[k] s0) ∈ boxes).max? := by
    rw [← max?_map_sub hge, max?_congr key]
  unfold walk walkBoxes
  rw [← hhere, ← hmet, ← hsteps, Option.map_map]
  rfl

end CryptWalker.GroupChat.ReaderScan

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Logic.Function.Iterate
import Mathlib.Data.List.Basic

/-! # The walk to an acknowledged box

Indexes are opaque and advance only by `next`, so `b` comes after `a` exactly when stepping
forward from `a` reaches `b`. A reader finds an acknowledged box by walking to it. -/

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

/-- The target a walk finds is the start stepped forward by the reported step count, within the
limit. -/
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

/-- No target lies between the one a walk finds and the walk's limit. -/
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

end CryptWalker.GroupChat.ReaderScan

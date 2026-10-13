/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Tactic
import CryptWalker.GroupChat.Member.Dict

/-! # Lookups in an insertion-ordered map -/

namespace CryptWalker.GroupChat.Member.Dict

variable {K V : Type} [DecidableEq K]

theorem get?_mk_cons (k' : K) (v' : V) (ps : List (K × V)) (k : K) :
    (⟨(k', v') :: ps⟩ : Dict K V).get? k = if k' = k then some v' else (⟨ps⟩ : Dict K V).get? k := by
  simp only [get?, List.find?_cons]
  split_ifs <;> simp_all

@[simp] theorem get?_mk_nil (k : K) : (⟨[]⟩ : Dict K V).get? k = none := rfl

theorem get?_eq_some {d : Dict K V} {k : K} {v : V} (h : d.get? k = some v) : (k, v) ∈ d.pairs := by
  obtain ⟨ps⟩ := d
  induction ps with
  | nil => simp at h
  | cons p ps ih =>
    obtain ⟨k', v'⟩ := p
    rw [get?_mk_cons] at h
    split_ifs at h with hk
    · cases h; subst hk; exact List.mem_cons_self
    · exact List.mem_cons_of_mem _ (ih h)

theorem contains_iff {d : Dict K V} {k : K} : d.contains k = true ↔ ∃ v, (k, v) ∈ d.pairs := by
  obtain ⟨ps⟩ := d
  unfold contains
  induction ps with
  | nil => simp
  | cons p ps ih =>
    obtain ⟨k', v'⟩ := p
    rw [get?_mk_cons]
    split_ifs with hk
    · subst hk; simp
    · rw [ih]; simp [Ne.symm hk]

theorem get?_replace (ps : List (K × V)) (k k' : K) (v : V) :
    (⟨ps.map fun p => if p.1 = k then (k, v) else p⟩ : Dict K V).get? k' =
      if k = k' then ((⟨ps⟩ : Dict K V).get? k).map fun _ => v else (⟨ps⟩ : Dict K V).get? k' := by
  induction ps with
  | nil => split_ifs <;> rfl
  | cons p ps ih =>
    obtain ⟨k1, v1⟩ := p
    simp only [List.map_cons]
    by_cases h1 : k1 = k
    · subst h1
      simp only [if_true]
      rw [get?_mk_cons, get?_mk_cons, ih]
      by_cases h2 : k1 = k'
      · simp [h2]
      · simp only [h2, if_false, if_true, Option.map_some]
        rw [get?_mk_cons, if_neg h2]
    · simp only [h1, if_false]
      rw [get?_mk_cons, ih, get?_mk_cons, get?_mk_cons]
      by_cases h2 : k = k'
      · subst h2; simp [h1]
      · simp [h2]

theorem get?_append (ps : List (K × V)) (k k' : K) (v : V) :
    (⟨ps ++ [(k, v)]⟩ : Dict K V).get? k' =
      ((⟨ps⟩ : Dict K V).get? k').or (if k = k' then some v else none) := by
  induction ps with
  | nil => simp [get?_mk_cons]
  | cons p ps ih =>
    obtain ⟨k1, v1⟩ := p
    rw [List.cons_append, get?_mk_cons, ih, get?_mk_cons]
    split_ifs <;> simp

@[simp] theorem get?_set_self (d : Dict K V) (k : K) (v : V) : (d.set k v).get? k = some v := by
  obtain ⟨ps⟩ := d
  unfold set
  split
  · next hc =>
    rw [get?_replace, if_pos rfl]
    unfold contains at hc
    obtain ⟨w, hw⟩ := Option.isSome_iff_exists.1 hc
    rw [hw]; rfl
  · next hc =>
    rw [get?_append]
    unfold contains at hc
    simp only [Bool.not_eq_true, Option.isSome_eq_false_iff, Option.isNone_iff_eq_none] at hc
    simp [hc]

@[simp] theorem get?_set_ne (d : Dict K V) {k k' : K} (v : V) (h : k ≠ k') :
    (d.set k v).get? k' = d.get? k' := by
  obtain ⟨ps⟩ := d
  unfold set
  split
  · rw [get?_replace, if_neg h]
  · rw [get?_append, if_neg h]; simp

@[simp] theorem get?_mapValues {W : Type} (d : Dict K V) (f : V → W) (k : K) :
    (d.mapValues f).get? k = (d.get? k).map f := by
  obtain ⟨ps⟩ := d
  unfold mapValues
  induction ps with
  | nil => rfl
  | cons p ps ih =>
    obtain ⟨k1, v1⟩ := p
    simp only [List.map_cons]
    rw [get?_mk_cons, get?_mk_cons]
    split_ifs
    · rfl
    · exact ih

omit [DecidableEq K] in
theorem mem_filter {d : Dict K V} {p : K → V → Bool} {e : K × V} :
    e ∈ (d.filter p).pairs ↔ e ∈ d.pairs ∧ p e.1 e.2 = true := by
  simp [filter]

omit [DecidableEq K] in
theorem mem_mapValues {W : Type} {d : Dict K V} {f : V → W} {e : K × W} :
    e ∈ (d.mapValues f).pairs ↔ ∃ v, (e.1, v) ∈ d.pairs ∧ e.2 = f v := by
  obtain ⟨k, w⟩ := e
  unfold mapValues
  simp only [List.mem_map, Prod.mk.injEq]
  constructor
  · rintro ⟨⟨k', v⟩, hm, rfl, rfl⟩; exact ⟨v, hm, rfl⟩
  · rintro ⟨v, hm, rfl⟩; exact ⟨(k, v), hm, rfl, rfl⟩

omit [DecidableEq K] in
theorem mem_mapWithKey {W : Type} {d : Dict K V} {f : K → V → W} {e : K × W} :
    e ∈ (d.mapWithKey f).pairs ↔ ∃ v, (e.1, v) ∈ d.pairs ∧ e.2 = f e.1 v := by
  obtain ⟨k, w⟩ := e
  unfold mapWithKey
  simp only [List.mem_map, Prod.mk.injEq]
  constructor
  · rintro ⟨⟨k', v⟩, hm, rfl, rfl⟩; exact ⟨v, hm, rfl⟩
  · rintro ⟨v, hm, rfl⟩; exact ⟨(k, v), hm, rfl, rfl⟩

theorem mem_set {d : Dict K V} {k : K} {v : V} {e : K × V} (h : e ∈ (d.set k v).pairs) :
    e = (k, v) ∨ e ∈ d.pairs := by
  unfold set at h
  split_ifs at h
  · obtain ⟨p, hp, rfl⟩ := List.mem_map.1 h
    split_ifs
    · exact Or.inl rfl
    · exact Or.inr hp
  · rcases List.mem_append.1 h with h | h
    · exact Or.inr h
    · exact Or.inl (List.mem_singleton.1 h)

theorem get?_setDefault_self (d : Dict K V) (k : K) (v : V) :
    (d.setDefault k v).get? k = some ((d.get? k).getD v) := by
  unfold setDefault contains
  cases h : d.get? k <;> simp [h]

theorem get?_setDefault_ne (d : Dict K V) {k k' : K} (v : V) (h : k ≠ k') :
    (d.setDefault k v).get? k' = d.get? k' := by
  unfold setDefault
  split_ifs <;> simp [h]

theorem get?_erase (d : Dict K V) (k k' : K) :
    (d.erase k).get? k' = if k = k' then none else d.get? k' := by
  obtain ⟨ps⟩ := d
  unfold erase
  induction ps with
  | nil => split_ifs <;> rfl
  | cons p ps ih =>
    obtain ⟨k1, v1⟩ := p
    simp only [List.filter_cons]
    by_cases h1 : k1 = k
    · subst h1
      simp only [ne_eq, not_true_eq_false, decide_false, Bool.false_eq_true, if_false]
      rw [ih, get?_mk_cons]
      by_cases h2 : k1 = k' <;> simp [h2]
    · simp only [ne_eq, h1, not_false_eq_true, decide_true, if_true]
      rw [get?_mk_cons, ih, get?_mk_cons]
      by_cases h2 : k = k'
      · subst h2; simp [h1]
      · simp [h2]

theorem get?_modify (d : Dict K V) (k k' : K) (f : V → V) :
    (d.modify k f).get? k' = if k = k' then (d.get? k).map f else d.get? k' := by
  unfold modify
  cases h : d.get? k with
  | none => split_ifs with hk <;> simp_all
  | some v =>
    simp only
    by_cases hk : k = k'
    · subst hk; simp
    · simp [hk]

end CryptWalker.GroupChat.Member.Dict

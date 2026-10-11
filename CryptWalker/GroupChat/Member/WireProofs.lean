/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Tactic
import CryptWalker.GroupChat.Member.Wire

/-! # The Numbers and IntroducedAt encodings round trip

See "Numbers and IntroducedAt wire format" in the group chat spec.

* `decodeNumbers_encodeNumbers`: whatever a `Numbers` field can carry decodes back to itself:
  one-byte indexes in strictly ascending order, and either the single entry for the
  `Introduction` the message itself carries, or entries each naming an `Introduction` by a
  one-byte introducer index and a 104-byte box.
* `decodeIntroducedAt_encodeIntroducedAt`: likewise for `IntroducedAt`. -/

namespace CryptWalker.GroupChat.Member

/-- What the `Numbers` encoding can carry. -/
def NumbersWF (ns : Numbers) : Prop :=
  ascending (ns.map (·.1)) = true ∧ (∀ e ∈ ns, e.1 < 256) ∧
    ((∃ k, ns = [(k, none)]) ∨
      ∀ e ∈ ns, ∃ r, e.2 = some r ∧ r.introducer < 256 ∧ r.index.size = indexSize)

theorem toUInt8_toNat {k : Nat} (h : k < 256) : k.toUInt8.toNat = k := by
  simp [Nat.toUInt8]; omega

/-- One entry naming an `Introduction`, as the encoding writes it. -/
def entryBytes (e : Nat × Option IntroRef) : List UInt8 :=
  match e with
  | (k, some r) => k.toUInt8 :: r.introducer.toUInt8 :: r.index.data.toList
  | (_, none) => []

theorem entries_flatMap {α : Type} (g : α → List UInt8) :
    ∀ l : List α, (∀ x ∈ l, (g x).length = entrySize) →
      entries l.length (l.flatMap g) = l.map g
  | [], _ => rfl
  | x :: xs, h => by
    have hx := h x List.mem_cons_self
    simp only [List.length_cons, List.flatMap_cons, entries, List.map_cons]
    rw [List.take_left' hx, List.drop_left' hx,
      entries_flatMap g xs fun y hy => h y (List.mem_cons_of_mem _ hy)]

theorem encodeNumbers_of_all : ∀ {ns : Numbers}, (∀ e ∈ ns, ∃ r, e.2 = some r) →
    encodeNumbers ns = ns.flatMap entryBytes
  | [], _ => rfl
  | [(_, some _)], _ => by simp [encodeNumbers, entryBytes]
  | [(_, none)], h => by obtain ⟨r, hr⟩ := h _ List.mem_cons_self; simp at hr
  | _ :: _ :: _, _ => by
    simp only [encodeNumbers]
    congr 1

theorem decodeNumbers_encodeNumbers {ns : Numbers} (h : NumbersWF ns) :
    decodeNumbers (encodeNumbers ns) = ns := by
  obtain ⟨hasc, hk, hshape⟩ := h
  rcases hshape with ⟨k, rfl⟩ | hall
  · have : k < 256 := hk _ List.mem_cons_self
    simp [encodeNumbers, decodeNumbers, toUInt8_toNat this]
  · rw [encodeNumbers_of_all fun e he => (hall e he).imp fun r h => h.1]
    have hlen : ∀ e ∈ ns, (entryBytes e).length = entrySize := by
      intro e he
      obtain ⟨r, hr, -, hsize⟩ := hall e he
      obtain ⟨k, _⟩ := e
      simp only at hr
      subst hr
      have h104 : r.index.data.size = 104 := hsize
      simp [entryBytes, entrySize, indexSize, h104]
    have htotal : (ns.flatMap entryBytes).length = ns.length * entrySize := by
      rw [List.length_flatMap, List.map_congr_left hlen]
      simp [List.map_const', List.sum_replicate, mul_comm]
    have hdec : (entries ns.length (ns.flatMap entryBytes)).map (fun e =>
        ((e.getD 0 0).toNat, some (⟨(e.getD 1 0).toNat, ⟨(e.drop 2).toArray⟩⟩ : IntroRef))) = ns := by
      rw [entries_flatMap entryBytes ns hlen, List.map_map]
      conv_rhs => rw [← List.map_id ns]
      apply List.map_congr_left
      intro e he
      obtain ⟨r, hr, hi, -⟩ := hall e he
      obtain ⟨k, _⟩ := e
      simp only at hr
      subst hr
      have hk' : k < 256 := hk _ he
      simp [entryBytes, toUInt8_toNat hk', toUInt8_toNat hi]
    unfold decodeNumbers
    split
    · next b heq =>
      have hl := congrArg List.length heq
      simp only [htotal, List.length_singleton, entrySize, indexSize] at hl
      omega
    · have hmod : (ns.flatMap entryBytes).length % entrySize = 0 := by
        rw [htotal]; simp
      have hdiv : (ns.flatMap entryBytes).length / entrySize = ns.length := by
        rw [htotal]; simp [entrySize, indexSize]
      simp only [hmod, ne_eq, not_true_eq_false, if_false, hdiv, hdec, hasc, if_true]

theorem decodeIntroducedAt_encodeIntroducedAt {r : IntroRef} (hi : r.introducer < 256)
    (hs : r.index.size = indexSize) : decodeIntroducedAt (encodeIntroducedAt r) = some r := by
  have hl : r.index.data.toList.length = indexSize := by rw [Array.length_toList]; exact hs
  unfold encodeIntroducedAt decodeIntroducedAt
  dsimp only
  rw [if_pos (by simp only [List.length_cons, hl]; omega)]
  simp [toUInt8_toNat hi]

end CryptWalker.GroupChat.Member

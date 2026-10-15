/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Tactic
import CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member.Wire

/-! # The Numbers and IntroducedAt encodings round trip

See "Numbers and IntroducedAt wire format" in the group chat spec. -/

namespace CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member

/-- Members at consecutive indexes from `first`, each named by its prefix. -/
def consecutive (first : Nat) (ps : List ByteArray) : Numbers :=
  ps.zipIdx.map fun (p, n) => (first + n, some p)

/-- What the `Numbers` encoding can carry. -/
def NumbersWF (ns : Numbers) : Prop :=
  (∃ k, k < 256 ∧ ns = [(k, none)]) ∨
    ∃ first ps, ns = consecutive first ps ∧ ps ≠ [] ∧ (∀ p ∈ ps, p.size = prefixSize) ∧
      ps.Nodup ∧ first + ps.length ≤ 256

theorem toUInt8_toNat {k : Nat} (h : k < 256) : k.toUInt8.toNat = k := by
  simp [Nat.toUInt8]; omega

theorem prefixes_flatMap :
    ∀ ps : List ByteArray, (∀ p ∈ ps, p.size = prefixSize) →
      prefixes ps.length (ps.flatMap (·.data.toList)) = ps.map (·.data.toList)
  | [], _ => rfl
  | p :: ps, h => by
    have hp : p.data.toList.length = prefixSize := by
      rw [Array.length_toList]; exact h p List.mem_cons_self
    simp only [List.length_cons, List.flatMap_cons, prefixes, List.map_cons]
    rw [List.take_left' hp, List.drop_left' hp,
      prefixes_flatMap ps fun q hq => h q (List.mem_cons_of_mem _ hq)]

theorem data_toList_injective : Function.Injective fun p : ByteArray => p.data.toList := by
  intro a b h
  cases a; cases b
  simp only [ByteArray.mk.injEq]
  exact Array.ext' h

theorem encodeNumbers_some (k : Nat) (p : ByteArray) (rest : Numbers) :
    encodeNumbers ((k, some p) :: rest) = k.toUInt8 :: ((some p :: rest.map (·.2)).flatMap fun
      | some p => p.data.toList
      | none => []) := by
  cases rest <;> rfl

theorem decodeNumbers_encodeNumbers {ns : Numbers} (h : NumbersWF ns) :
    decodeNumbers (encodeNumbers ns) = ns := by
  rcases h with ⟨k, hk, rfl⟩ | ⟨first, ps, rfl, hne, hsize, hnodup, hlen⟩
  · simp [encodeNumbers, decodeNumbers, toUInt8_toNat hk]
  obtain ⟨p0, rest, rfl⟩ := List.exists_cons_of_ne_nil hne
  have hfirst : first < 256 := by simp at hlen; omega
  have hmap : ∀ (l : List ByteArray) (n : Nat),
      ((l.zipIdx n).map fun x => (first + x.2, some x.1)).map (·.2) = l.map some := by
    intro l; induction l with
    | nil => intro n; rfl
    | cons q qs ih => intro n; simp [List.zipIdx_cons, ih]
  have henc : encodeNumbers (consecutive first (p0 :: rest)) =
      first.toUInt8 :: (p0 :: rest).flatMap (·.data.toList) := by
    simp only [consecutive, List.zipIdx_cons, List.map_cons, Nat.add_zero]
    rw [encodeNumbers_some, hmap]
    simp [List.flatMap_map]
  rw [henc]
  have hL : ((p0 :: rest).flatMap (·.data.toList)).length = prefixSize * (p0 :: rest).length := by
    rw [List.length_flatMap, List.map_congr_left (fun p hp => (by
      rw [Array.length_toList]; exact hsize p hp : p.data.toList.length = prefixSize))]
    simp [List.map_const', List.sum_replicate]; ring
  have hpos : 0 < ((p0 :: rest).flatMap (·.data.toList)).length := by
    rw [hL]; simp [prefixSize]
  unfold decodeNumbers
  split
  · next k heq =>
    have := congrArg List.length heq
    simp only [List.length_cons, List.length_nil] at this
    omega
  · next heq => simp at heq
  · next f rs heq =>
    simp only [List.cons.injEq] at heq
    obtain ⟨rfl, rfl⟩ := heq
    have hdiv : ((p0 :: rest).flatMap (·.data.toList)).length / prefixSize = (p0 :: rest).length := by
      rw [hL]; simp [prefixSize]
    have hmod : ((p0 :: rest).flatMap (·.data.toList)).length % prefixSize = 0 := by
      rw [hL]; simp
    rw [if_neg (by omega), hdiv, prefixes_flatMap _ hsize, toUInt8_toNat hfirst]
    rw [if_neg (by
      simp only [List.length_map, rosterMax, not_or, not_lt, not_not]
      exact ⟨by omega, hnodup.map data_toList_injective⟩)]
    simp only [consecutive, List.zipIdx_map, List.map_map]
    apply List.map_congr_left
    intro e _
    simp

theorem decodeIntroducedAt_encodeIntroducedAt {r : IntroRef} (hi : r.introducer < 256)
    (hs : r.index.size = indexSize) : decodeIntroducedAt (encodeIntroducedAt r) = some r := by
  have hl : r.index.data.toList.length = indexSize := by rw [Array.length_toList]; exact hs
  unfold encodeIntroducedAt decodeIntroducedAt
  dsimp only
  rw [if_pos (by simp only [List.length_cons, hl]; omega)]
  simp [toUInt8_toNat hi]

end CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member

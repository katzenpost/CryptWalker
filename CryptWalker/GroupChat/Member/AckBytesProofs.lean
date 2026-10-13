/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.GroupChat.AckCodec
import CryptWalker.GroupChat.Member.AckBytes

/-! # The byte codec is the proved one

`AckBytes` computes what `AckCodec` defines, reading with the spec's (not strict) parser, so
`AckCodec`'s theorems hold of the codec a client runs. -/

namespace CryptWalker.GroupChat.Member.AckBytes

open CryptWalker.GroupChat

theorem foldr_pow (l : List ℕ) : l.foldr (fun k s => 2 ^ k + s) 0 = (l.map (2 ^ ·)).sum := by
  induction l with
  | nil => rfl
  | cons _ _ ih => simp [ih]

theorem bitmapByte_eq (idx : List ℕ) (j : ℕ) :
    bitmapByte idx j = AckCodec.bitmapByte idx j := by
  unfold bitmapByte AckCodec.bitmapByte AckCodec.byteBits
  rw [foldr_pow, ← List.sum_toFinset _ (List.nodup_range.filter _)]
  apply Finset.sum_congr _ (fun _ _ => rfl)
  ext k
  simp only [List.mem_toFinset, List.mem_filter, List.mem_range, marks, List.any_eq_true,
    Bool.and_eq_true, decide_eq_true_eq, List.mem_map]
  constructor
  · rintro ⟨-, i, hi, hj, rfl⟩
    exact ⟨i, ⟨hi, by simpa using hj⟩, rfl⟩
  · rintro ⟨i, ⟨hi, hj⟩, rfl⟩
    exact ⟨by omega, i, hi, by simpa using hj, rfl⟩

theorem bitmap_eq (idx : List ℕ) (w : ℕ) : bitmap idx w = AckCodec.bitmap idx w := by
  simp [bitmap, AckCodec.bitmap, bitmapByte_eq]

theorem nameMembers_eq (idx : List ℕ) : nameMembers idx = AckCodec.nameMembers idx := by
  unfold nameMembers AckCodec.nameMembers
  cases hl : idx.getLast? with
  | none => rfl
  | some last =>
    simp only [width, AckCodec.width, bitmap_eq]
    congr

theorem ascending_iff : ∀ l : List ℕ, ascending l = true ↔ l.IsChain (· < ·)
  | [] => by simp [ascending]
  | [_] => by simp [ascending]
  | a :: b :: rest => by
    simp [ascending, List.isChain_cons_cons, ascending_iff (b :: rest)]

theorem setBits_eq (naming : List ℕ) : setBits naming = AckCodec.setBits naming := rfl

theorem readMembers_eq (naming : List ℕ) (count : ℕ) :
    readMembers naming count = AckCodec.readMembers false naming count := by
  unfold readMembers AckCodec.readMembers
  have h := ascending_iff naming
  simp only [setBits_eq, maxNaming, AckCodec.maxNaming, Bool.false_eq_true, false_implies,
    and_true]
  by_cases hc : naming.IsChain (· < ·)
  · simp only [h.2 hc, hc, if_true]
    congr
  · have : ascending naming = false := by
      cases hb : ascending naming
      · rfl
      · exact absurd (h.1 hb) hc
    simp only [this, hc, Bool.false_eq_true, if_false]
    congr

theorem chunks_eq (v : ℕ) : ∀ (l : List ℕ) (n : ℕ), chunks v l n = AckCodec.chunks v l n
  | _, 0 => rfl
  | l, n + 1 => by simp [chunks, AckCodec.chunks, chunks_eq v (l.drop v) n]

theorem le_eq : ∀ (k n : ℕ), le k n = AckCodec.le k n
  | 0, _ => rfl
  | k + 1, n => by simp [le, AckCodec.le, le_eq k]

theorem fromLE_eq (l : List ℕ) : fromLE l = AckCodec.fromLE l := rfl

theorem encodeValues_eq (acks : List (ℕ × List ℕ)) :
    encodeValues acks = AckCodec.encode acks := by
  simp [encodeValues, AckCodec.encode, encodeUncounted, AckCodec.encodeUncounted, nameMembers_eq]

theorem decodeValues_eq (v : ℕ) (field : List ℕ) :
    decodeValues v field = AckCodec.decode false v field := by
  cases field with
  | nil => rfl
  | cons c rest => simp [decodeValues, AckCodec.decode, readMembers_eq, chunks_eq]

theorem encodeNat_eq (acks : List (ℕ × ℕ)) : encodeNat acks = AckCodec.encodeIdx64 acks := by
  simp [encodeNat, AckCodec.encodeIdx64, encodeValues_eq, le_eq, idxSize, AckCodec.idxSize]

theorem decodeNat_eq (field : List ℕ) : decodeNat field = AckCodec.decodeIdx64 false field := by
  simp [decodeNat, AckCodec.decodeIdx64, decodeValues_eq, fromLE_eq, idxSize, AckCodec.idxSize]

/-- Decoding undoes encoding, for numbers. -/
theorem decodeNat_encodeNat {acks : List (ℕ × ℕ)} (h : AckCodec.WFIdx64 acks) :
    decodeNat (encodeNat acks) = some acks := by
  rw [decodeNat_eq, encodeNat_eq]
  exact AckCodec.decodeIdx64_encodeIdx64 false h

end CryptWalker.GroupChat.Member.AckBytes

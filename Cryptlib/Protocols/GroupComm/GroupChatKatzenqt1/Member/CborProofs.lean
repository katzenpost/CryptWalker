/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Tactic
import Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.Cbor

/-! # Reading back what is written

Each item written by `Cbor` reads back as itself, followed by whatever came after it. -/

namespace Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.Cbor

theorem foldl_be_aux : ∀ (k n acc : ℕ), n < 256 ^ k →
    (be k n).foldl (fun n b => n * 256 + b.toNat) acc = acc * 256 ^ k + n
  | 0, n, acc, h => by simp at h; simp [be, h]
  | k + 1, n, acc, h => by
    have h' : n / 256 < 256 ^ k := by rw [pow_succ] at h; omega
    simp only [be, List.foldl_append, List.foldl_cons, List.foldl_nil]
    rw [foldl_be_aux k (n / 256) acc h']
    have : (n % 256).toUInt8.toNat = n % 256 := by simp
    rw [this, pow_succ]; ring_nf; omega

theorem fromBE_be (k n : ℕ) (h : n < 256 ^ k) : fromBE (be k n) = n := by
  simpa [fromBE] using foldl_be_aux k n 0 h

theorem length_be : ∀ k n, (be k n).length = k
  | 0, _ => rfl
  | k + 1, n => by simp [be, length_be k]

theorem toNat_byte {x : ℕ} (h : x < 256) : x.toUInt8.toNat = x := by simp; omega

theorem readHeader_long (b : ℕ) (k : ℕ) (m n : ℕ) (rest : List UInt8) (hb : b = m * 32 + 24 + k)
    (hk : k < 4) (hm : m < 8) (hn : n < 256 ^ (2 ^ k)) :
    readHeader (b.toUInt8 :: (be (2 ^ k) n ++ rest)) = some (m, n, rest) := by
  have hb' : b.toUInt8.toNat = b := toNat_byte (by omega)
  simp only [readHeader, hb']
  have h1 : ¬ b % 32 < 24 := by omega
  have h2 : b % 32 < 28 := by omega
  have h3 : b % 32 - 24 = k := by omega
  have h4 : b / 32 = m := by omega
  simp only [h1, h2, h3, h4, if_false, if_true, List.length_append, length_be]
  simp [List.take_left' (length_be _ _), List.drop_left' (length_be _ _), fromBE_be _ _ hn]

theorem readHeader_header (m n : ℕ) (rest : List UInt8) (hm : m < 8) (hn : n < 2 ^ 64) :
    readHeader (header m n ++ rest) = some (m, n, rest) := by
  unfold header
  split_ifs with h0 h1 h2 h3
  · have hb : (m * 32 + n).toUInt8.toNat = m * 32 + n := toNat_byte (by omega)
    simp only [List.singleton_append, readHeader, hb]
    have : (m * 32 + n) % 32 = n := by omega
    simp [this, h0]; omega
  · simpa using readHeader_long (m * 32 + 24) 0 m n rest (by omega) (by omega) hm (by simpa using h1)
  · simpa using readHeader_long (m * 32 + 25) 1 m n rest (by omega) (by omega) hm (by simpa using h2)
  · simpa using readHeader_long (m * 32 + 26) 2 m n rest (by omega) (by omega) hm (by simpa using h3)
  · simpa using readHeader_long (m * 32 + 27) 3 m n rest (by omega) (by omega) hm (by simpa using hn)

theorem readUInt_uint (n : ℕ) (rest : List UInt8) (hn : n < 2 ^ 64) :
    readUInt (uint n ++ rest) = some (n, rest) := by
  simp [readUInt, uint, readHeader_header 0 n rest (by omega) hn]

theorem readString_header (m : ℕ) (b rest : List UInt8) (hm : m < 8) (hb : b.length < 2 ^ 64) :
    readString m (header m b.length ++ b ++ rest) = some (b, rest) := by
  rw [List.append_assoc]
  simp [readString, readHeader_header m b.length (b ++ rest) hm hb]

theorem readBytes_bytes (b rest : List UInt8) (hb : b.length < 2 ^ 64) :
    readBytes (bytes b ++ rest) = some (b, rest) := readString_header 2 b rest (by omega) hb

theorem fromUTF8_toByteArray (s : String) : String.fromUTF8? s.toByteArray = some s := by
  simp [String.fromUTF8?, s.isValidUTF8, String.fromUTF8]

theorem readText_text (s : String) (rest : List UInt8) (hs : s.utf8ByteSize < 2 ^ 64) :
    readText (text s ++ rest) = some (s, rest) := by
  have hl : s.toByteArray.data.toList.length = s.utf8ByteSize := by
    simp
  unfold text readText
  rw [← hl, readString_header 3 _ rest (by omega) (by rw [hl]; exact hs)]
  simp only [Option.bind_eq_bind, Option.bind_some, Array.toArray_toList]
  rw [show ({ data := s.toByteArray.data } : ByteArray) = s.toByteArray from rfl,
    fromUTF8_toByteArray]
  rfl

end Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.Cbor

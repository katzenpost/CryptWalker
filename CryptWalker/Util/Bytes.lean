/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Util.Bytes

/-! # Splitting and rejoining byte strings

`Util.Combine` does this for `Vector UInt8 n`, where the widths are type-level and `splitL`/
`splitR` need no hypotheses. Byte *strings* are the other half of the same story: an AEAD
ciphertext is `body ‖ tag` where only the tag has a statically known width, so the split has to
be stated with `extract` and its side conditions discharged by hand.

These three lemmas are all that a length-prefixed or tag-suffixed format needs: parse the two
halves of a concatenation, and rejoin a split. They are the reason `AESGCMSIV`'s correctness
proofs are about cryptography rather than about `Array.extract`.
-/

/-- A fixed-width vector as a byte string. -/
def ofVector {n : Nat} (v : Vector UInt8 n) : ByteArray := ⟨v.toArray⟩

@[simp] theorem size_ofVector {n : Nat} (v : Vector UInt8 n) : (ofVector v).size = n := by
  simp [ofVector, ByteArray.size]

/-- The reverse of `ofVector`: reinterpret a `ByteArray` as a fixed-width vector, total via
`ByteArray.get!`'s default-on-out-of-range behavior (never exercised by a caller that already
knows its input is exactly `n` bytes). -/
def toVecN (n : Nat) (a : ByteArray) : Vector UInt8 n := Vector.ofFn fun i : Fin n => a.get! i.val

/-- `toVecN` undoes `ofVector`: reinterpreting an already-fixed-width vector's own bytes at that
width recovers it exactly. Bridges an encode/decode round trip stated over `Vector UInt8 n` into
one stated over a raw `ByteArray`. -/
@[simp] theorem toVecN_ofVector {n : Nat} (v : Vector UInt8 n) : toVecN n (ofVector v) = v := by
  apply Vector.ext
  intro i hi
  simp only [toVecN, Vector.getElem_ofFn]
  show (ofVector v).get! i = v[i]
  show v.toArray[i]! = v[i]
  simp [getElem!_pos, hi]

/-- `ofVector` undoes `toVecN`, the other direction from `toVecN_ofVector`. -/
theorem ofVector_toVecN {n : Nat} (X : ByteArray) (h : X.size = n) : ofVector (toVecN n X) = X := by
  apply ByteArray.ext_getElem
  · show (Array.ofFn (fun i : Fin n => X.get! i.val)).size = X.size
    rw [Array.size_ofFn, h]
  · intro i hi hi'
    rw [size_ofVector] at hi
    have hi2 : i < (Array.ofFn (fun i : Fin n => X.get! i.val)).size := by
      rw [Array.size_ofFn]; exact hi
    show (Array.ofFn (fun i : Fin n => X.get! i.val))[i]'hi2 = X[i]'hi'
    rw [Array.getElem_ofFn]
    obtain ⟨bs⟩ := X
    show bs[i]! = (⟨bs⟩ : ByteArray)[i]'hi'
    rw [getElem!_pos bs i hi']
    rfl

/-- The left half of a concatenation. -/
theorem extract_append_left (a b : ByteArray) : (a ++ b).extract 0 a.size = a := by
  apply ByteArray.ext_getElem
  · simp [ByteArray.size_extract, ByteArray.size_append]
  · intro i h1 h2
    rw [ByteArray.getElem_extract, ByteArray.getElem_append_left (by omega)]
    simp

/-- The right half of a concatenation. -/
theorem extract_append_right (a b : ByteArray) :
    (a ++ b).extract a.size (a.size + b.size) = b := by
  apply ByteArray.ext_getElem
  · simp [ByteArray.size_extract, ByteArray.size_append]
  · intro i h1 h2
    rw [ByteArray.getElem_extract, ByteArray.getElem_append_right (by omega)]
    simp

/-- Extracting a range that lies entirely in the left half of a concatenation only sees that
half. -/
theorem extract_append_of_le (a b : ByteArray) {lo hi : Nat} (h : hi ≤ a.size) :
    (a ++ b).extract lo hi = a.extract lo hi := by
  apply ByteArray.ext_getElem
  · simp [ByteArray.size_extract, ByteArray.size_append]; omega
  · intro i h1 h2
    rw [ByteArray.getElem_extract, ByteArray.getElem_extract,
      ByteArray.getElem_append_left (by simp [ByteArray.size_extract] at h1; omega)]

/-- Extracting from an inner offset all the way to the end of a concatenation splits into the
left half's own tail, followed by all of the right half. -/
theorem extract_append_ge (a b : ByteArray) {lo : Nat} (h : lo ≤ a.size) :
    (a ++ b).extract lo (a.size + b.size) = a.extract lo a.size ++ b := by
  have htail : (a.extract lo a.size).size = a.size - lo := by
    rw [ByteArray.size_extract]; omega
  apply ByteArray.ext_getElem
  · simp only [ByteArray.size_extract, ByteArray.size_append, htail]
    omega
  · intro i h1 h2
    rw [ByteArray.getElem_extract]
    by_cases hi : i < a.size - lo
    · have hlt : i < (a.extract lo a.size).size := by rw [htail]; omega
      have hlt2 : lo + i < a.size := by omega
      rw [ByteArray.getElem_append_left hlt2, ByteArray.getElem_append_left hlt,
        ByteArray.getElem_extract]
    · have hge : (a.extract lo a.size).size ≤ i := by rw [htail]; omega
      have hge2 : a.size ≤ lo + i := by omega
      rw [ByteArray.getElem_append_right hge2, ByteArray.getElem_append_right hge]
      congr 1
      rw [htail]
      omega

/-- Extracting a prefix that reaches past the left half of a concatenation into the right: the
whole left half, followed by however much of the right half's own start is needed. -/
theorem extract_append_le (a b : ByteArray) {m : Nat} (h : a.size ≤ m) :
    (a ++ b).extract 0 m = a ++ b.extract 0 (m - a.size) := by
  have htail : (b.extract 0 (m - a.size)).size = min (m - a.size) b.size := by
    rw [ByteArray.size_extract]; omega
  apply ByteArray.ext_getElem
  · simp only [ByteArray.size_extract, ByteArray.size_append, htail]
    omega
  · intro i h1 h2
    simp only [ByteArray.size_append] at h2
    simp only [ByteArray.getElem_extract, Nat.zero_add]
    by_cases hi : i < a.size
    · rw [ByteArray.getElem_append_left hi, ByteArray.getElem_append_left hi]
    · have hge : a.size ≤ i := by omega
      have hlt : i - a.size < (b.extract 0 (m - a.size)).size := by omega
      rw [ByteArray.getElem_append_right hge, ByteArray.getElem_append_right hge]
      simp only [ByteArray.getElem_extract, Nat.zero_add]

/-- Extracting a range that lies entirely in the right half of a concatenation only sees that
half, at the correspondingly shifted offsets. -/
theorem extract_append_of_ge (a b : ByteArray) {lo hi : Nat} (h : a.size ≤ lo) :
    (a ++ b).extract lo hi = b.extract (lo - a.size) (hi - a.size) := by
  apply ByteArray.ext_getElem
  · simp only [ByteArray.size_extract, ByteArray.size_append]
    omega
  · intro i h1 h2
    simp only [ByteArray.size_extract] at h2
    have hlt : lo - a.size + i < b.size := by omega
    have hlt2 : a.size ≤ lo + i := by omega
    simp only [ByteArray.getElem_extract, ByteArray.getElem_append_right hlt2]
    congr 1
    omega

/-- Splitting at any point and rejoining is the identity. -/
theorem append_extract (b : ByteArray) (n : Nat) (h : n ≤ b.size) :
    b.extract 0 n ++ b.extract n b.size = b := by
  have hleft : (b.extract 0 n).size = n := by
    simp [ByteArray.size_extract]; omega
  apply ByteArray.ext_getElem
  · simp
  · intro i h1 h2
    by_cases hi : i < n
    · rw [ByteArray.getElem_append_left (by omega), ByteArray.getElem_extract]
      simp
    · rw [ByteArray.getElem_append_right (by omega), ByteArray.getElem_extract]
      have hidx : n + (i - min n b.size) = i := by omega
      simp [hidx]

end CryptWalker.Util.Bytes

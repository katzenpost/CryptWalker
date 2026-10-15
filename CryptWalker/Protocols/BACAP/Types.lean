/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Ed25519_blinded
import CryptWalker.Hash.HKDF
import Std.Tactic.BVDecide

/-! # BACAP types: MessageBoxIndex, ReadCap, WriteCap (Echomix §4)

Binary layouts:
- MessageBoxIndex: uint64 LE ++ [32]byte ++ [32]byte ++ [32]byte = 104 bytes
- ReadCap: [32]byte pubkey ++ MessageBoxIndex = 136 bytes
- WriteCap: [32]byte seed ++ [32]byte pubkey ++ MessageBoxIndex = 168 bytes -/

namespace CryptWalker.Protocols.BACAP.Types

open CryptWalker.Sign.Ed25519Blinded

abbrev MessageBoxIndexSize : Nat := 104
abbrev ReadCapSize : Nat := 136
abbrev WriteCapSize : Nat := 168

/-- Ratchet state: message counter, blinding factor K_i, encryption key E_i, HKDF state H_i. -/
structure MessageBoxIndex where
  idx64             : UInt64
  curBlindingFactor : Vector UInt8 32
  curEncryptionKey  : Vector UInt8 32
  hkdfState         : Vector UInt8 32

def MessageBoxIndex.empty : MessageBoxIndex where
  idx64             := 0
  curBlindingFactor := Vector.replicate 32 0
  curEncryptionKey  := Vector.replicate 32 0
  hkdfState         := Vector.replicate 32 0

instance : Inhabited MessageBoxIndex := ⟨MessageBoxIndex.empty⟩

private def putU64LE (v : UInt64) : Vector UInt8 8 :=
  Vector.ofFn fun i : Fin 8 => (v >>> (UInt64.ofNat (8 * i.val))).toUInt8

private def getU64LE (data : Vector UInt8 8) : UInt64 :=
  let d := fun (i : Nat) => (data[i]!).toUInt64
  d 0 ||| (d 1 <<< 8) ||| (d 2 <<< 16) ||| (d 3 <<< 24) |||
  (d 4 <<< 32) ||| (d 5 <<< 40) ||| (d 6 <<< 48) ||| (d 7 <<< 56)

def marshalMessageBoxIndex (m : MessageBoxIndex) : Vector UInt8 MessageBoxIndexSize :=
  let buf : Vector UInt8 104 :=
    (putU64LE m.idx64 ++ m.curBlindingFactor ++ m.curEncryptionKey ++ m.hkdfState : Vector UInt8 104)
  buf

def unmarshalMessageBoxIndex (data : Vector UInt8 MessageBoxIndexSize) : MessageBoxIndex where
  idx64             := getU64LE (Vector.ofFn fun i : Fin 8 => data[i.val]!)
  curBlindingFactor := Vector.ofFn fun i : Fin 32 => data[i.val + 8]!
  curEncryptionKey  := Vector.ofFn fun i : Fin 32 => data[i.val + 40]!
  hkdfState         := Vector.ofFn fun i : Fin 32 => data[i.val + 72]!

structure ReadCap where
  rootPublicKey   : Vector UInt8 32
  messageBoxIndex : MessageBoxIndex

def marshalReadCap (rc : ReadCap) : Vector UInt8 ReadCapSize :=
  (rc.rootPublicKey ++ marshalMessageBoxIndex rc.messageBoxIndex : Vector UInt8 136)

/-- Deserialize `pubkey ++ index`; `none` if the root public key is not an edwards25519 point
(an unreduced `y` is accepted). -/
def unmarshalReadCap (data : Vector UInt8 ReadCapSize) : Option ReadCap :=
  let pk : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => data[i.val]!
  if (CryptWalker.Sign.Ed25519Math.decodePoint pk).isSome then
    some { rootPublicKey := pk
           messageBoxIndex := unmarshalMessageBoxIndex (Vector.ofFn fun i : Fin MessageBoxIndexSize =>
             data[i.val + 32]!) }
  else none

/-- A write capability: the root Ed25519 seed plus the earliest reachable index. The seed is
kept because the expanded scalar `clamp(SHA-512(seed))` cannot be inverted for serialization. -/
structure WriteCap where
  rootSeed        : Vector UInt8 32
  messageBoxIndex : MessageBoxIndex

/-- The root signing scalar S_R, expanded from the seed per RFC 8032. -/
def WriteCap.rootPrivateKey (wc : WriteCap) : Scalar :=
  scalarFromSeed wc.rootSeed

/-- The root verification key P_R = S_R · G. -/
def WriteCap.rootPublicKey (wc : WriteCap) : PubBytes :=
  publicKey wc.rootPrivateKey

/-- The read capability at the same index: derives and decrypts the same boxes, cannot sign. -/
def WriteCap.readCap (wc : WriteCap) : ReadCap where
  rootPublicKey   := wc.rootPublicKey
  messageBoxIndex := wc.messageBoxIndex

/-- Re-base the cap to `idx`. The holder of the result learns nothing about earlier indices. -/
def WriteCap.withMessageBoxIndex (wc : WriteCap) (idx : MessageBoxIndex) : WriteCap :=
  { wc with messageBoxIndex := idx }

/-- Re-base the cap to `idx`. The holder of the result learns nothing about earlier indices. -/
def ReadCap.withMessageBoxIndex (rc : ReadCap) (idx : MessageBoxIndex) : ReadCap :=
  { rc with messageBoxIndex := idx }

/-- Serialize as `seed ++ pubkey ++ index`. -/
def marshalWriteCap (wc : WriteCap) : Vector UInt8 WriteCapSize :=
  (wc.rootSeed ++ wc.rootPublicKey ++ marshalMessageBoxIndex wc.messageBoxIndex : Vector UInt8 168)

/-- Deserialize `seed ++ pubkey ++ index`; `none` if the stored public key is not the one the
seed derives. -/
def unmarshalWriteCap (data : Vector UInt8 WriteCapSize) : Option WriteCap :=
  let wc : WriteCap :=
    { rootSeed        := Vector.ofFn fun i : Fin 32 => data[i.val]!
      messageBoxIndex := unmarshalMessageBoxIndex (Vector.ofFn fun i : Fin MessageBoxIndexSize =>
        data[i.val + 64]!) }
  let stored : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => data[i.val + 32]!
  if wc.rootPublicKey == stored then some wc else none

/-! ## `unmarshal ∘ marshal` is the identity -/

private theorem getElem!_append_left {α} [Inhabited α] {n m : Nat}
    (a : Vector α n) (b : Vector α m) (i : Nat) (h : i < n) : (a ++ b)[i]! = a[i]! := by
  rw [getElem!_pos (a ++ b) i (by omega), getElem!_pos a i h, Vector.getElem_append, dif_pos h]

private theorem getElem!_append_right {α} [Inhabited α] {n m : Nat}
    (a : Vector α n) (b : Vector α m) (i k : Nat) (h : i < m) (hk : n = k) :
    (a ++ b)[i + k]! = b[i]! := by
  subst hk
  rw [getElem!_pos (a ++ b) (i + n) (by omega), getElem!_pos b i h,
    Vector.getElem_append, dif_neg (by omega)]
  congr 1
  omega

private theorem ofFn_append_left {α} [Inhabited α] {n m : Nat}
    (a : Vector α n) (b : Vector α m) :
    (Vector.ofFn fun i : Fin n => (a ++ b)[i.val]!) = a := by
  apply Vector.ext
  intro i hi
  rw [Vector.getElem_ofFn, getElem!_append_left _ _ _ hi, getElem!_pos _ i hi]

private theorem ofFn_append_right {α} [Inhabited α] {n m k : Nat}
    (a : Vector α n) (b : Vector α m) (hk : n = k) :
    (Vector.ofFn fun i : Fin m => (a ++ b)[i.val + k]!) = b := by
  apply Vector.ext
  intro i hi
  rw [Vector.getElem_ofFn, getElem!_append_right _ _ _ _ hi hk, getElem!_pos _ i hi]

private theorem getU64LE_putU64LE (v : UInt64) : getU64LE (putU64LE v) = v := by
  have h : ∀ (i : Nat), i < 8 → (putU64LE v)[i]! = (v >>> (UInt64.ofNat (8 * i))).toUInt8 := by
    intro i hi
    rw [putU64LE, getElem!_pos _ i hi, Vector.getElem_ofFn]
  simp only [getU64LE, h 0 (by omega), h 1 (by omega), h 2 (by omega), h 3 (by omega),
    h 4 (by omega), h 5 (by omega), h 6 (by omega), h 7 (by omega),
    show UInt64.ofNat (8 * 0) = 0 from rfl, show UInt64.ofNat (8 * 1) = 8 from rfl,
    show UInt64.ofNat (8 * 2) = 16 from rfl, show UInt64.ofNat (8 * 3) = 24 from rfl,
    show UInt64.ofNat (8 * 4) = 32 from rfl, show UInt64.ofNat (8 * 5) = 40 from rfl,
    show UInt64.ofNat (8 * 6) = 48 from rfl, show UInt64.ofNat (8 * 7) = 56 from rfl]
  bv_decide

private theorem putU64LE_getU64LE (d : Vector UInt8 8) : putU64LE (getU64LE d) = d := by
  apply Vector.ext
  intro i hi
  rw [putU64LE, Vector.getElem_ofFn]
  apply UInt8.eq_of_toBitVec_eq
  apply BitVec.eq_of_getLsbD_eq
  intro j hj
  have hb : ∀ k (hk : k < 8), d[k]! = d[k] := fun k hk => getElem!_pos d k hk
  simp only [getU64LE, hb 0 (by omega), hb 1 (by omega), hb 2 (by omega), hb 3 (by omega),
    hb 4 (by omega), hb 5 (by omega), hb 6 (by omega), hb 7 (by omega)]
  interval_cases i <;> interval_cases j <;> simp [UInt64.toBitVec_or, UInt64.toBitVec_shiftLeft,
    UInt64.toBitVec_shiftRight, UInt8.toBitVec_toUInt64, UInt64.toBitVec_toUInt8]

@[simp] theorem unmarshal_marshal_messageBoxIndex (m : MessageBoxIndex) :
    unmarshalMessageBoxIndex (marshalMessageBoxIndex m) = m := by
  obtain ⟨idx, cbf, cek, hs⟩ := m
  have h0 : (Vector.ofFn fun i : Fin 8 =>
      (((putU64LE idx ++ cbf) ++ cek) ++ hs : Vector UInt8 104)[i.val]!) = putU64LE idx := by
    apply Vector.ext
    intro i hi
    rw [Vector.getElem_ofFn, getElem!_append_left _ _ _ (by omega),
      getElem!_append_left _ _ _ (by omega), getElem!_append_left _ _ _ hi,
      getElem!_pos _ i hi]
  have h8 : (Vector.ofFn fun i : Fin 32 =>
      (((putU64LE idx ++ cbf) ++ cek) ++ hs : Vector UInt8 104)[i.val + 8]!) = cbf := by
    apply Vector.ext
    intro i hi
    rw [Vector.getElem_ofFn, getElem!_append_left _ _ _ (by omega),
      getElem!_append_left _ _ _ (by omega), getElem!_append_right _ _ _ _ hi rfl,
      getElem!_pos _ i hi]
  have h40 : (Vector.ofFn fun i : Fin 32 =>
      (((putU64LE idx ++ cbf) ++ cek) ++ hs : Vector UInt8 104)[i.val + 40]!) = cek := by
    apply Vector.ext
    intro i hi
    rw [Vector.getElem_ofFn, getElem!_append_left _ _ _ (by omega),
      getElem!_append_right _ _ _ _ hi rfl, getElem!_pos _ i hi]
  have h72 : (Vector.ofFn fun i : Fin 32 =>
      (((putU64LE idx ++ cbf) ++ cek) ++ hs : Vector UInt8 104)[i.val + 72]!) = hs := by
    apply Vector.ext
    intro i hi
    rw [Vector.getElem_ofFn, getElem!_append_right _ _ _ _ hi rfl, getElem!_pos _ i hi]
  simp only [unmarshalMessageBoxIndex, marshalMessageBoxIndex, h0, h8, h40, h72,
    getU64LE_putU64LE]

/-- A read cap whose root public key is a curve point round-trips. -/
theorem unmarshal_marshal_readCap (rc : ReadCap)
    (h : (CryptWalker.Sign.Ed25519Math.decodePoint rc.rootPublicKey).isSome) :
    unmarshalReadCap (marshalReadCap rc) = some rc := by
  obtain ⟨pub, idx⟩ := rc
  simp only [unmarshalReadCap, marshalReadCap, ofFn_append_left,
    ofFn_append_right _ _ rfl, unmarshal_marshal_messageBoxIndex]
  rw [if_pos h]

/-- Every write cap round-trips. -/
@[simp] theorem unmarshal_marshal_writeCap (wc : WriteCap) :
    unmarshalWriteCap (marshalWriteCap wc) = some wc := by
  obtain ⟨seed, idx⟩ := wc
  have hseed : (Vector.ofFn fun i : Fin 32 =>
      ((seed ++ WriteCap.rootPublicKey ⟨seed, idx⟩) ++ marshalMessageBoxIndex idx :
        Vector UInt8 168)[i.val]!) = seed := by
    apply Vector.ext
    intro i hi
    rw [Vector.getElem_ofFn, getElem!_append_left _ _ _ (by omega),
      getElem!_append_left _ _ _ hi, getElem!_pos _ i hi]
  have hpub : (Vector.ofFn fun i : Fin 32 =>
      ((seed ++ WriteCap.rootPublicKey ⟨seed, idx⟩) ++ marshalMessageBoxIndex idx :
        Vector UInt8 168)[i.val + 32]!) = WriteCap.rootPublicKey ⟨seed, idx⟩ := by
    apply Vector.ext
    intro i hi
    rw [Vector.getElem_ofFn, getElem!_append_left _ _ _ (by omega),
      getElem!_append_right _ _ _ _ hi rfl, getElem!_pos _ i hi]
  simp only [unmarshalWriteCap, marshalWriteCap, hseed, hpub,
    ofFn_append_right _ _ rfl, unmarshal_marshal_messageBoxIndex, beq_self_eq_true, if_true]

/-! ## `marshal ∘ unmarshal` is the identity on blobs that parse: encodings are canonical -/

private theorem ofFn_slices {n m : Nat} (d : Vector UInt8 (n + m)) :
    ((Vector.ofFn fun i : Fin n => d[i.val]!) ++ (Vector.ofFn fun i : Fin m => d[i.val + n]!) :
      Vector UInt8 (n + m)) = d := by
  apply Vector.ext
  intro i hi
  rw [Vector.getElem_append]
  split
  · rw [Vector.getElem_ofFn, getElem!_pos d i hi]
  · rw [Vector.getElem_ofFn, getElem!_pos d _ (by omega)]
    dsimp only
    congr 1
    omega

@[simp] theorem marshal_unmarshal_messageBoxIndex (d : Vector UInt8 MessageBoxIndexSize) :
    marshalMessageBoxIndex (unmarshalMessageBoxIndex d) = d := by
  simp only [marshalMessageBoxIndex, unmarshalMessageBoxIndex, putU64LE_getU64LE]
  apply Vector.ext
  intro i hi
  simp only [Vector.getElem_append, Vector.getElem_ofFn]
  split_ifs <;> rw [getElem!_pos d _ (by unfold MessageBoxIndexSize; omega)] <;> congr 1 <;> omega

/-- A read cap that parses re-serializes to the bytes it came from. -/
theorem marshal_unmarshal_readCap {data : Vector UInt8 ReadCapSize} {rc : ReadCap}
    (h : unmarshalReadCap data = some rc) : marshalReadCap rc = data := by
  unfold unmarshalReadCap at h
  dsimp only at h
  split at h
  · rw [Option.some.injEq] at h
    subst h
    simp only [marshalReadCap, marshal_unmarshal_messageBoxIndex]
    exact ofFn_slices (n := 32) (m := 104) data
  · exact absurd h nofun

/-- A write cap that parses re-serializes to the bytes it came from. -/
theorem marshal_unmarshal_writeCap {data : Vector UInt8 WriteCapSize} {wc : WriteCap}
    (h : unmarshalWriteCap data = some wc) : marshalWriteCap wc = data := by
  unfold unmarshalWriteCap at h
  dsimp only at h
  split at h
  · rename_i hpub
    rw [Option.some.injEq] at h
    subst h
    rw [beq_iff_eq] at hpub
    simp only [marshalWriteCap, hpub, marshal_unmarshal_messageBoxIndex]
    apply Vector.ext
    intro i hi
    simp only [Vector.getElem_append, Vector.getElem_ofFn]
    split_ifs <;> rw [getElem!_pos data _ (by simp only [WriteCapSize, MessageBoxIndexSize] at *; omega)] <;> congr 1 <;> omega
  · exact absurd h nofun

end CryptWalker.Protocols.BACAP.Types

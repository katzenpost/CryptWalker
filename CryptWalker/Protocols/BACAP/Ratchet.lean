/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Protocols.BACAP.Types
import CryptWalker.Hash.HKDF

/-! # BACAP ratchet and per-context key derivation -/

namespace CryptWalker.Protocols.BACAP.Ratchet

open CryptWalker.Protocols.BACAP.Types
open CryptWalker.Hash.HKDF

/-- K_i^ctx = HKDF-Expand(HKDF-Extract(salt=ctx, IKM=K_i), info=empty, 32). -/
def deriveKForContext (m : MessageBoxIndex) (hkdf : HKDF) (ctx : ByteArray) : Vector UInt8 32 :=
  let ikm := ⟨m.curBlindingFactor.toArray⟩
  let prk := hkdf.extract ctx ikm
  let okm := hkdf.expand prk ByteArray.empty 32
  Vector.ofFn fun i : Fin 32 => okm[i]!

/-- E_i^ctx = HKDF-Expand(HKDF-Extract(salt=ctx, IKM=E_i), info=empty, 32). -/
def deriveEForContext (m : MessageBoxIndex) (hkdf : HKDF) (ctx : ByteArray) : Vector UInt8 32 :=
  let ikm := ⟨m.curEncryptionKey.toArray⟩
  let prk := hkdf.extract ctx ikm
  let okm := hkdf.expand prk ByteArray.empty 32
  Vector.ofFn fun i : Fin 32 => okm[i]!

/-- Advance one step: expand HKDF(IKM=H_i, info=idx64 LE) to 96 bytes, split as
    H_{i+1} ‖ E ‖ K, and increment `idx64`. -/
def advanceOne (m : MessageBoxIndex) (hkdf : HKDF) : MessageBoxIndex :=
  let idx64Bytes : Vector UInt8 8 := Vector.ofFn fun i : Fin 8 =>
    (m.idx64 >>> (UInt64.ofNat (8 * i.val))).toUInt8
  let ikm := ⟨m.hkdfState.toArray⟩
  let prk := hkdf.extract ByteArray.empty ikm
  let okm := hkdf.expand prk ⟨idx64Bytes.toArray⟩ 96
  { idx64             := m.idx64 + 1
    curBlindingFactor := Vector.ofFn fun i : Fin 32 => okm[64 + i.val]!
    curEncryptionKey  := Vector.ofFn fun i : Fin 32 => okm[32 + i.val]!
    hkdfState         := Vector.ofFn fun i : Fin 32 => okm[i]! }

/-- Advance to `target`; `none` if `target` is behind the current index. -/
def advanceTo (m : MessageBoxIndex) (hkdf : HKDF) (target : UInt64) : Option MessageBoxIndex :=
  if target < m.idx64 then none
  else
    let steps := (target - m.idx64).toNat
    let rec go : Nat → MessageBoxIndex → MessageBoxIndex
      | 0, cur => cur
      | n + 1, cur =>
        if cur.idx64 < target
        then go n (advanceOne cur hkdf)
        else cur
    some (go steps m)

/-- Advance the ratchet by one step. -/
def nextIndex (m : MessageBoxIndex) (hkdf : HKDF) : Option MessageBoxIndex :=
  advanceTo m hkdf (m.idx64 + 1)

/-- HKDF info label separating `mutateKDFState` from ordinary advancement. -/
def mutateKDFStateLabel : ByteArray := "bacap-mutate-kdf-state-v1".toUTF8

/-- Re-seed the ratchet state from `ctx`, preserving `idx64` and the root key. The result
    addresses a fresh box sequence that cannot be found without `ctx`. -/
def mutateKDFState (m : MessageBoxIndex) (hkdf : HKDF) (ctx : ByteArray) : MessageBoxIndex :=
  let ikm := ⟨m.hkdfState.toArray⟩
  let prk := hkdf.extract ctx ikm
  let okm := hkdf.expand prk mutateKDFStateLabel 96
  { idx64             := m.idx64
    curBlindingFactor := Vector.ofFn fun i : Fin 32 => okm[64 + i.val]!
    curEncryptionKey  := Vector.ofFn fun i : Fin 32 => okm[32 + i.val]!
    hkdfState         := Vector.ofFn fun i : Fin 32 => okm[i.val]! }

/-- A fresh `MessageBoxIndex` from 48 random bytes: 32 bytes of HKDF state, and a starting
    index that is the sum of two 62-bit little-endian draws, then advanced once. A random start
    hides how many messages precede a shared capability. -/
def ofRandomBytes (rb : Vector UInt8 48) (hkdf : HKDF) : MessageBoxIndex :=
  let idxByte : Nat → UInt64 := fun j =>
    let b := rb[32 + j]!
    (if j == 7 || j == 15 then b &&& 0x3f else b).toUInt64
  let le : Nat → UInt64 := fun off =>
    (List.range 8).foldl (fun acc k => acc ||| (idxByte (off + k) <<< (UInt64.ofNat (8 * k)))) 0
  advanceOne
    { idx64             := le 0 + le 8
      curBlindingFactor := Vector.replicate 32 0
      curEncryptionKey  := Vector.replicate 32 0
      hkdfState         := Vector.ofFn fun i : Fin 32 => rb[i.val]! }
    hkdf

/-- `mutateKDFState` preserves `idx64`. -/
theorem mutateKDFState_preserves_idx64 (m : MessageBoxIndex) (hkdf : HKDF) (ctx : ByteArray) :
    (mutateKDFState m hkdf ctx).idx64 = m.idx64 := by
  simp only [mutateKDFState]

theorem advanceOne_increments_idx64 (m : MessageBoxIndex) (hkdf : HKDF) :
    (advanceOne m hkdf).idx64 = m.idx64 + 1 := rfl

theorem advanceTo_noop (m : MessageBoxIndex) (hkdf : HKDF) :
    advanceTo m hkdf m.idx64 = some m := by
  simp [advanceTo, advanceTo.go, UInt64.lt_irrefl]

end CryptWalker.Protocols.BACAP.Ratchet

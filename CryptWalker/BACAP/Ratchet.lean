/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.BACAP.Types
import CryptWalker.Hash.HKDF

/-! # BACAP Ratchet: HKDF chain advancement + context key derivation

The ratchet advances the `MessageBoxIndex` state forward through the HKDF chain,
deriving new blinding factors, encryption keys, and HKDF state at each step.

Context derivation derives per-context keys from the current ratchet state:
- `deriveKForContext`: derives a blinding factor from `curBlindingFactor` + context
- `deriveEForContext`: derives an encryption key from `curEncryptionKey` + context

These match `hpqc/bacap/bacap_impl.go:deriveKForContext` and `deriveEForContext`.

The ratchet itself matches `AdvanceIndexTo` — it reads 32 bytes of `H_{i+1}`, then 32 bytes
of `E_i`, then 32 bytes of `K_i` from an HKDF instance keyed on `H_i` with the index as info. -/

namespace CryptWalker.BACAP.Ratchet

open CryptWalker.BACAP.Types
open CryptWalker.Hash.HKDF

/-- Derive a context-specific blinding factor K_i^ctx from `curBlindingFactor` and `ctx`.

    Uses HKDF: Extract(salt=ctx, IKM=K_i) then Expand(PRK, info=empty, len=32).
    Matches `hpqc/bacap/bacap_impl.go:deriveKForContext`. -/
def deriveKForContext (m : MessageBoxIndex) (hkdf : HKDF) (ctx : ByteArray) : Vector UInt8 32 :=
  let ikm := ⟨m.curBlindingFactor.toArray⟩
  let prk := hkdf.extract ctx ikm
  let okm := hkdf.expand prk ByteArray.empty 32
  Vector.ofFn fun i : Fin 32 => okm[i]!

/-- Derive a context-specific encryption key E_i^ctx from `curEncryptionKey` and `ctx`.

    Uses HKDF: Extract(salt=ctx, IKM=E_i) then Expand(PRK, info=empty, len=32).
    Matches `hpqc/bacap/bacap_impl.go:deriveEForContext`. -/
def deriveEForContext (m : MessageBoxIndex) (hkdf : HKDF) (ctx : ByteArray) : Vector UInt8 32 :=
  let ikm := ⟨m.curEncryptionKey.toArray⟩
  let prk := hkdf.extract ctx ikm
  let okm := hkdf.expand prk ByteArray.empty 32
  Vector.ofFn fun i : Fin 32 => okm[i]!

/-- Advance the ratchet by one step.

    On input `(idx64, H_i)` this produces:
    - `H_{i+1}` from HKDF-Extract(ikm=H_i, salt=idx64_LE) expanded to 96 bytes,
      first 32 → H_{i+1}, next 32 → E_i, last 32 → K_i.
    - Then `idx64 := idx64 + 1`.

    This matches the read order in `AdvanceIndexTo`: H, E, K. -/
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

/-- Advance the ratchet to a target index (must be ≥ current index). -/
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

/-- HKDF info (domain-separation) label used by `mutateKDFState`.

    Matches Go's `bacap.mutateKDFStateLabel`. It keeps a re-seeded ratchet state from ever
    colliding with a state produced by ordinary chain advancement, which uses an empty salt
    and the index as info. -/
def mutateKDFStateLabel : ByteArray := "bacap-mutate-kdf-state-v1".toUTF8

/-- Re-seed the ratchet state from `ctx`, preserving `idx64`.

    Mixes `H_i` with `ctx` through HKDF under `mutateKDFStateLabel`, then re-derives `E_i` and
    `K_i` from the result in the same read order as `advanceOne` (H, E, K). The mutated index
    addresses a fresh sequence of boxes that cannot be found without `ctx`, while the root key
    held by the cap is untouched.

    This is the BACAP primitive behind the Contact Voucher's VoucherSalt: the joiner mutates
    their WriteCap and the inductor mutates the paired ReadCap by the same `ctx`, so writer and
    readers land on the same mutated sequence. Unlike `deriveKForContext`, which derives a
    single box ID without disturbing the ratchet, this advances the ratchet itself.

    Matches `hpqc/bacap/bacap_impl.go:MutateKDFState`. -/
def mutateKDFState (m : MessageBoxIndex) (hkdf : HKDF) (ctx : ByteArray) : MessageBoxIndex :=
  let ikm := ⟨m.hkdfState.toArray⟩
  let prk := hkdf.extract ctx ikm
  let okm := hkdf.expand prk mutateKDFStateLabel 96
  { idx64             := m.idx64
    curBlindingFactor := Vector.ofFn fun i : Fin 32 => okm[64 + i.val]!
    curEncryptionKey  := Vector.ofFn fun i : Fin 32 => okm[32 + i.val]!
    hkdfState         := Vector.ofFn fun i : Fin 32 => okm[i.val]! }

/-- Build a fresh `MessageBoxIndex` from 48 bytes of randomness.

    The first 32 bytes become the conversation's HKDF key. The remaining 16 are read as two
    little-endian `uint64`s; the most significant byte of each (offsets 7 and 15) has its top
    two bits cleared, bounding each summand to `[0, 2^62 - 1]`, and their wrapping sum is the
    starting index. Starting at a random index rather than 0 means a later recipient of a
    capability learns only an upper bound on how many messages preceded it, and summing two
    smaller draws biases the start towards the middle, which lowers the chance of landing near
    0. The ratchet is then advanced once so the returned index has properly derived `E_i` and
    `K_i`.

    Randomness is a parameter rather than an effect so this stays a pure function; see
    `MessageBoxIndex.randomIO` in `CryptWalker.BACAP.API` for the `IO` wrapper that draws from
    the system CSPRNG. Matches `hpqc/bacap/bacap_impl.go:NewMessageBoxIndex`. -/
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

/-- `mutateKDFState` preserves `idx64`; only the derived key material moves. -/
theorem mutateKDFState_preserves_idx64 (m : MessageBoxIndex) (hkdf : HKDF) (ctx : ByteArray) :
    (mutateKDFState m hkdf ctx).idx64 = m.idx64 := by
  simp only [mutateKDFState]

/-- `advanceOne` increments `idx64` by 1. -/
theorem advanceOne_increments_idx64 (m : MessageBoxIndex) (hkdf : HKDF) :
    (advanceOne m hkdf).idx64 = m.idx64 + 1 := rfl

/-- `advanceTo` with target equal to current index is a no-op. -/
theorem advanceTo_noop (m : MessageBoxIndex) (hkdf : HKDF) :
    advanceTo m hkdf m.idx64 = some m := by
  simp [advanceTo, advanceTo.go, UInt64.lt_irrefl]

end CryptWalker.BACAP.Ratchet

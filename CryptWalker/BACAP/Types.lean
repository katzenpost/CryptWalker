/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Ed25519_blinded
import CryptWalker.Hash.HKDF

/-! # BACAP Types: MessageBoxIndex, ReadCap, WriteCap

Data types for the Blinded Cryptographic Capability system (§4 of the Echomix paper),
their serialization, and the record-level plumbing that needs no key derivation.

Binary layouts match `hpqc/bacap/bacap.go` for cross-implementation test vectors:
- MessageBoxIndex: uint64 LE ++ [32]byte ++ [32]byte ++ [32]byte = 104 bytes
- ReadCap: [32]byte pubkey ++ MessageBoxIndex = 136 bytes
- WriteCap: [64]byte privkey ++ MessageBoxIndex = 168 bytes

A Go `ed25519.PrivateKey` is 64 bytes, `seed ++ pubkey`, so a serialized WriteCap
carries the root public key even though it is redundant. We store only the seed and
re-derive the scalar and the public key, which is why this file reaches for
`scalarFromSeed` and `publicKey`; everything else here is pure byte handling. -/

namespace CryptWalker.BACAP.Types

open CryptWalker.Sign.Ed25519Blinded

def MessageBoxIndexSize : Nat := 104
def ReadCapSize : Nat := 136
def WriteCapSize : Nat := 168

/-- Ratchet state for one direction of a BACAP conversation.

Fields correspond to `hpqc/bacap/bacap.go:MessageBoxIndex`:
- `idx64` — the message counter (little-endian uint64).
- `curBlindingFactor` — K_i, used to derive box IDs via Ed25519 blinding.
- `curEncryptionKey` — E_i, used to derive per-box AEAD keys.
- `hkdfState` — H_i, the HKDF ratchet state for advancing to the next index. -/
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
  let d := fun (i : Fin 8) => (data[i]!).toUInt64
  (d ⟨0, by omega⟩) ||| (d ⟨1, by omega⟩ <<< (UInt64.ofNat 8)) |||
  (d ⟨2, by omega⟩ <<< (UInt64.ofNat 16)) ||| (d ⟨3, by omega⟩ <<< (UInt64.ofNat 24)) |||
  (d ⟨4, by omega⟩ <<< (UInt64.ofNat 32)) ||| (d ⟨5, by omega⟩ <<< (UInt64.ofNat 40)) |||
  (d ⟨6, by omega⟩ <<< (UInt64.ofNat 48)) ||| (d ⟨7, by omega⟩ <<< (UInt64.ofNat 56))

def marshalMessageBoxIndex (m : MessageBoxIndex) : Vector UInt8 MessageBoxIndexSize :=
  let buf : Vector UInt8 104 :=
    (putU64LE m.idx64 ++ m.curBlindingFactor ++ m.curEncryptionKey ++ m.hkdfState : Vector UInt8 104)
  buf

def unmarshalMessageBoxIndex (data : Vector UInt8 MessageBoxIndexSize) : MessageBoxIndex where
  idx64             := getU64LE (Vector.ofFn fun i : Fin 8 => data[i]!)
  curBlindingFactor := Vector.ofFn fun i : Fin 32 => data[i.val + 8]!
  curEncryptionKey  := Vector.ofFn fun i : Fin 32 => data[i.val + 40]!
  hkdfState         := Vector.ofFn fun i : Fin 32 => data[i.val + 72]!

structure ReadCap where
  rootPublicKey   : Vector UInt8 32
  messageBoxIndex : MessageBoxIndex

def marshalReadCap (rc : ReadCap) : Vector UInt8 ReadCapSize :=
  (rc.rootPublicKey ++ marshalMessageBoxIndex rc.messageBoxIndex : Vector UInt8 136)

def unmarshalReadCap (data : Vector UInt8 ReadCapSize) : ReadCap where
  rootPublicKey   := Vector.ofFn fun i : Fin 32 => data[i]!
  messageBoxIndex := unmarshalMessageBoxIndex (Vector.ofFn fun i : Fin MessageBoxIndexSize =>
    data[i.val + 32]!)

/-- A write capability: the root Ed25519 *seed* plus the earliest index the holder can reach.

We keep the seed rather than the expanded scalar because the scalar is `clamp(SHA-512(seed))`,
which cannot be inverted; storing it would make `marshalWriteCap` unable to reproduce the
serialization that `unmarshalWriteCap` consumes. -/
structure WriteCap where
  rootSeed        : Vector UInt8 32
  messageBoxIndex : MessageBoxIndex

/-- The root signing scalar S_R, expanded from the seed exactly as RFC 8032 key generation does. -/
def WriteCap.rootPrivateKey (wc : WriteCap) : Scalar :=
  scalarFromSeed wc.rootSeed

/-- The root verification key P_R = S_R · G. -/
def WriteCap.rootPublicKey (wc : WriteCap) : PubBytes :=
  publicKey wc.rootPrivateKey

/-- The read capability paired with this write capability, at the same index.

Mirrors `WriteCap.ReadCap` in Go. Handing this out lets the bearer derive the same box IDs
and decrypt them, but not sign new boxes. -/
def WriteCap.readCap (wc : WriteCap) : ReadCap where
  rootPublicKey   := wc.rootPublicKey
  messageBoxIndex := wc.messageBoxIndex

/-- Re-base the cap to `idx`, leaving the receiver unchanged.

Use it to move a cap to a chosen position (say the live edge) before handing it out, so the
holder of the new cap learns nothing about indices before `idx`. Go and Python panic or raise
on a nil index; here the type rules that out. -/
def WriteCap.withMessageBoxIndex (wc : WriteCap) (idx : MessageBoxIndex) : WriteCap :=
  { wc with messageBoxIndex := idx }

/-- Re-base the cap to `idx`, leaving the receiver unchanged.

Re-basing a read cap to the current position before sharing means the recipient starts there
and cannot iterate the one-way ratchet back to count earlier messages. -/
def ReadCap.withMessageBoxIndex (rc : ReadCap) (idx : MessageBoxIndex) : ReadCap :=
  { rc with messageBoxIndex := idx }

/-- Serialize as `seed ++ pubkey ++ index`, matching Go's 64-byte `ed25519.PrivateKey`. -/
def marshalWriteCap (wc : WriteCap) : Vector UInt8 WriteCapSize :=
  (wc.rootSeed ++ wc.rootPublicKey ++ marshalMessageBoxIndex wc.messageBoxIndex : Vector UInt8 168)

/-- Deserialize `seed ++ pubkey ++ index`. The stored public key is ignored: it is implied by
the seed, and re-deriving it is what Go's `UnmarshalBinary` does too. -/
def unmarshalWriteCap (data : Vector UInt8 WriteCapSize) : WriteCap where
  rootSeed        := Vector.ofFn fun i : Fin 32 => data[i]!
  messageBoxIndex := unmarshalMessageBoxIndex (Vector.ofFn fun i : Fin MessageBoxIndexSize =>
    data[i.val + 64]!)

@[simp] theorem unmarshal_marshal_messageBoxIndex (m : MessageBoxIndex) :
    unmarshalMessageBoxIndex (marshalMessageBoxIndex m) = m := by
  sorry

@[simp] theorem unmarshal_marshal_readCap (rc : ReadCap) :
    unmarshalReadCap (marshalReadCap rc) = rc := by
  sorry

@[simp] theorem unmarshal_marshal_writeCap (wc : WriteCap) :
    unmarshalWriteCap (marshalWriteCap wc) = wc := by
  sorry

end CryptWalker.BACAP.Types

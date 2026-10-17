/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace Cryptlib.Primitives.Sign.Sign

/-! # Digital signature schemes

Signing randomness lives in `StateM State`; `verify_sign` quantifies over every state, so a
randomized signer must verify for every nonce. Key generation is a pure function of a seed.
Signatures are fixed-size and `sign` is total, which excludes stateful schemes such as XMSS.
-/

structure Signature where
  State      : Type
  PublicKey  : Type
  PrivateKey : Type
  Sig        : Type

  seedSize       : Nat
  publicKeySize  : Nat
  privateKeySize : Nat
  sigSize        : Nat

  encodePublicKey  : PublicKey  → Vector UInt8 publicKeySize
  decodePublicKey  : Vector UInt8 publicKeySize  → Option PublicKey
  encodePrivateKey : PrivateKey → Vector UInt8 privateKeySize
  decodePrivateKey : Vector UInt8 privateKeySize → Option PrivateKey
  encodeSig        : Sig        → Vector UInt8 sigSize
  decodeSig        : Vector UInt8 sigSize        → Option Sig

  /-- Key generation from a caller-supplied seed. -/
  privateKeyFromSeed : Vector UInt8 seedSize → PrivateKey

  pub : PrivateKey → PublicKey

  /-- Stateful only to carry signing randomness. -/
  sign : PrivateKey → ByteArray → StateM State Sig

  verify : PublicKey → ByteArray → Sig → Bool

  decode_encode_pub  : ∀ pk, decodePublicKey  (encodePublicKey  pk) = some pk
  decode_encode_priv : ∀ sk, decodePrivateKey (encodePrivateKey sk) = some sk
  decode_encode_sig  : ∀ s,  decodeSig        (encodeSig        s)  = some s

  /-- Correctness, for every private key and every signing state. -/
  verify_sign : ∀ sk m s, verify (pub sk) m (sign sk m s).1 = true

/-- The trivial scheme: one key, one signature, everything verifies. Insecure. -/
instance : Inhabited Signature := ⟨{
  State      := Unit
  PublicKey  := Unit
  PrivateKey := Unit
  Sig        := Unit

  seedSize       := 0
  publicKeySize  := 0
  privateKeySize := 0
  sigSize        := 0

  encodePublicKey  := fun _ => #v[]
  decodePublicKey  := fun _ => some ()
  encodePrivateKey := fun _ => #v[]
  decodePrivateKey := fun _ => some ()
  encodeSig        := fun _ => #v[]
  decodeSig        := fun _ => some ()

  privateKeyFromSeed := fun _ => ()
  pub                := id
  sign               := fun _ _ => pure ()
  verify             := fun _ _ _ => true

  decode_encode_pub  := fun _ => rfl
  decode_encode_priv := fun _ => rfl
  decode_encode_sig  := fun _ => rfl
  verify_sign        := fun _ _ _ => rfl
}⟩

end Cryptlib.Primitives.Sign.Sign

/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/
namespace CryptWalker.NIKE.NIKE


structure NIKE where
  PrivateKey   : Type
  PublicKey    : Type
  SharedSecret : Type

  name : String

  privateKeySize   : Nat
  publicKeySize    : Nat
  sharedSecretSize : Nat

  -- Elements the group action is defined on: right subgroup, non-degenerate.
  Safe : PublicKey → Prop
  [decSafe : DecidablePred Safe]

  privateKeyFromSeed : Vector UInt8 32 → PrivateKey
  derivePublicKey    : PrivateKey → PublicKey

  -- Cannot be called without a safety proof.
  groupAction : PrivateKey → (pk : PublicKey) → Safe pk → SharedSecret

  encodePrivateKey   : PrivateKey   → Vector UInt8 privateKeySize
  decodePrivateKey   : Vector UInt8 privateKeySize → Option PrivateKey
  encodePublicKey    : PublicKey    → Vector UInt8 publicKeySize
  decodePublicKey    : Vector UInt8 publicKeySize  → Option PublicKey
  encodeSharedSecret : SharedSecret → Vector UInt8 sharedSecretSize

  -- Laws.
  derive_safe : ∀ sk, Safe (derivePublicKey sk)
  decode_encode_priv : ∀ sk, decodePrivateKey (encodePrivateKey sk) = some sk
  decode_encode_pub  : ∀ pk, decodePublicKey  (encodePublicKey  pk) = some pk

  -- Encodings are canonical: no two byte strings decode to the same key.
  encode_decode_pub : ∀ v pk, decodePublicKey v = some pk → encodePublicKey pk = v

  commutes : ∀ sk₁ sk₂,
    groupAction sk₁ (derivePublicKey sk₂) (derive_safe sk₂)
      = groupAction sk₂ (derivePublicKey sk₁) (derive_safe sk₁)

attribute [instance] NIKE.decSafe


end CryptWalker.NIKE.NIKE

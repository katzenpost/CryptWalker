/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/
namespace CryptWalker.NIKE.NIKE

structure NIKE where
  PublicKeyType : Type
  PrivateKeyType : Type

  name : String
  privateKeySize : Nat
  publicKeySize : Nat

  generatePrivateKey : IO PrivateKeyType
  derivePublicKey : PrivateKeyType → PublicKeyType
  groupAction : PrivateKeyType → PublicKeyType → PublicKeyType
  encodePrivateKey : PrivateKeyType → ByteArray
  decodePrivateKey : ByteArray → Option PrivateKeyType
  encodePublicKey : PublicKeyType → ByteArray
  decodePublicKey : ByteArray → Option PublicKeyType
  validPublicKey : PublicKeyType → Bool

structure LawfulNIKE (nike : NIKE) : Prop where
  decode_encode_pub  : ∀ pk, nike.decodePublicKey (nike.encodePublicKey pk) = some pk
  decode_encode_priv : ∀ sk, nike.decodePrivateKey (nike.encodePrivateKey sk) = some sk
  derive_valid : ∀ sk, nike.validPublicKey (nike.derivePublicKey sk) = true
  commutes : ∀ sk₁ sk₂,
    nike.groupAction sk₁ (nike.derivePublicKey sk₂)
      = nike.groupAction sk₂ (nike.derivePublicKey sk₁)


end CryptWalker.NIKE.NIKE

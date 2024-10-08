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
  generateKeyPair : IO (PublicKeyType × PrivateKeyType)
  groupAction : PrivateKeyType → PublicKeyType → PublicKeyType
  encodePrivateKey : PrivateKeyType → ByteArray
  decodePrivateKey : ByteArray → Option PrivateKeyType
  encodePublicKey : PublicKeyType → ByteArray
  decodePublicKey : ByteArray → Option PublicKeyType

end CryptWalker.NIKE.NIKE

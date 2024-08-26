/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

namespace CryptWalker.nike.nike

class Key (key : Type) where
  encode : key → ByteArray
  decode : ByteArray → Option key

class PrivateKey (privkey : Type) extends Key privkey

class PublicKey (pubkey : Type) extends Key pubkey

class NIKE (scheme : Type) where
  PublicKeyType : Type
  PrivateKeyType : Type

  generatePrivateKey : IO PrivateKeyType
  derivePublicKey : PrivateKeyType → PublicKeyType
  generateKeyPair : IO (PublicKeyType × PrivateKeyType)
  groupAction : PrivateKeyType → PublicKeyType → PublicKeyType
  privateKeySize : Nat
  publicKeySize : Nat
  encodePrivateKey : PrivateKeyType → ByteArray
  decodePrivateKey : ByteArray → Option PrivateKeyType
  encodePublicKey : PublicKeyType → ByteArray
  decodePublicKey : ByteArray → Option PublicKeyType

end CryptWalker.nike.nike

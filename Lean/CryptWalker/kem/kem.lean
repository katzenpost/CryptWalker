/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

namespace CryptWalker.kem.kem

class Key (key : Type) where
  encode : key → ByteArray
  decode : ByteArray → Option key

class PrivateKey (privkey : Type) extends Key privkey

class PublicKey (pubkey : Type) extends Key pubkey

class KEM (scheme : Type) where
  PublicKeyType : Type
  PrivateKeyType : Type

  generateKeyPair : IO (PublicKeyType × PrivateKeyType)
  encapsulate : scheme → PublicKeyType → IO (ByteArray × ByteArray)
  decapsulate : scheme → PrivateKeyType → ByteArray → ByteArray
  privateKeySize : Nat
  publicKeySize : Nat
  encodePrivateKey : PrivateKeyType → ByteArray
  decodePrivateKey : ByteArray → Option PrivateKeyType
  encodePublicKey : PublicKeyType → ByteArray
  decodePublicKey : ByteArray → Option PublicKeyType

end CryptWalker.kem.kem

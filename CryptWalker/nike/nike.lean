/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/
import Batteries.Classes.SatisfiesM

namespace CryptWalker.nike.nike

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

structure Key (key : Type) where
  encode : key → ByteArray
  decode : NIKE → ByteArray → Option key

structure PrivateKey (privkey : Type) extends Key privkey

structure PublicKey (pubkey : Type) extends Key pubkey

end CryptWalker.nike.nike

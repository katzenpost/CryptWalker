/-
SPDX-FileCopyrightText: © 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only

Inspired by the Haskell FFI X25519:
https://github.com/haskell-crypto/cryptonite/blob/master/Crypto/PubKey/Curve25519.hs
-/

import Mathlib.Data.ByteArray
import CryptWalker.nike.nike

namespace CryptWalker.nike.x25519ffi

def keySize : Nat := 32

@[extern "curve25519"]
opaque curve25519 : ByteArray → ByteArray → ByteArray

def dh (privateKey : ByteArray) (publicKey : ByteArray) : ByteArray :=
  if privateKey.size ≠ keySize then
    panic! "Private key must be 32 bytes long."
  else if publicKey.size ≠ keySize then
    panic! "Public key must be 32 bytes long."
  else
    curve25519 privateKey publicKey

def toPublic (privateKey : ByteArray) : ByteArray :=
  dh privateKey basepoint
  where
  basepoint : ByteArray := String.toAsciiByteArray "\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

def x25519generatePrivateKey : IO ByteArray := do
  let mut arr := ByteArray.mkEmpty 32
  for _ in [0:32] do
    let randomByte ← IO.rand 0 255
    arr := arr.push (UInt8.ofNat randomByte)
  return arr

/-
  NIKE type classes instances for x25519
-/
structure PrivateKey where
  data : ByteArray

structure PublicKey where
  data : ByteArray

instance : nike.Key PrivateKey where
  encode : PrivateKey → ByteArray := fun (key : PrivateKey) => key.data
  decode : ByteArray → Option PrivateKey := fun (bytes : ByteArray) => some (PrivateKey.mk bytes)

instance : nike.Key PublicKey where
  encode : PublicKey → ByteArray := fun (key : PublicKey) => key.data
  decode : ByteArray → Option PublicKey := fun (bytes : ByteArray) => some (PublicKey.mk bytes)

structure X25519Scheme

instance : nike.NIKE X25519Scheme where
  PublicKeyType := PublicKey
  PrivateKeyType := PrivateKey

  generatePrivateKey : IO PrivateKey := do
    let key : ByteArray ← x25519generatePrivateKey
    pure { data := key }

  generateKeyPair : IO (PublicKey × PrivateKey) := do
    let rawprivKey ← x25519generatePrivateKey
    let privKey := PrivateKey.mk rawprivKey
    let pubKey := PublicKey.mk (toPublic privKey.data)
    pure (pubKey, privKey)

  derivePublicKey (sk : PrivateKey) : PublicKey := PublicKey.mk $ toPublic sk.data

  groupAction (sk : PrivateKey) (pk : PublicKey) : PublicKey := PublicKey.mk $ dh sk.data pk.data

  privateKeySize : Nat := keySize
  publicKeySize : Nat := keySize

  encodePrivateKey : PrivateKey → ByteArray := fun (sk : PrivateKey) => nike.Key.encode sk
  decodePrivateKey : ByteArray → Option PrivateKey := fun (bytes : ByteArray) => nike.Key.decode bytes
  encodePublicKey : PublicKey → ByteArray := fun (pk : PublicKey) => nike.Key.encode pk
  decodePublicKey : ByteArray → Option PublicKey := fun (bytes : ByteArray) => nike.Key.decode bytes

end CryptWalker.nike.x25519ffi

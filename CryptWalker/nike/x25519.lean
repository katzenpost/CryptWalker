/-
SPDX-FileCopyrightText: © 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/
import Mathlib.Algebra.Field.Defs
import Mathlib.Algebra.Field.Basic
import Mathlib.Data.ZMod.Basic
import Mathlib.Data.ByteArray

import CryptWalker.util.newnat
import CryptWalker.util.newhex
import CryptWalker.nike.nike
import CryptWalker.nike.MontgomeryLadder

open CryptWalker.nike.nike
open CryptWalker.nike.MontgomeryLadder

namespace CryptWalker.nike.x25519

def scheme : Scheme := {
  primeOrder := 2^255 - 19,
  basepoint := 9
  keySize := 32
  a24 := 121666
  ladderSteps := 255
  clampScalar := fun scalarBytes =>
    let c := scalarBytes.set! 0 (scalarBytes.get! 0 &&& 0xf8)
    c.set! 31 ((c.get! 31 &&& 0x7f) ||| 0x40)
}

def ecdh := newECDH scheme

def curve25519 (point : ByteArray) (scalarBytes : ByteArray): ByteArray :=
  ecdh.curve scalarBytes point

/-
  NIKE types for x25519
-/

def PublicKeySize := scheme.keySize
def PrivateKeySize := scheme.keySize

structure PrivateKey where
  data : ByteArray

structure PublicKey where
  data : ByteArray

def generatePrivateKey : IO PrivateKey := do
  let mut arr := ByteArray.mkEmpty scheme.keySize
  for _ in [0:scheme.keySize] do
    let randomByte ← IO.rand 0 255
    arr := arr.push (UInt8.ofNat randomByte)
  pure { data := arr }

def derivePublicKey (sk : PrivateKey) : PublicKey :=
    PublicKey.mk $ ecdh.fromField $ (ecdh.scalarmult sk.data scheme.basepoint)

def SchemeName := "X25519"

def Scheme : NIKE :=
{
  PublicKeyType := PublicKey,
  PrivateKeyType := PrivateKey,
  privateKeySize := scheme.keySize,
  publicKeySize := scheme.keySize,
  name := SchemeName,

  generatePrivateKey := generatePrivateKey,

  generateKeyPair := do
    let privKey ← generatePrivateKey
    let pubKey := derivePublicKey privKey
    pure (pubKey, privKey),

  derivePublicKey := fun (sk : PrivateKey) => derivePublicKey sk,

  groupAction := fun (sk : PrivateKey) (pk : PublicKey) => PublicKey.mk $ curve25519 pk.data sk.data,

  encodePrivateKey := fun (sk : PrivateKey) => sk.data,
  decodePrivateKey := fun (bytes : ByteArray) => some { data := bytes },
  encodePublicKey := fun (pk : PublicKey) => pk.data,
  decodePublicKey := fun (bytes : ByteArray) => some { data := bytes }
}

end CryptWalker.nike.x25519

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
open CryptWalker.util.newhex

namespace CryptWalker.nike.x41417

set_option exponentiation.threshold 414

def mytoField (p : ℕ) (ba : ByteArray) : ZMod p :=
  let n := (ByteArray.mk $ Array.mk ba.toList.reverse).foldl (fun acc b => acc * 256 + b.toNat) 0
  n

def scheme : Scheme := {
  primeOrder := 2^414 - 17,
  basepoint := mytoField (2^414 - 17) $ falliableHexStringToByteArray "0e7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7c3c",
  keySize := 52,
  a24 := mytoField (2^414 - 17) $ falliableHexStringToByteArray "543668f26583265f3668f26583265f3668f26583265f3668f26583265f3668f26583265f3626",
  ladderSteps := 414,
  clampScalar := fun scalarBytes =>
    let c := scalarBytes.set! 0 (scalarBytes.get! 0 &&& 248)
    c.set! 51 ((c.get! 51 &&& 63) ||| 32)
}

def ecdh := newECDH scheme

def curve41417 (point : ByteArray) (scalarBytes : ByteArray): ByteArray :=
  ecdh.curve scalarBytes point

/-
  NIKE type classes instances for x41417
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

def SchemeName := "X41417"

def Scheme : NIKE :=
{
  PublicKeyType := PublicKey
  PrivateKeyType := PrivateKey

  privateKeySize := scheme.keySize,
  publicKeySize := scheme.keySize,

  name := "X41417"

  generatePrivateKey := generatePrivateKey,

  generateKeyPair := do
    let privKey ← generatePrivateKey
    let pubKey := derivePublicKey privKey
    pure (pubKey, privKey),

  derivePublicKey := fun (sk : PrivateKey) => derivePublicKey sk,

  groupAction := fun (sk : PrivateKey) (pk : PublicKey) => PublicKey.mk $ curve41417 pk.data sk.data,

  encodePrivateKey := fun (sk : PrivateKey) => sk.data,
  decodePrivateKey := fun (bytes : ByteArray) => some { data := bytes },
  encodePublicKey := fun (pk : PublicKey) => pk.data,
  decodePublicKey := fun (bytes : ByteArray) => some { data := bytes }
}

end CryptWalker.nike.x41417

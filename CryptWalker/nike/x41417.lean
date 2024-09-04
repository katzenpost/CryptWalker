/-
SPDX-FileCopyrightText: © 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/
import Mathlib.Algebra.Field.Defs
import Mathlib.Algebra.Field.Basic
import Mathlib.Data.ZMod.Basic
import Mathlib.Data.ByteArray
import Batteries.Classes.SatisfiesM

import CryptWalker.util.newnat
import CryptWalker.util.newhex
import CryptWalker.nike.nike

open CryptWalker.nike.nike
open CryptWalker.util.newhex

namespace CryptWalker.nike.x41417

set_option exponentiation.threshold 415

def p : ℕ := 2^414 - 17
def keySize : ℕ := 52

def clampScalarBytes (scalarBytes : ByteArray) : ByteArray :=
  let clamped1 := scalarBytes.set! 0 (scalarBytes.get! 0 &&& 248)
  let clamped2 := clamped1.set! 51 ((clamped1.get! 51 &&& 63) ||| 32)
  clamped2

def fromField (x : ZMod p) : ByteArray :=
  let bytes := ByteArray.mk $ Array.mk $ (ByteArray.toList $ natToBytes x.val).reverse
  bytes ++ ByteArray.mk (Array.mk (List.replicate (keySize - bytes.size) 0))

def toField (ba : ByteArray) : ZMod p :=
  let n := (ByteArray.mk $ Array.mk ba.toList.reverse).foldl (fun acc b => acc * 256 + b.toNat) 0
  n

def clampScalar (scalar : ZMod p) : ZMod p :=
  let b := fromField scalar
  let newB := clampScalarBytes b
  toField newB

structure LadderState :=
  a : ZMod p
  b : ZMod p
  c : ZMod p
  d : ZMod p

abbrev LadderM := StateM LadderState

def A24 : ZMod p := toField $ falliableHexStringToByteArray "543668f26583265f3668f26583265f3668f26583265f3668f26583265f3668f26583265f3626"
def basepoint : ZMod p := toField $ falliableHexStringToByteArray "0e7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7c3c"

def cswap (swap : UInt8) (x y : ZMod p) : (ZMod p × ZMod p) :=
  if swap == 1 then (y, x) else (x, y)

def scalar_mult (scalarBytes : ByteArray) (pointBytes : ByteArray) : LadderM Unit := do
  let clampedScalar := clampScalarBytes scalarBytes
  let point := toField pointBytes

  let mut a : ZMod p := 1
  let mut b : ZMod p := point
  let mut c : ZMod p := 0
  let mut d : ZMod p := 1
  let mut r : UInt8 := 0

  for i in (List.range 414).reverse do
    r := (clampedScalar.get! (i >>> 3) >>> UInt8.ofNat (i &&& 7)) &&& 1
    (a, b) := cswap r a b
    (c, d) := cswap r c d
    let e := a + c
    a := a - c
    c := b + d
    b := b - d
    d := e^2
    let f := a^2
    a := a * c
    c := b * e
    let e := a + c
    a := a - c
    b := a^2
    c := d - f
    a := c * A24
    a := a + d
    c := c * a
    a := d * f
    d := b * point
    b := e^2
    (a, b) := cswap r a b
    (c, d) := cswap r c d

  modify fun state => { state with a := a * c⁻¹ }

def scalar_mult_base (scalarBytes : ByteArray) : ByteArray :=
  let (_, st) := (scalar_mult scalarBytes $ fromField basepoint).run {
    a := 1,
    b := basepoint,
    c := 0,
    d := 1
  }
  fromField st.a

def curve41417 (scalarBytes : ByteArray) (point : ByteArray) : ByteArray :=
  let (_, result) := (scalar_mult scalarBytes point).run {
    a := 1,
    b := toField point,
    c := 0,
    d := 1
  }
  fromField result.a


/-
  NIKE type classes instances for x41417
-/

def PublicKeySize := keySize
def PrivateKeySize := keySize

structure PrivateKey where
  data : ByteArray

structure PublicKey where
  data : ByteArray

def generatePrivateKey : IO PrivateKey := do
  let mut arr := ByteArray.mkEmpty keySize
  for _ in [0:keySize] do
    let randomByte ← IO.rand 0 255
    arr := arr.push (UInt8.ofNat randomByte)
  pure { data := arr }

def derivePublicKey (privateKey : PrivateKey) : PublicKey :=
  PublicKey.mk $ scalar_mult_base privateKey.data

def SchemeName := "X41417"

def Scheme : NIKE :=
{
  PublicKeyType := PublicKey
  PrivateKeyType := PrivateKey

  privateKeySize := keySize,
  publicKeySize := keySize,

  name := "X41417"

  generatePrivateKey := generatePrivateKey,

  generateKeyPair := do
    let privKey ← generatePrivateKey
    let pubKey := derivePublicKey privKey
    pure (pubKey, privKey),

  derivePublicKey := fun (sk : PrivateKey) => derivePublicKey sk,

  groupAction := fun (sk : PrivateKey) (pk : PublicKey) => PublicKey.mk $ curve41417 sk.data pk.data,

  encodePrivateKey := fun (sk : PrivateKey) => sk.data,
  decodePrivateKey := fun (bytes : ByteArray) => some { data := bytes },
  encodePublicKey := fun (pk : PublicKey) => pk.data,
  decodePublicKey := fun (bytes : ByteArray) => some { data := bytes }
}

end CryptWalker.nike.x41417

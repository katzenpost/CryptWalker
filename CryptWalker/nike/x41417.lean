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

namespace CryptWalker.nike.x41417

--set_option exponentiation.threshold 500

def p : ℕ := 2^414 - 17
def keySize : ℕ := 52

theorem p_is_prime : Nat.Prime p := by sorry
instance fact_p_is_prime : Fact (Nat.Prime p) := ⟨p_is_prime⟩
instance : Field (ZMod p) := ZMod.instField p

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
  (a : ZMod p)
  (b : ZMod p)
  (c : ZMod p)
  (d : ZMod p)
  (e : ZMod p)
  (f : ZMod p)
  (r : UInt8)

def A24 : ZMod p := toField $ infalliableHexStringToByteArray "543668f26583265f3668f26583265f3668f26583265f3668f26583265f3668f26583265f3626"
def basepoint : ZMod p := toField $ infalliableHexStringToByteArray "0e7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7cf0c1071f7c3c"

def cswap (swap : UInt8) (x y : ZMod p) : (ZMod p × ZMod p) :=
  if swap == 1 then (y, x) else (x, y)

def montgomery_step (state : LadderState) (z : ByteArray) (i : Nat) (pe : ZMod p) : LadderState :=
  let r : UInt8 := (z.get! (i / 8) >>> UInt8.ofNat (i % 8)) &&& 1
  let (a, b) := cswap r state.a state.b
  let (c, d) := cswap r state.c state.d
  let e := a + c
  let a := a - c
  let c := b + d
  let b := b - d
  let d := e^2
  let f := a^2
  let a := a * c
  let c := b * e
  let e := a + c
  let a := a - c
  let b := a^2
  let c := d - f
  let a := c * A24
  let a := a + d
  let c := c * a
  let a := d * f
  let d := b * pe
  let b := e^2
  let (a, b) := cswap r a b
  let (c, d) := cswap r c d
  { a := a, b := b, c := c, d := d, e := e, f := f, r := r }

def montgomery_ladder (scalar : ZMod p) (point : ZMod p) : LadderState :=
  let e : ByteArray := fromField scalar
  let initState : LadderState := {
    a := 1,
    b := point,
    c := 0,
    d := 1,
    e := 0,
    f := 0,
    r := 0,
  }
  let rec ladderRec (state : LadderState) (i : Nat) : LadderState :=
    if i = 0 then
      state
    else
      let newState := montgomery_step state e (i - 1) point
      ladderRec newState (i - 1)
  ladderRec initState 414

def scalarmult (scalarBytes : ByteArray) (point : ZMod p) : ZMod p :=
  let clampedScalar := toField $ clampScalarBytes scalarBytes
  let finalState := montgomery_ladder clampedScalar point
  finalState.a * finalState.c⁻¹

def curve41417 (scalarBytes : ByteArray) (point : ByteArray) : ByteArray :=
  fromField $ scalarmult scalarBytes $ toField point

/-
  NIKE type classes instances for x41417
-/

def PublicKeySize := keySize
def PrivateKeySize := keySize

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

structure X41417Scheme

def generatePrivateKey : IO PrivateKey := do
  let mut arr := ByteArray.mkEmpty keySize
  for _ in [0:keySize] do
    let randomByte ← IO.rand 0 255
    arr := arr.push (UInt8.ofNat randomByte)
  pure { data := arr }

def derivePublicKey (sk : PrivateKey) : PublicKey :=
    PublicKey.mk $ fromField $ (scalarmult sk.data basepoint)

instance : nike.NIKE X41417Scheme where
  PublicKeyType := PublicKey
  PrivateKeyType := PrivateKey

  name : String := "X41417"

  generatePrivateKey : IO PrivateKey := do
    generatePrivateKey

  generateKeyPair : IO (PublicKey × PrivateKey) := do
    let privKey ← generatePrivateKey
    let pubKey := derivePublicKey privKey
    pure (pubKey, privKey)

  derivePublicKey (sk : PrivateKey) : PublicKey := derivePublicKey sk

  groupAction (sk : PrivateKey) (pk : PublicKey) : PublicKey := PublicKey.mk $ curve41417 sk.data pk.data

  privateKeySize : Nat := keySize
  publicKeySize : Nat := keySize

  encodePrivateKey : PrivateKey → ByteArray := fun (sk : PrivateKey) => nike.Key.encode sk
  decodePrivateKey : ByteArray → Option PrivateKey := fun (bytes : ByteArray) => nike.Key.decode bytes
  encodePublicKey : PublicKey → ByteArray := fun (pk : PublicKey) => nike.Key.encode pk
  decodePublicKey : ByteArray → Option PublicKey := fun (bytes : ByteArray) => nike.Key.decode bytes

end CryptWalker.nike.x41417

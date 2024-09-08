/-
SPDX-FileCopyrightText: © 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/
import Mathlib.Algebra.Field.Defs
import Mathlib.Algebra.Field.Basic
import Mathlib.Data.ZMod.Basic
import Mathlib.Data.ByteArray
import Mathlib.NumberTheory.LucasPrimality

import CryptWalker.util.newnat
import CryptWalker.util.newhex
import CryptWalker.nike.nike

open CryptWalker.nike.nike

namespace CryptWalker.nike.x25519

def p : ℕ := 2^255 - 19
def basepoint : ZMod p := 9
def keySize : ℕ := 32

def clampScalarBytes (scalarBytes : ByteArray) : ByteArray :=
  let clamped1 := scalarBytes.set! 0 (scalarBytes.get! 0 &&& 0xf8)
  let clamped2 := clamped1.set! 31 ((clamped1.get! 31 &&& 0x7f) ||| 0x40)
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
  (x1 : ZMod p)
  (x2 : ZMod p)
  (z2 : ZMod p)
  (x3 : ZMod p)
  (z3 : ZMod p)

def montgomery_step (s : LadderState) : LadderState :=
  let tmp0 := s.x3 - s.z3
  let tmp1 := s.x2 - s.z2
  let x2 := s.x2 + s.z2
  let z2 := s.x3 + s.z3
  let z3 := (tmp0 * x2)
  let z2 := z2 * tmp1
  let tmp0 := tmp1^2
  let tmp1 := x2^2
  let x3 := z3 + z2
  let z2 := z3 - z2
  let x2 := tmp1 * tmp0
  let tmp1 := tmp1 - tmp0
  let z2 := z2^2
  let z3 := tmp1 * 121666
  let x3 := x3^2
  let tmp0 := tmp0 + z3
  let z3 := s.x1 * z2
  let z2 := tmp1 * tmp0
  { s with x2 := x2, z2 := z2, x3 := x3, z3 := z3 }

def cswap (swap : Bool) (x y : ZMod p) : (ZMod p × ZMod p) :=
  if swap then (y, x) else (x, y)

def montgomery_ladder (scalar : ZMod p) (point : ZMod p) : Id LadderState :=
  do
    let e : ByteArray := fromField scalar
    let mut state : LadderState := {
      x1 := point,
      x2 := 1,
      z2 := 0,
      x3 := point,
      z3 := 1
    }
    let mut swap := false
    for pos in (List.range 255).reverse do
      let byteIndex := pos / 8
      let bitIndex := pos % 8
      let b : Bool := (Nat.toUInt8 ((e.get! byteIndex).toNat >>> bitIndex) &&& 1) == 1
      let newSwap := swap != b
      let (stateX2, stateX3) := cswap newSwap state.x2 state.x3
      let (stateZ2, stateZ3) := cswap newSwap state.z2 state.z3
      state := { state with x2 := stateX2, x3 := stateX3, z2 := stateZ2, z3 := stateZ3 }
      state := montgomery_step state
      swap := b
    let (finalX2, finalX3) := cswap swap state.x2 state.x3
    let (finalZ2, finalZ3) := cswap swap state.z2 state.z3
    state := { state with x2 := finalX2, x3 := finalX3, z2 := finalZ2, z3 := finalZ3 }
    state

def scalarmult (scalarBytes : ByteArray) (point : ZMod p) : ZMod p :=
  let clampedScalar := toField $ clampScalarBytes scalarBytes
  let finalState := montgomery_ladder clampedScalar point
  finalState.x2 * finalState.z2⁻¹

def curve25519 (scalarBytes : ByteArray) (point : ByteArray) : ByteArray :=
  fromField $ scalarmult scalarBytes $ toField point

/-
  NIKE type classes instances for x25519
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

def derivePublicKey (sk : PrivateKey) : PublicKey :=
    PublicKey.mk $ fromField $ (scalarmult sk.data basepoint)

def SchemeName := "X25519"

def Scheme : NIKE :=
{
  PublicKeyType := PublicKey,
  PrivateKeyType := PrivateKey,
  privateKeySize := keySize,
  publicKeySize := keySize,
  name := SchemeName,

  generatePrivateKey := generatePrivateKey,

  generateKeyPair := do
    let privKey ← generatePrivateKey
    let pubKey := derivePublicKey privKey
    pure (pubKey, privKey),

  derivePublicKey := fun (sk : PrivateKey) => derivePublicKey sk,

  groupAction := fun (sk : PrivateKey) (pk : PublicKey) => PublicKey.mk $ curve25519 sk.data pk.data,

  encodePrivateKey := fun (sk : PrivateKey) => sk.data,
  decodePrivateKey := fun (bytes : ByteArray) => some { data := bytes },
  encodePublicKey := fun (pk : PublicKey) => pk.data,
  decodePublicKey := fun (bytes : ByteArray) => some { data := bytes }
}

end CryptWalker.nike.x25519

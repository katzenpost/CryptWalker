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

namespace CryptWalker.nike.x25519

def p : ℕ := 2^255 - 19
def basepoint : ZMod p := 9
def keySize : ℕ := 32

theorem p_is_prime : Nat.Prime p := by sorry
instance fact_p_is_prime : Fact (Nat.Prime p) := ⟨p_is_prime⟩
instance : Field (ZMod p) := ZMod.instField p

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

def montgomery_ladder (scalar : ZMod p) (point : ZMod p) : LadderState :=
  let e : ByteArray := fromField scalar
  let initState : LadderState := {
    x1 := point,
    x2 := 1,
    z2 := 0,
    x3 := point,
    z3 := 1
  }
  let finalState := (List.range 255).reverse.foldl (fun (state, swap) pos =>
    let byteIndex := pos / 8
    let bitIndex := pos % 8
    let b : UInt8 := Nat.toUInt8 ((e.get! byteIndex).toNat >>> bitIndex) &&& 1
    let newSwap := swap ^^^ b
    let (x2, x3) := if newSwap == 1 then (state.x3, state.x2) else (state.x2, state.x3)
    let (z2, z3) := if newSwap == 1 then (state.z3, state.z2) else (state.z2, state.z3)
    let newState := montgomery_step { state with x2 := x2, x3 := x3, z2 := z2, z3 := z3 }
    (newState, b)
  ) (initState, 0)

  let finalSwap := finalState.snd
  let finalState := finalState.fst
  let (x2, x3) := if finalSwap == 1 then (finalState.x3, finalState.x2) else (finalState.x2, finalState.x3)
  let (z2, z3) := if finalSwap == 1 then (finalState.z3, finalState.z2) else (finalState.z2, finalState.z3)
  { finalState with x2 := x2, x3 := x3, z2 := z2, z3 := z3 }

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

instance : nike.Key PrivateKey where
  encode : PrivateKey → ByteArray := fun (key : PrivateKey) => key.data
  decode : ByteArray → Option PrivateKey := fun (bytes : ByteArray) => some (PrivateKey.mk bytes)

instance : nike.Key PublicKey where
  encode : PublicKey → ByteArray := fun (key : PublicKey) => key.data
  decode : ByteArray → Option PublicKey := fun (bytes : ByteArray) => some (PublicKey.mk bytes)

def generatePrivateKey : IO PrivateKey := do
  let mut arr := ByteArray.mkEmpty keySize
  for _ in [0:keySize] do
    let randomByte ← IO.rand 0 255
    arr := arr.push (UInt8.ofNat randomByte)
  pure { data := arr }

def derivePublicKey (sk : PrivateKey) : PublicKey :=
    PublicKey.mk $ fromField $ (scalarmult sk.data basepoint)

structure X25519Scheme

instance : nike.NIKE X25519Scheme where
  PublicKeyType := PublicKey
  PrivateKeyType := PrivateKey

  name : String := "X25519"

  generatePrivateKey : IO PrivateKey := do
    generatePrivateKey

  generateKeyPair : IO (PublicKey × PrivateKey) := do
    let privKey ← generatePrivateKey
    let pubKey := derivePublicKey privKey
    pure (pubKey, privKey)

  derivePublicKey (sk : PrivateKey) : PublicKey := derivePublicKey sk

  groupAction (sk : PrivateKey) (pk : PublicKey) : PublicKey := PublicKey.mk $ curve25519 sk.data pk.data

  privateKeySize : Nat := keySize
  publicKeySize : Nat := keySize

  encodePrivateKey : PrivateKey → ByteArray := fun (sk : PrivateKey) => nike.Key.encode sk
  decodePrivateKey : ByteArray → Option PrivateKey := fun (bytes : ByteArray) => nike.Key.decode bytes
  encodePublicKey : PublicKey → ByteArray := fun (pk : PublicKey) => nike.Key.encode pk
  decodePublicKey : ByteArray → Option PublicKey := fun (bytes : ByteArray) => nike.Key.decode bytes

end CryptWalker.nike.x25519

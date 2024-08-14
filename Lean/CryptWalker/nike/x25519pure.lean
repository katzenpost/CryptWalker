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

namespace CryptWalker.nike.x25519pure

def p : ℕ := 2^255 - 19
def basepoint : ZMod p := 9

theorem p_is_prime : Nat.Prime p := by sorry
instance fact_p_is_prime : Fact (Nat.Prime p) := ⟨p_is_prime⟩
instance : Field (ZMod p) := ZMod.instField p

def clampScalarBytes (scalarBytes : ByteArray) : ByteArray :=
  let clamped1 := scalarBytes.set! 0 (scalarBytes.get! 0 &&& 0xf8)
  let clamped2 := clamped1.set! 31 ((clamped1.get! 31 &&& 0x7f) ||| 0x40)
  clamped2

def zmodToByteArray (x : ZMod p) : ByteArray :=
  let bytes := ByteArray.mk $ Array.mk $ (ByteArray.toList $ natToBytes x.val).reverse
  bytes ++ ByteArray.mk (Array.mk (List.replicate (32 - bytes.size) 0))

def byteArrayToZmod (ba : ByteArray) : ZMod p :=
  let n := (ByteArray.mk $ Array.mk ba.toList.reverse).foldl (fun acc b => acc * 256 + b.toNat) 0
  n

def clampScalar (scalar : ZMod p) : ZMod p :=
  let b := zmodToByteArray scalar
  let newB := clampScalarBytes b
  byteArrayToZmod newB

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
  let e : ByteArray := zmodToByteArray scalar
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
  let clampedScalar := byteArrayToZmod $ clampScalarBytes scalarBytes
  let finalState := montgomery_ladder clampedScalar point
  finalState.x2 * finalState.z2⁻¹

end CryptWalker.nike.x25519pure

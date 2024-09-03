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

namespace CryptWalker.nike.MontgomeryLadder

structure Scheme :=
  primeOrder : ℕ
  keySize : ℕ
  basepoint : ZMod primeOrder
  a24 : ZMod primeOrder
  ladderSteps : ℕ
  clampScalar : ByteArray → ByteArray

structure LadderState (p : ℕ) :=
  x1 : ZMod p
  x2 : ZMod p
  z2 : ZMod p
  x3 : ZMod p
  z3 : ZMod p

structure ECDH :=
  scheme : Scheme
  montgomery_step : LadderState scheme.primeOrder → LadderState scheme.primeOrder
  montgomery_ladder : ZMod scheme.primeOrder → ZMod scheme.primeOrder → LadderState scheme.primeOrder
  fromField : ZMod scheme.primeOrder → ByteArray
  toField : ByteArray → ZMod scheme.primeOrder
  scalarmult : ByteArray → ZMod scheme.primeOrder → ZMod scheme.primeOrder
  curve : ByteArray → ByteArray → ByteArray


def fromField (scheme : Scheme) (x : ZMod scheme.primeOrder) : ByteArray :=
  let bytes := ByteArray.mk $ Array.mk $ (ByteArray.toList $ natToBytes x.val).reverse
  bytes ++ ByteArray.mk (Array.mk (List.replicate (scheme.keySize - bytes.size) 0))

def toField (scheme : Scheme) (ba : ByteArray) : ZMod scheme.primeOrder :=
  let n := (ByteArray.mk $ Array.mk ba.toList.reverse).foldl (fun acc b => acc * 256 + b.toNat) 0
  n

def montgomery_step (scheme : Scheme) (s : LadderState scheme.primeOrder) : LadderState scheme.primeOrder:=
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
  let z3 := tmp1 * scheme.a24
  let x3 := x3^2
  let tmp0 := tmp0 + z3
  let z3 := s.x1 * z2
  let z2 := tmp1 * tmp0
  { s with x2 := x2, z2 := z2, x3 := x3, z3 := z3 }

def montgomery_ladder (scheme : Scheme) (scalar : ZMod scheme.primeOrder) (point : ZMod scheme.primeOrder) : LadderState scheme.primeOrder :=
  let e : ByteArray := fromField scheme scalar
  let initState : LadderState scheme.primeOrder := {
    x1 := point,
    x2 := 1,
    z2 := 0,
    x3 := point,
    z3 := 1
  }
  let finalState := (List.range scheme.ladderSteps).reverse.foldl (fun (state, swap) pos =>
    let byteIndex := pos / 8
    let bitIndex := pos % 8
    let b : UInt8 := Nat.toUInt8 ((e.get! byteIndex).toNat >>> bitIndex) &&& 1
    let newSwap := swap ^^^ b
    let (x2, x3) := if newSwap == 1 then (state.x3, state.x2) else (state.x2, state.x3)
    let (z2, z3) := if newSwap == 1 then (state.z3, state.z2) else (state.z2, state.z3)
    let newState := montgomery_step scheme { state with x2 := x2, x3 := x3, z2 := z2, z3 := z3 }
    (newState, b)
  ) (initState, 0)
  let finalSwap := finalState.snd
  let finalState := finalState.fst
  let (x2, x3) := if finalSwap == 1 then (finalState.x3, finalState.x2) else (finalState.x2, finalState.x3)
  let (z2, z3) := if finalSwap == 1 then (finalState.z3, finalState.z2) else (finalState.z2, finalState.z3)
  { finalState with x2 := x2, x3 := x3, z2 := z2, z3 := z3 }

def scalarmult (scheme : Scheme) (scalarBytes : ByteArray) (point : ZMod scheme.primeOrder) : ZMod scheme.primeOrder :=
  let clampedScalar := toField scheme $ scheme.clampScalar scalarBytes
  let finalState := montgomery_ladder scheme clampedScalar point
  finalState.x2 * finalState.z2⁻¹

def curve (scheme : Scheme) (scalarBytes : ByteArray) (point : ByteArray) : ByteArray :=
  fromField scheme $ scalarmult scheme scalarBytes $ toField scheme point


def newECDH (scheme : Scheme) : ECDH :=
  {
    scheme := scheme,

    fromField := fun x => fromField scheme x,
    toField := fun ba => toField scheme ba,
    montgomery_step := fun l => montgomery_step scheme l,
    montgomery_ladder := fun ss x => montgomery_ladder scheme ss x,
    scalarmult := fun ba x => scalarmult scheme ba x,
    curve := fun a b => curve scheme a b
  }


end CryptWalker.nike.MontgomeryLadder

/-
SPDX-FileCopyrightText: © 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/
import Mathlib.Algebra.Field.Defs
import Mathlib.Algebra.Field.Basic
import Mathlib.Data.ZMod.Basic
import Mathlib.NumberTheory.LucasPrimality

import CryptWalker.Util.newnat
import CryptWalker.Util.newhex
import CryptWalker.NIKE.NIKE

open CryptWalker.Util.newnat
open CryptWalker.NIKE.NIKE

namespace CryptWalker.NIKE.X25519

def p : ℕ := 2^255 - 19
instance : NeZero p := ⟨by norm_num [p]⟩

def basepoint : ZMod p := 9
abbrev keySize : ℕ := 32

/-- Little-endian byte decoding, with bit 255 masked per RFC 7748. -/
def toField (v : Vector UInt8 keySize) : ZMod p :=
  let masked := v.set 31 (v[31] &&& 0x7f)
  (List.range keySize).foldr (fun i acc => acc * 256 + (masked[i]!).toNat) 0

/-- Little-endian byte encoding, exactly 32 bytes by construction. -/
def fromField (x : ZMod p) : Vector UInt8 keySize :=
  Vector.ofFn (fun i : Fin keySize => (x.val >>> (8 * i.val)).toUInt8)

/-- RFC 7748 clamping: clear the low three bits, clear bit 255, set bit 254. -/
def clampScalar (v : Vector UInt8 keySize) : Vector UInt8 keySize :=
  let v1 := v.set 0  (v[0]  &&& 0xf8)
  v1.set 31 ((v1[31] &&& 0x7f) ||| 0x40)

def basepointBytes : Vector UInt8 keySize := fromField basepoint

structure LadderState where
  x1 : ZMod p
  x2 : ZMod p
  z2 : ZMod p
  x3 : ZMod p
  z3 : ZMod p

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

/-- The ladder consumes the scalar as *bytes*, not as a `ZMod p`.

Taking a `ZMod p` here and calling `fromField` to get the bits back was a correctness bug: a
clamped scalar lies in `[2^254, 2^255)` and can exceed `p = 2^255 - 19`, so the round trip
through the field reduced it modulo the field prime. A scalar reduces modulo the *group order*,
never modulo `p`. It affected the two clamped values above `p` -- `2^255 - 16` and `2^255 - 8`
-- and was found by cross-checking against `X25519_math.Scheme`, which computes in the group
and does not reduce. -/
def montgomery_ladder (e : Vector UInt8 keySize) (point : ZMod p) : Id LadderState :=
  do
    let mut state : LadderState := {
      x1 := point,
      x2 := 1,
      z2 := 0,
      x3 := point,
      z3 := 1
    }
    let mut swap := false
    for pos in (List.range 255).reverse do
      let b : Bool := ((e[pos / 8]!).toNat >>> (pos % 8)) &&& 1 == 1
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

def scalarmult (scalarBytes : Vector UInt8 keySize) (point : ZMod p) : ZMod p :=
  let finalState := montgomery_ladder (clampScalar scalarBytes) point
  finalState.x2 * finalState.z2⁻¹

def curve25519 (scalar point : Vector UInt8 keySize) : Vector UInt8 keySize :=
  fromField (scalarmult scalar (toField point))

/-
  NIKE types for x25519
-/

structure PrivateKey   where data : Vector UInt8 keySize
structure PublicKey    where data : Vector UInt8 keySize
structure SharedSecret where data : Vector UInt8 keySize

def derivePub (sk : PrivateKey) : PublicKey := ⟨curve25519 sk.data basepointBytes⟩

private def bytes32 (l : List UInt8) (h : l.length = keySize := by decide) :
    Vector UInt8 keySize := ⟨l.toArray, by simpa using h⟩

/-- Curve25519 small-order points, little-endian, per libsodium's `has_small_order`.
    Seven values; the high bit of byte 31 is masked before comparison, so each
    also covers its +2^255 variant. See eprint.iacr.org/2017/806. -/
def smallOrderPoints : List (Vector UInt8 keySize) := [
  -- 0 (order 4)
  bytes32 (List.replicate 32 0x00),
  -- 1 (order 1)
  bytes32 (0x01 :: List.replicate 31 0x00),
  -- order 8
  bytes32 [0xe0,0xeb,0x7a,0x7c,0x3b,0x41,0xb8,0xae,0x16,0x56,0xe3,0xfa,0xf1,0x9f,0xc4,0x6a,
           0xda,0x09,0x8d,0xeb,0x9c,0x32,0xb1,0xfd,0x86,0x62,0x05,0x16,0x5f,0x49,0xb8,0x00],
  -- order 8
  bytes32 [0x5f,0x9c,0x95,0xbc,0xa3,0x50,0x8c,0x24,0xb1,0xd0,0xb1,0x55,0x9c,0x83,0xef,0x5b,
           0x04,0x44,0x5c,0xc4,0x58,0x1c,0x8e,0x86,0xd8,0x22,0x4e,0xdd,0xd0,0x9f,0x11,0x57],
  -- p-1 (order 2)
  bytes32 (0xec :: List.replicate 30 0xff ++ [0x7f]),
  -- p (=0, order 4)
  bytes32 (0xed :: List.replicate 30 0xff ++ [0x7f]),
  -- p+1 (=1, order 1)
  bytes32 (0xee :: List.replicate 30 0xff ++ [0x7f])
]

/-- Clear the high bit of byte 31, as libsodium does before comparison. -/
def maskHighBit (v : Vector UInt8 keySize) : Vector UInt8 keySize :=
  v.set 31 (v[31] &&& 0x7f)

def SafePub (pk : PublicKey) : Prop := maskHighBit pk.data ∉ smallOrderPoints


instance : DecidablePred SafePub := fun pk => by
  unfold SafePub; infer_instance

axiom derivePub_safe : ∀ sk : PrivateKey, SafePub (derivePub sk)

axiom curve25519_commutes : ∀ sk₁ sk₂ : PrivateKey,
  curve25519 sk₁.data (derivePub sk₂).data = curve25519 sk₂.data (derivePub sk₁).data

def SchemeName := "X25519-ladder"

def LadderScheme : NIKE where
  PrivateKey   := PrivateKey
  PublicKey    := PublicKey
  SharedSecret := SharedSecret

  name := SchemeName
  privateKeySize   := keySize
  publicKeySize    := keySize
  sharedSecretSize := keySize

  Safe    := SafePub
  decSafe := inferInstance

  privateKeyFromSeed := fun seed => ⟨clampScalar seed⟩
  derivePublicKey    := derivePub
  groupAction        := fun sk pk _ => ⟨curve25519 sk.data pk.data⟩

  encodePrivateKey   := fun sk => sk.data
  decodePrivateKey   := fun v => some ⟨v⟩
  encodePublicKey    := fun pk => pk.data
  decodePublicKey    := fun v => some ⟨v⟩
  encodeSharedSecret := fun ss => ss.data

  derive_safe        := derivePub_safe
  decode_encode_priv := fun _ => rfl
  decode_encode_pub  := fun _ => rfl
  encode_decode_pub  := fun _ _ h => congrArg PublicKey.data (Option.some.inj h) ▸ rfl
  commutes           := fun sk₁ sk₂ => congrArg SharedSecret.mk (curve25519_commutes sk₁ sk₂)

end CryptWalker.NIKE.X25519

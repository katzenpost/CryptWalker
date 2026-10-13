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
import CryptWalker.NIKE.X25519Common
import CryptWalker.NIKE.Field25519

open CryptWalker.Util.newnat
open CryptWalker.NIKE.NIKE
open CryptWalker.NIKE.X25519Common

namespace CryptWalker.NIKE.X25519_montgomery_ladder

/-- Little-endian byte encoding, exactly 32 bytes. -/
def fromField (x : ZMod p) : Vector UInt8 keySize :=
  Vector.ofFn (fun i : Fin keySize => (x.val >>> (8 * i.val)).toUInt8)

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

/-- The ladder takes the scalar as bytes: a clamped scalar can exceed `p`, so it must not be
reduced modulo `p`. -/
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

/-- RFC 7748 X25519. Total: the ladder is defined on every u-coordinate, including twist
points. -/
def x25519 (scalarBytes uCoordBytes : Vector UInt8 keySize) : Vector UInt8 keySize :=
  curve25519 scalarBytes uCoordBytes

/-! ## The same ladder on `Field25519.Fe`

The ladder on fixed-width limbs, with masked swaps so it does not branch on scalar bits. Tested
against the `ZMod` ladder and RFC 7748 vectors, not yet proved equal to it. -/

open CryptWalker.NIKE.Field25519 (Fe)

structure LadderStateFe where
  x1 : Fe
  x2 : Fe
  z2 : Fe
  x3 : Fe
  z3 : Fe

def montgomery_step_fe (s : LadderStateFe) : LadderStateFe :=
  let tmp0 := s.x3.sub s.z3
  let tmp1 := s.x2.sub s.z2
  let x2 := s.x2.add s.z2
  let z2 := s.x3.add s.z3
  let z3 := tmp0.mul x2
  let z2 := z2.mul tmp1
  let tmp0 := tmp1.sq
  let tmp1 := x2.sq
  let x3 := z3.add z2
  let z2 := z3.sub z2
  let x2 := tmp1.mul tmp0
  let tmp1 := tmp1.sub tmp0
  let z2 := z2.sq
  let z3 := tmp1.mulSmall 121666
  let x3 := x3.sq
  let tmp0 := tmp0.add z3
  let z3 := s.x1.mul z2
  let z2 := tmp1.mul tmp0
  { s with x2 := x2, z2 := z2, x3 := x3, z3 := z3 }

def montgomery_ladder_fe (e : Vector UInt8 keySize) (point : Fe) : LadderStateFe := Id.run do
  let mut state : LadderStateFe := { x1 := point, x2 := Fe.one, z2 := Fe.zero, x3 := point, z3 := Fe.one }
  let mut swap : UInt64 := 0
  for k in [0:255] do
    let pos := 254 - k
    let b : UInt64 := ((e[pos / 8]!).toUInt64 >>> (pos % 8).toUInt64) &&& 1
    let s := swap ^^^ b
    let (x2, x3) := Fe.cswap s state.x2 state.x3
    let (z2, z3) := Fe.cswap s state.z2 state.z3
    state := montgomery_step_fe { state with x2, x3, z2, z3 }
    swap := b
  let (x2, x3) := Fe.cswap swap state.x2 state.x3
  let (z2, z3) := Fe.cswap swap state.z2 state.z3
  return { state with x2, x3, z2, z3 }

def scalarmult_fe (scalarBytes : Vector UInt8 keySize) (point : Fe) : Fe :=
  let s := montgomery_ladder_fe (clampScalar scalarBytes) point
  s.x2.mul s.z2.invert

def curve25519_fe (scalar point : Vector UInt8 keySize) : Vector UInt8 keySize :=
  (scalarmult_fe scalar (Fe.ofBytes point)).toBytes

/- NIKE types for X25519. -/

structure PublicKey    where data : Vector UInt8 keySize
structure SharedSecret where data : Vector UInt8 keySize

def derivePub (sk : PrivateKey) : PublicKey := ⟨curve25519 sk.data basepointBytes⟩

private def bytes32 (l : List UInt8) (h : l.length = keySize := by decide) :
    Vector UInt8 keySize := ⟨l.toArray, by simpa using h⟩

/-- Curve25519 small-order points, little-endian. Compared after masking the high bit of byte 31,
so each also covers its `+2^255` variant. See eprint.iacr.org/2017/806. -/
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

/-- Clear the high bit of byte 31. -/
def maskHighBit (v : Vector UInt8 keySize) : Vector UInt8 keySize :=
  v.set 31 (v[31] &&& 0x7f)

def SafePub (pk : PublicKey) : Prop := maskHighBit pk.data ∉ smallOrderPoints


instance : DecidablePred SafePub := fun pk => by
  unfold SafePub; infer_instance

axiom derivePub_safe : ∀ sk : PrivateKey, SafePub (derivePub sk)

axiom curve25519_commutes : ∀ sk₁ sk₂ : PrivateKey,
  curve25519 sk₁.data (derivePub sk₂).data = curve25519 sk₂.data (derivePub sk₁).data

/-- The ladder's output is never a small-order point: clamping makes every scalar a multiple of
the cofactor 8. -/
axiom curve25519_safe : ∀ (sk : PrivateKey) (pk : PublicKey),
  SafePub (⟨curve25519 sk.data pk.data⟩ : PublicKey)

/-- Group actions by two private keys commute on any public key, not only on derived ones as in
`curve25519_commutes`. -/
axiom curve25519_comm_gen : ∀ (sk₁ sk₂ : PrivateKey) (pk : Vector UInt8 keySize),
  curve25519 sk₁.data (curve25519 sk₂.data pk) = curve25519 sk₂.data (curve25519 sk₁.data pk)

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
  groupAction        := fun sk spk => ⟨curve25519 sk.data spk.1.data⟩

  encodePrivateKey   := fun sk => sk.data
  decodePrivateKey   := fun v => some ⟨v⟩
  encodePublicKey    := fun pk => pk.data
  decodePublicKey    := fun v => some ⟨v⟩
  encodeSharedSecret := fun ss => ss.data

  derive_safe        := derivePub_safe
  decode_encode_priv := fun _ => rfl
  decodePrivateKey_total := fun v => ⟨⟨v⟩, rfl⟩
  decode_encode_pub  := fun _ => rfl
  encode_decode_pub  := fun _ _ h => congrArg PublicKey.data (Option.some.inj h) ▸ rfl
  commutes           := fun sk₁ sk₂ => congrArg SharedSecret.mk (curve25519_commutes sk₁ sk₂)
  reinterpret        := fun ss => ⟨ss.data⟩
  reinterpret_safe   := fun sk spk => curve25519_safe sk spk.1
  groupAction_comm   := fun sk₁ sk₂ spk => congrArg SharedSecret.mk (curve25519_comm_gen sk₁ sk₂ spk.1.data)
  publicKeySize_eq_sharedSecretSize := rfl
  encodePublicKey_reinterpret := fun _ => rfl

/-! ## The ladder on `Field25519` limbs, as a NIKE

`LadderScheme` with `curve25519_fe` in place of `curve25519`. Its axioms restate the ladder's for
`curve25519_fe`; proving `curve25519_fe = curve25519` would remove them. -/

def derivePubFe (sk : PrivateKey) : PublicKey := ⟨curve25519_fe sk.data basepointBytes⟩

axiom derivePubFe_safe : ∀ sk : PrivateKey, SafePub (derivePubFe sk)

axiom curve25519_fe_commutes : ∀ sk₁ sk₂ : PrivateKey,
  curve25519_fe sk₁.data (derivePubFe sk₂).data = curve25519_fe sk₂.data (derivePubFe sk₁).data

axiom curve25519_fe_safe : ∀ (sk : PrivateKey) (pk : PublicKey),
  SafePub (⟨curve25519_fe sk.data pk.data⟩ : PublicKey)

axiom curve25519_fe_comm_gen : ∀ (sk₁ sk₂ : PrivateKey) (pk : Vector UInt8 keySize),
  curve25519_fe sk₁.data (curve25519_fe sk₂.data pk) = curve25519_fe sk₂.data (curve25519_fe sk₁.data pk)

def FeSchemeName := "X25519"

def FeScheme : NIKE where
  PrivateKey   := PrivateKey
  PublicKey    := PublicKey
  SharedSecret := SharedSecret

  name := FeSchemeName
  privateKeySize   := keySize
  publicKeySize    := keySize
  sharedSecretSize := keySize

  Safe    := SafePub
  decSafe := inferInstance

  privateKeyFromSeed := fun seed => ⟨clampScalar seed⟩
  derivePublicKey    := derivePubFe
  groupAction        := fun sk spk => ⟨curve25519_fe sk.data spk.1.data⟩

  encodePrivateKey   := fun sk => sk.data
  decodePrivateKey   := fun v => some ⟨v⟩
  encodePublicKey    := fun pk => pk.data
  decodePublicKey    := fun v => some ⟨v⟩
  encodeSharedSecret := fun ss => ss.data

  derive_safe        := derivePubFe_safe
  decode_encode_priv := fun _ => rfl
  decodePrivateKey_total := fun v => ⟨⟨v⟩, rfl⟩
  decode_encode_pub  := fun _ => rfl
  encode_decode_pub  := fun _ _ h => congrArg PublicKey.data (Option.some.inj h) ▸ rfl
  commutes           := fun sk₁ sk₂ => congrArg SharedSecret.mk (curve25519_fe_commutes sk₁ sk₂)
  reinterpret        := fun ss => ⟨ss.data⟩
  reinterpret_safe   := fun sk spk => curve25519_fe_safe sk spk.1
  groupAction_comm   := fun sk₁ sk₂ spk => congrArg SharedSecret.mk (curve25519_fe_comm_gen sk₁ sk₂ spk.1.data)
  publicKeySize_eq_sharedSecretSize := rfl
  encodePublicKey_reinterpret := fun _ => rfl

end CryptWalker.NIKE.X25519_montgomery_ladder

/-
SPDX-FileCopyrightText: © 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.AlgebraicGeometry.EllipticCurve.Affine.Point
import Mathlib.Algebra.Field.Defs
import Mathlib.Algebra.Field.Basic
import Mathlib.Data.ZMod.Basic
import Mathlib.Data.Nat.Digits.Lemmas
import Mathlib.NumberTheory.LucasPrimality

import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.X25519Common

/-!
# X25519 as a group operation

The group action here *is* scalar multiplication on Curve25519, so `NIKE.commutes` is
`Nat.mul_comm` and nothing else. Contrast `CryptWalker.NIKE.X25519_montgomery_ladder.LadderScheme`,
which implements the same exchange as a Montgomery ladder over byte strings and has to take
commutativity as an axiom.

Curve25519, `y² = x³ + 486662x² + x`, is already a Weierstrass equation in long form
(`a₁ = a₃ = a₆ = 0`, `a₂ = 486662`, `a₄ = 1`), so the group — associativity included — comes
from Mathlib's `WeierstrassCurve.Affine.Point` rather than being defined here. Everything is
computable: `n • P` runs in the interpreter, so this is an implementation and not only a model.

Public keys are group elements, encoded as 65 bytes `0x04 ‖ x ‖ y` with both coordinates
little-endian, or 65 zero bytes for the point at infinity. Carrying `y` is what makes decoding
a left inverse of encoding. The 32-byte u-coordinate interface of RFC 7748 is provided
separately by `x25519`, which recovers a `y` by square root.

`X25519Common` is what this file and `X25519_montgomery_ladder` actually share: the field
prime, RFC 7748 byte encoding and clamping, and the private-key shape. Nothing else about the
two implementations is coupled.

The single unproved statement in this file is the axiom `p_prime`.
-/

namespace CryptWalker.NIKE.X25519

open CryptWalker.NIKE.NIKE
open CryptWalker.NIKE.X25519Common

/-! ### The base field -/

/-- `2^255 - 19` is prime.

Taken as an axiom. Mathlib's `lucas_primality` is the tool that would remove it: `p - 1 =
2² · 3 · 65147 · 74058212732561358302231226437062788676166966415465897661863160754340907`, so a
Pratt certificate discharges it, but that needs a recursive certificate for the 233-bit factor
and an efficient modular-exponentiation tactic. Nothing below depends on how it is closed, only
on `Fact p.Prime` making `ZMod p` a field. -/
axiom p_prime : Nat.Prime p

instance : Fact (Nat.Prime p) := ⟨p_prime⟩

lemma p_lt_pow : p < 256 ^ 32 := by norm_num [p]

private lemma natCast_ne_zero_of_lt {n : ℕ} (h0 : n ≠ 0) (hlt : n < p) :
    ((n : ℕ) : ZMod p) ≠ 0 := by
  rw [Ne, ZMod.natCast_eq_zero_iff]
  exact fun hdvd => absurd (Nat.le_of_dvd (Nat.pos_of_ne_zero h0) hdvd) (by omega)

/-! ### The group

Mathlib supplies the group law and its associativity; there is nothing to define beyond the
coefficients. -/

/-- Curve25519 `y² = x³ + 486662x² + x` as a Weierstrass curve in affine coordinates. -/
def curve : WeierstrassCurve.Affine (ZMod p) where
  a₁ := 0
  a₂ := 486662
  a₃ := 0
  a₄ := 1
  a₆ := 0

/-- The points of Curve25519: the point at infinity together with the affine solutions of the
curve equation. Carries `AddCommGroup` from Mathlib. -/
abbrev Point := curve.Point

example : AddCommGroup Point := inferInstance

/-- The curve equation, in the form a program can check. -/
def onCurve (x y : ZMod p) : Prop := y ^ 2 = x ^ 3 + 486662 * x ^ 2 + x

instance decidableOnCurve (x y : ZMod p) : Decidable (onCurve x y) :=
  inferInstanceAs (Decidable (_ = _))

lemma equation_iff {x y : ZMod p} : curve.Equation x y ↔ onCurve x y := by
  rw [WeierstrassCurve.Affine.equation_iff]
  simp only [curve, onCurve]
  constructor <;> intro h <;> linear_combination h

lemma curve_Δ_ne_zero : curve.Δ ≠ 0 := by
  have h : curve.Δ = ((3789438435840 : ℕ) : ZMod p) := by
    simp only [WeierstrassCurve.Δ, WeierstrassCurve.b₂, WeierstrassCurve.b₄,
      WeierstrassCurve.b₆, WeierstrassCurve.b₈, curve]
    push_cast
    norm_num
  rw [h]
  exact natCast_ne_zero_of_lt (by norm_num) (by norm_num [p])

/-- Curve25519 is nonsingular, so lying on it is the whole condition for being a point. -/
lemma nonsingular_iff_onCurve {x y : ZMod p} : curve.Nonsingular x y ↔ onCurve x y :=
  (WeierstrassCurve.Affine.equation_iff_nonsingular_of_Δ_ne_zero curve_Δ_ne_zero).symm.trans
    equation_iff

/-- Build a point from coordinates that pass the curve check. -/
def mkPoint {x y : ZMod p} (h : onCurve x y) : Point :=
  .some x y (nonsingular_iff_onCurve.mpr h)

/-- The x-coordinate, `0` at infinity — matching what a Montgomery ladder returns there. -/
def xCoord : Point → ZMod p
  | .zero => 0
  | .some x _ _ => x

/-! ### The basepoint -/

/-- The `y`-coordinate of the standard basepoint `x = 9`, as a natural number. -/
def basepointYNat : ℕ :=
  14781619447589544791020593568409986887264606134616475288964881837755586237401

/-- The `y`-coordinate of the standard basepoint `x = 9`. -/
def basepointY : ZMod p := (basepointYNat : ℕ)

lemma basepoint_onCurve : onCurve basepoint basepointY := by
  have hrhs : ((9 ^ 3 + 486662 * 9 ^ 2 + 9 : ℕ) : ZMod p)
      = basepoint ^ 3 + 486662 * basepoint ^ 2 + basepoint := by
    simp only [basepoint]
    push_cast
    ring
  show basepointY ^ 2 = _
  rw [basepointY, ← Nat.cast_pow, ← hrhs, ZMod.natCast_eq_natCast_iff']
  norm_num [basepointYNat, p]

/-- The standard basepoint of X25519, as a group element. -/
def G : Point := mkPoint basepoint_onCurve

/-! ### Commutativity

The reason X25519 is a NIKE at all. In the group it is one rewrite — no axiom, unlike the
ladder implementation's `curve25519_commutes`. -/

/-- **The Diffie-Hellman identity.** -/
theorem dh_commutes (a b : ℕ) (P : Point) : a • (b • P) = b • (a • P) := by
  rw [smul_smul, smul_smul, Nat.mul_comm]

/-! ### Encoding field elements

32 bytes, little-endian, as base-256 digits. Using `Nat.digits` keeps the round-trip proof to
`Nat.ofDigits_digits`. -/

/-- A field element as 32 little-endian bytes. -/
def encodeField (z : ZMod p) : List UInt8 :=
  (Nat.digits 256 z.val ++ List.replicate (32 - (Nat.digits 256 z.val).length) 0).map UInt8.ofNat

/-- Little-endian bytes back to a field element. -/
def decodeField (bs : List UInt8) : ZMod p := (Nat.ofDigits 256 (bs.map UInt8.toNat) : ℕ)

lemma digits_length_le (z : ZMod p) : (Nat.digits 256 z.val).length ≤ 32 :=
  (Nat.digits_length_le_iff (by norm_num) z.val).mpr (lt_trans (ZMod.val_lt z) p_lt_pow)

@[simp] lemma encodeField_length (z : ZMod p) : (encodeField z).length = 32 := by
  have h := digits_length_le z
  simp only [encodeField, List.length_map, List.length_append, List.length_replicate]
  omega

@[simp] lemma decodeField_encodeField (z : ZMod p) : decodeField (encodeField z) = z := by
  have hdigits : ∀ d ∈ Nat.digits 256 z.val ++
      List.replicate (32 - (Nat.digits 256 z.val).length) 0, d < 256 := by
    intro d hd
    rcases List.mem_append.mp hd with h | h
    · exact Nat.digits_lt_base (by norm_num) h
    · simpa using (List.eq_of_mem_replicate h).le.trans_lt (by norm_num)
  have hmap : ((Nat.digits 256 z.val ++
      List.replicate (32 - (Nat.digits 256 z.val).length) 0).map UInt8.ofNat).map UInt8.toNat
      = Nat.digits 256 z.val ++ List.replicate (32 - (Nat.digits 256 z.val).length) 0 := by
    rw [List.map_map]
    refine (List.map_congr_left (g := id) fun d hd => ?_).trans (List.map_id _)
    simpa using UInt8.toNat_ofNat_of_lt' (hdigits d hd)
  rw [decodeField, encodeField, hmap, Nat.ofDigits_append_replicate_zero, Nat.ofDigits_digits]
  simp

/-! ### Encoding points

`0x04 ‖ x ‖ y`, or 65 zero bytes for the point at infinity. -/

def encodePoint : Point → List UInt8
  | .zero => 0 :: List.replicate 64 0
  | .some x y _ => 4 :: (encodeField x ++ encodeField y)

@[simp] lemma encodePoint_length (P : Point) : (encodePoint P).length = 65 := by
  cases P with
  | zero => simp [encodePoint]
  | some x y h => simp [encodePoint]

/-- Parse, without yet insisting the encoding was canonical. -/
def decodePointRaw : List UInt8 → Option Point
  | [] => none
  | tag :: rest =>
    if tag = 4 then
      if rest.length = 64 then
        let x := decodeField (rest.take 32)
        let y := decodeField (rest.drop 32)
        if h : onCurve x y then some (mkPoint h) else none
      else none
    else if tag = 0 then some 0
    else none

@[simp] lemma decodePointRaw_encodePoint (P : Point) :
    decodePointRaw (encodePoint P) = some P := by
  cases P with
  | zero => rfl
  | some x y h =>
    have hx : (encodeField x).length = 32 := encodeField_length x
    have hlen : (encodeField x ++ encodeField y).length = 64 := by simp
    rw [encodePoint, decodePointRaw]
    rw [if_pos rfl, if_pos hlen, List.take_left' hx, List.drop_left' hx,
      decodeField_encodeField, decodeField_encodeField, dif_pos (nonsingular_iff_onCurve.mp h)]
    rfl

/-- Parse and then insist the input was exactly what this point encodes to.

The guard is what makes the encoding *canonical*, and it buys both of the interface's
round-trip laws from one decidable check. Without it `NIKE.encode_decode_pub` would be false:
`decodeField` reduces modulo `p`, so a 32-byte coordinate whose value is at least `p` would
decode to a point that re-encodes to different bytes. -/
def decodePoint (bs : List UInt8) : Option Point :=
  (decodePointRaw bs).bind fun P => if encodePoint P = bs then some P else none

@[simp] lemma decodePoint_encodePoint (P : Point) : decodePoint (encodePoint P) = some P := by
  simp [decodePoint, decodePointRaw_encodePoint]

lemma encodePoint_of_decodePoint {bs : List UInt8} {P : Point}
    (h : decodePoint bs = some P) : encodePoint P = bs := by
  unfold decodePoint at h
  cases hraw : decodePointRaw bs with
  | none => rw [hraw] at h; simp at h
  | some Q =>
    rw [hraw] at h
    simp only [Option.bind_some] at h
    split at h
    · next hguard => exact (Option.some.inj h) ▸ hguard
    · simp at h

/-! ### The NIKE scheme -/

/-- The clamped scalar of a private key, as a natural number.

Deliberately *not* routed through `ZMod p`: clamping leaves the value in `[2^254, 2^255)`, which
can exceed `p = 2^255 - 19`, and reducing a scalar modulo the *field* prime is wrong — the group
order is what a scalar reduces modulo. `X25519_montgomery_ladder.scalarmult` does route it through `ZMod p`, so the
two implementations disagree for the handful of clamped scalars above `p`. -/
def scalarOf (sk : PrivateKey) : ℕ :=
  Nat.ofDigits 256 ((clampScalar sk.data).toList.map UInt8.toNat)

def publicKeySize : ℕ := 65

def encodePublicKey (P : Point) : Vector UInt8 publicKeySize :=
  ⟨(encodePoint P).toArray, by simp [publicKeySize]⟩

def decodePublicKey (v : Vector UInt8 publicKeySize) : Option Point := decodePoint v.toList

def encodeSharedSecret (z : ZMod p) : Vector UInt8 32 :=
  ⟨(encodeField z).toArray, by simp⟩

/-- Scalar multiplication in the group is total, so there is no public key on which the group
action is undefined and `Safe` is `True`.

That is a real difference from `X25519_montgomery_ladder.LadderScheme`, whose `Safe` rejects the small-order
points. Rejecting them is about *contributory behaviour* — ensuring a peer cannot force a
predictable shared secret — which is a security property this model does not express, rather
than a definedness requirement. -/
def Scheme : NIKE where
  PrivateKey   := PrivateKey
  PublicKey    := Point
  SharedSecret := ZMod p

  name := "X25519-group"
  privateKeySize   := keySize
  publicKeySize    := publicKeySize
  sharedSecretSize := 32

  Safe    := fun _ => True
  decSafe := fun _ => isTrue trivial

  privateKeyFromSeed := fun seed => ⟨clampScalar seed⟩
  derivePublicKey    := fun sk => scalarOf sk • G
  groupAction        := fun sk pk _ => xCoord (scalarOf sk • pk)

  encodePrivateKey   := fun sk => sk.data
  decodePrivateKey   := fun v => some ⟨v⟩
  encodePublicKey    := encodePublicKey
  decodePublicKey    := decodePublicKey
  encodeSharedSecret := encodeSharedSecret

  derive_safe        := fun _ => trivial
  decode_encode_priv := fun _ => rfl
  -- `Vector.toList` of a `Vector.mk` built from `List.toArray` is the list itself, by `rfl`,
  -- so both laws reduce to the statements already proved about `encodePoint`/`decodePoint`.
  decode_encode_pub  := fun pk => decodePoint_encodePoint pk
  encode_decode_pub  := by
    intro v pk h
    apply Vector.toArray_inj.mp
    show (encodePoint pk).toArray = v.toArray
    rw [encodePoint_of_decodePoint h]
    exact Array.toArray_toList
  commutes           := fun sk₁ sk₂ => congrArg xCoord (dh_commutes _ _ G)

/-! ### RFC 7748 interface

X25519 on the wire exchanges 32-byte u-coordinates, not points, so `y` has to be recovered by a
square root. `p ≡ 5 mod 8`, so a root of `a` is `a^((p+3)/8)`, possibly times `√-1`. Nothing here
is assumed: the candidate is checked against the curve equation, and `liftX` returns `none` if it
fails — which is also what happens for a `u` on the quadratic twist. -/

/-- Binary modular exponentiation. `ZMod`'s own `^` unfolds to unary recursion, which does not
terminate in practice at this size. -/
private def powAux (base : ZMod p) (e : ℕ) : ZMod p :=
  if _h : e = 0 then 1
  else
    let half := powAux (base * base) (e / 2)
    if e % 2 = 1 then base * half else half
termination_by e
decreasing_by exact Nat.div_lt_self (Nat.pos_of_ne_zero _h) (by norm_num)

/-- `√-1` in `ZMod p`, i.e. `2^((p-1)/4)`. -/
def sqrtMinusOne : ZMod p :=
  ((19681161376707505956807079304988542015446066515923890162744021073123829784752 : ℕ) : ZMod p)

/-- Recover a point from its u-coordinate, or `none` if `u` is on the quadratic twist. The result
is checked, so a wrong square root can only cause `none`, never a bad point. -/
def liftX (x : ZMod p) : Option Point :=
  let rhs := x ^ 3 + 486662 * x ^ 2 + x
  let v := powAux rhs ((p + 3) / 8)
  let y := if v ^ 2 = rhs then v else v * sqrtMinusOne
  if h : onCurve x y then some (mkPoint h) else none

/-- A u-coordinate as 32 little-endian bytes. -/
def uBytes (P : Point) : Vector UInt8 32 := encodeSharedSecret (xCoord P)

/-- **X25519**, RFC 7748 signature: a 32-byte scalar and a 32-byte u-coordinate to a 32-byte
u-coordinate, computed as scalar multiplication in the group. `none` exactly when the input
u-coordinate is not on the curve. -/
def x25519 (scalarBytes uCoordBytes : Vector UInt8 32) : Option (Vector UInt8 32) :=
  (liftX (toField uCoordBytes)).map fun P =>
    uBytes (Nat.ofDigits 256 ((clampScalar scalarBytes).toList.map UInt8.toNat) • P)

end CryptWalker.NIKE.X25519

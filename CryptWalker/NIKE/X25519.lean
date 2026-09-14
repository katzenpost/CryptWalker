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

Points are still encoded internally as 65 bytes `0x04 ‖ x ‖ y` (`encodePoint`/`decodePoint`,
with both coordinates little-endian, or 65 zero bytes for the point at infinity — carrying `y` is
what makes decoding a left inverse of encoding), but the `NIKE` instance `Scheme` below instead
uses the 32-byte RFC 7748 u-coordinate format — the same format
`X25519_montgomery_ladder.LadderScheme` uses — recovering `y` from `x` by square root via `liftX`.
Matching formats is what lets a shared secret double as the next hop's public key generically, as
`Sphinx.NIKESphinx` needs.

`X25519Common` is what this file and `X25519_montgomery_ladder` actually share: the field
prime, RFC 7748 byte encoding and clamping, and the private-key shape. Nothing else about the
two implementations is coupled.

Two statements in this file are taken as axioms rather than proved: `p_prime`, and
`liftX_isSome_of_exists` (the `p ≡ 5 mod 8` square-root algorithm always succeeds on a genuine
quadratic residue — standard number theory, but long enough to state rather than reproduce here).
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

/-- The candidate `y`, before it's checked against the curve equation. Factored out of `liftX` so
`liftX` itself is a bare `dite` — easy for `split`/`split_ifs` to see through, unlike a `dite`
behind `let`s. -/
private def liftXCandidateY (x : ZMod p) : ZMod p :=
  let rhs := x ^ 3 + 486662 * x ^ 2 + x
  let v := powAux rhs ((p + 3) / 8)
  if v ^ 2 = rhs then v else v * sqrtMinusOne

/-- Recover a point from its u-coordinate, or `none` if `u` is on the quadratic twist. The result
is checked, so a wrong square root can only cause `none`, never a bad point. -/
def liftX (x : ZMod p) : Option Point :=
  if h : onCurve x (liftXCandidateY x) then some (mkPoint h) else none

/-- **`liftX` succeeds on every genuine curve x-coordinate.**

The forward direction — a candidate that checks out really is on the curve — is proved inline in
`liftX`'s own `dif`. This is the converse: the `p ≡ 5 mod 8` square-root algorithm never spuriously
fails to find a root when one exists. That is standard (Euler's criterion identifies which of `v`,
`v * sqrtMinusOne` is the root, given `rhs` is a square), but the calculation is long enough that,
like `p_prime`, it is taken as given rather than reproduced here. -/
axiom liftX_isSome_of_exists {x : ZMod p} : (∃ y, onCurve x y) → (liftX x).isSome = true

/-- Whatever point `liftX` returns, its x-coordinate is the one asked for — immediate from
`liftX`'s own definition, which only ever builds `mkPoint` at the input `x`. -/
lemma xCoord_of_liftX_eq_some {x : ZMod p} {Q : Point} (hQ : liftX x = some Q) : xCoord Q = x := by
  unfold liftX at hQ
  split at hQ
  · injection hQ with hQ
    subst hQ
    rfl
  · exact absurd hQ (by simp)

/-! ### The NIKE scheme

Public keys are 32-byte u-coordinates — the RFC 7748 wire format, and the same format
`X25519_montgomery_ladder.LadderScheme` uses — not the 65-byte `0x04‖x‖y` point encoding
`encodePoint`/`decodePoint` above. This makes `PublicKey` and `SharedSecret` the same type
(`ZMod p`, an x-coordinate), which is what lets a caller like `Sphinx.NIKESphinx` treat a shared
secret as the next hop's public key generically: for a Diffie-Hellman-style NIKE that
reinterpretation only typechecks when the two coincide, and nothing in the abstract `NIKE`
structure otherwise guarantees it. -/

/-- The clamped scalar of a private key, as a natural number.

Deliberately *not* routed through `ZMod p`: clamping leaves the value in `[2^254, 2^255)`, which
can exceed `p = 2^255 - 19`, and reducing a scalar modulo the *field* prime is wrong — the group
order is what a scalar reduces modulo. `X25519_montgomery_ladder.scalarmult` does route it through `ZMod p`, so the
two implementations disagree for the handful of clamped scalars above `p`. -/
def scalarOf (sk : PrivateKey) : ℕ :=
  Nat.ofDigits 256 ((clampScalar sk.data).toList.map UInt8.toNat)

/-- An x-coordinate is *safe* exactly when some `y` makes it a real point, i.e. it isn't on the
quadratic twist — `liftX` already computes that candidate-and-check, so `Safe` just asks whether
it succeeded. -/
def SafeX (x : ZMod p) : Prop := (liftX x).isSome = true

instance : DecidablePred SafeX := fun _x => inferInstanceAs (Decidable (_ = true))

/-- Recover the point a safe x-coordinate represents. -/
def toPoint (x : ZMod p) (h : SafeX x) : Point := (liftX x).get h

/-- `toPoint` recovers *a* point with the given x-coordinate — not necessarily the same point a
caller had in mind, since a curve point isn't determined by its x-coordinate alone, but that's all
`groupActionX`/`commutes` below ever need. -/
lemma xCoord_toPoint (x : ZMod p) (h : SafeX x) : xCoord (toPoint x h) = x :=
  xCoord_of_liftX_eq_some (Option.some_get h).symm

def groupActionX (sk : PrivateKey) (x : ZMod p) (h : SafeX x) : ZMod p :=
  xCoord (scalarOf sk • toPoint x h)

def derivePublicKeyX (sk : PrivateKey) : ZMod p := xCoord (scalarOf sk • G)

/-- Any curve point's x-coordinate is, trivially, one that has *some* `y` making it a point. -/
lemma exists_onCurve_xCoord (P : Point) : ∃ y, onCurve (xCoord P) y := by
  cases P with
  | zero => exact ⟨0, by simp [onCurve, xCoord]⟩
  | some x y h => exact ⟨y, nonsingular_iff_onCurve.mp h⟩

/-- 32-byte little-endian encoding, canonical-checked exactly as `decodePoint` is above: without
the guard, `encode_decode_pub` would be false for a coordinate whose 32 bytes represent a value
`≥ p`, since `decodeField` reduces mod `p`. -/
def decodeFieldChecked (v : Vector UInt8 32) : Option (ZMod p) :=
  if (encodeField (decodeField v.toList)).toArray = v.toArray then some (decodeField v.toList)
  else none

def encodeFieldChecked (z : ZMod p) : Vector UInt8 32 := ⟨(encodeField z).toArray, by simp⟩

/-! ### Commutativity of `groupActionX`

`groupActionX` doesn't act on the original point directly, only on the x-coordinate handed to it
— it recovers *a* point via `toPoint` first, which need not be the exact point a caller had in
mind (a curve point isn't determined by its x-coordinate alone: the only other point sharing it
is the negation, or, in the one x = 0 edge case, a second, self-negating point at x = 0 distinct
from `Point.zero` itself even though `xCoord` maps both to `0`). Commutativity survives this
regardless: negation commutes with scalar multiplication and doesn't move the x-coordinate, and
the x = 0 point has order 2, so every scalar multiple of it still has x-coordinate `0`. -/

lemma xCoord_neg (P : Point) : xCoord (-P) = xCoord P := by
  cases P with
  | zero => rfl
  | some x y h => simp [xCoord, WeierstrassCurve.Affine.Point.neg_some]

/-- `n`-fold scalar multiplication distributes over negation, for the natural-number action on
any `AddCommGroup` — proved directly by induction rather than pulled from a generic `Module`/
`DistribMulAction` lemma, since those can disagree syntactically (though not propositionally)
with the plain `AddMonoid.nsmul` instance `•` above resolves to. -/
lemma nsmul_neg (P : Point) (n : ℕ) : n • (-P) = -(n • P) := by
  induction n with
  | zero => simp
  | succ k ih => rw [succ_nsmul, ih, succ_nsmul, neg_add]

/-- Same reasoning as `nsmul_neg`: proved directly to sidestep any `SMulZeroClass`-vs-`AddMonoid`
instance mismatch for the plain `•` used throughout this section. -/
lemma nsmul_zero_point (n : ℕ) : n • (0 : Point) = 0 := by
  induction n with
  | zero => simp
  | succ k ih => rw [succ_nsmul, ih, zero_add]

/-- The finite point `(0, 0)`, given it's on the curve. -/
def zeroZeroPoint (h : curve.Nonsingular (0 : ZMod p) 0) : Point := .some 0 0 h

/-- The point `(0, 0)` — the unique finite point with x-coordinate `0` — is its own negative. -/
lemma zeroZeroPoint_add_self (h : curve.Nonsingular (0 : ZMod p) 0) :
    zeroZeroPoint h + zeroZeroPoint h = 0 :=
  WeierstrassCurve.Affine.Point.add_self_of_Y_eq (by simp [WeierstrassCurve.Affine.negY, curve])

/-- Every scalar multiple of an order-≤-2 point (`R + R = 0`) is either `0` or `R`. -/
lemma nsmul_eq_zero_or_self {R : Point} (hRR : R + R = 0) (n : ℕ) : n • R = 0 ∨ n • R = R := by
  induction n with
  | zero => left; simp
  | succ k ih =>
    rcases ih with h0 | h1
    · right; rw [succ_nsmul, h0, zero_add]
    · left; rw [succ_nsmul, h1, hRR]

/-- Scalar multiples of the x = 0 point never leave x-coordinate `0`. -/
lemma xCoord_smul_zero {y : ZMod p} (h : curve.Nonsingular (0 : ZMod p) y) (n : ℕ) :
    xCoord (n • (WeierstrassCurve.Affine.Point.some (W' := curve) 0 y h)) = 0 := by
  have hy : y = 0 := by
    have honcurve : onCurve 0 y := nonsingular_iff_onCurve.mp h
    have hy2 : y ^ 2 = 0 := by simpa [onCurve] using honcurve
    exact pow_eq_zero_iff two_ne_zero |>.mp hy2
  subst hy
  show xCoord (n • zeroZeroPoint h) = 0
  rcases nsmul_eq_zero_or_self (zeroZeroPoint_add_self h) n with h0 | h1
  · rw [h0]; rfl
  · rw [h1]; rfl

/-- **The key lemma behind `commutes`**: scalar multiplication only sees a point's x-coordinate,
in the sense that the *x-coordinate of the result* doesn't depend on which of the (at most two)
points sharing an input x-coordinate you started from. -/
lemma xCoord_smul_congr (n : ℕ) {P Q : Point} (hPQ : xCoord P = xCoord Q) :
    xCoord (n • P) = xCoord (n • Q) := by
  cases P with
  | zero =>
    cases Q with
    | zero => rfl
    | some x y hq =>
      have hx : x = 0 := by simpa [xCoord] using hPQ.symm
      subst hx
      show xCoord (n • (0 : Point)) = xCoord (n • WeierstrassCurve.Affine.Point.some 0 y hq)
      rw [nsmul_zero_point]
      exact (xCoord_smul_zero hq n).symm
  | some x y hp =>
    cases Q with
    | zero =>
      have hx : x = 0 := by simpa [xCoord] using hPQ
      subst hx
      show xCoord (n • WeierstrassCurve.Affine.Point.some 0 y hp) = xCoord (n • (0 : Point))
      rw [nsmul_zero_point]
      exact xCoord_smul_zero hp n
    | some x' y' hq =>
      have hxx : x = x' := by simpa [xCoord] using hPQ
      subst hxx
      rcases (WeierstrassCurve.Affine.Point.X_eq_iff (h₁ := hp) (h₂ := hq)).mp rfl with heq | heq
      · rw [heq]
      · rw [heq, nsmul_neg, xCoord_neg]

/-- **The Diffie-Hellman identity, for `groupActionX`.** -/
lemma groupActionX_commutes (sk₁ sk₂ : PrivateKey)
    (h₁ : SafeX (derivePublicKeyX sk₁)) (h₂ : SafeX (derivePublicKeyX sk₂)) :
    groupActionX sk₁ (derivePublicKeyX sk₂) h₂ = groupActionX sk₂ (derivePublicKeyX sk₁) h₁ := by
  unfold groupActionX derivePublicKeyX
  have e₂ : xCoord (toPoint (xCoord (scalarOf sk₂ • G)) h₂) = xCoord (scalarOf sk₂ • G) :=
    xCoord_toPoint _ h₂
  have e₁ : xCoord (toPoint (xCoord (scalarOf sk₁ • G)) h₁) = xCoord (scalarOf sk₁ • G) :=
    xCoord_toPoint _ h₁
  calc xCoord (scalarOf sk₁ • toPoint (xCoord (scalarOf sk₂ • G)) h₂)
      = xCoord (scalarOf sk₁ • (scalarOf sk₂ • G)) := xCoord_smul_congr _ e₂
    _ = xCoord (scalarOf sk₂ • (scalarOf sk₁ • G)) := congrArg xCoord (dh_commutes _ _ G)
    _ = xCoord (scalarOf sk₂ • toPoint (xCoord (scalarOf sk₁ • G)) h₁) :=
        (xCoord_smul_congr _ e₁).symm

/-- `groupActionX`'s output is always safe: it's an actual curve point's x-coordinate by
construction (`toPoint`/`scalarOf sk • ·` never leave the curve), regardless of whether the input
`x` came from an honestly-derived public key or a previously-blinded group element. This is what
lets Sphinx's blinding chain apply *another* group action to the result. -/
lemma groupActionX_safe (sk : PrivateKey) (x : ZMod p) (h : SafeX x) : SafeX (groupActionX sk x h) :=
  liftX_isSome_of_exists (exists_onCurve_xCoord (scalarOf sk • toPoint x h))

/-- **The Diffie-Hellman identity, generalized to a re-blinded chain**: `groupActionX_commutes`
above is the special case `x := derivePublicKeyX sk₂`; this is what `createHeader`'s *iterated*
blinding chain needs beyond that, once later hops act on a previously-blinded (not freshly
re-derived) element — the exact same proof, since it never actually used that `x` was derived,
only that `toPoint x h` is *some* point sharing `x`'s x-coordinate. -/
lemma groupActionX_comm (sk₁ sk₂ : PrivateKey) (x : ZMod p) (h : SafeX x) :
    groupActionX sk₁ (groupActionX sk₂ x h) (groupActionX_safe sk₂ x h)
      = groupActionX sk₂ (groupActionX sk₁ x h) (groupActionX_safe sk₁ x h) := by
  unfold groupActionX
  have e₂ : xCoord (toPoint (xCoord (scalarOf sk₂ • toPoint x h)) (groupActionX_safe sk₂ x h))
      = xCoord (scalarOf sk₂ • toPoint x h) :=
    xCoord_toPoint _ (groupActionX_safe sk₂ x h)
  have e₁ : xCoord (toPoint (xCoord (scalarOf sk₁ • toPoint x h)) (groupActionX_safe sk₁ x h))
      = xCoord (scalarOf sk₁ • toPoint x h) :=
    xCoord_toPoint _ (groupActionX_safe sk₁ x h)
  calc xCoord (scalarOf sk₁ • toPoint (xCoord (scalarOf sk₂ • toPoint x h)) (groupActionX_safe sk₂ x h))
      = xCoord (scalarOf sk₁ • (scalarOf sk₂ • toPoint x h)) := xCoord_smul_congr _ e₂
    _ = xCoord (scalarOf sk₂ • (scalarOf sk₁ • toPoint x h)) := congrArg xCoord (dh_commutes _ _ _)
    _ = xCoord (scalarOf sk₂ • toPoint (xCoord (scalarOf sk₁ • toPoint x h)) (groupActionX_safe sk₁ x h)) :=
        (xCoord_smul_congr _ e₁).symm

def Scheme : NIKE where
  PrivateKey   := PrivateKey
  PublicKey    := ZMod p
  SharedSecret := ZMod p

  name := "X25519-group"
  privateKeySize   := keySize
  publicKeySize    := 32
  sharedSecretSize := 32

  Safe    := SafeX
  decSafe := inferInstance

  privateKeyFromSeed := fun seed => ⟨clampScalar seed⟩
  derivePublicKey    := derivePublicKeyX
  groupAction        := groupActionX

  encodePrivateKey   := fun sk => sk.data
  decodePrivateKey   := fun v => some ⟨v⟩
  encodePublicKey    := encodeFieldChecked
  decodePublicKey    := decodeFieldChecked
  encodeSharedSecret := encodeFieldChecked

  derive_safe        := fun sk =>
    liftX_isSome_of_exists (exists_onCurve_xCoord (scalarOf sk • G))
  decode_encode_priv := fun _ => rfl
  decode_encode_pub  := fun x => by
    show decodeFieldChecked (encodeFieldChecked x) = some x
    unfold decodeFieldChecked encodeFieldChecked
    simp
  encode_decode_pub  := by
    intro v x h
    unfold decodeFieldChecked at h
    split at h
    · rename_i heq
      injection h with h
      apply Vector.toArray_inj.mp
      show (encodeField x).toArray = v.toArray
      rw [← h]
      exact heq
    · simp at h
  commutes           := fun sk₁ sk₂ => groupActionX_commutes sk₁ sk₂ _ _
  reinterpret        := id
  reinterpret_safe   := groupActionX_safe
  groupAction_comm   := groupActionX_comm

/-- A u-coordinate as 32 little-endian bytes. -/
def uBytes (P : Point) : Vector UInt8 32 := encodeFieldChecked (xCoord P)

/-- **X25519**, RFC 7748 signature: a 32-byte scalar and a 32-byte u-coordinate to a 32-byte
u-coordinate, computed as scalar multiplication in the group. `none` exactly when the input
u-coordinate is not on the curve. -/
def x25519 (scalarBytes uCoordBytes : Vector UInt8 32) : Option (Vector UInt8 32) :=
  (liftX (toField uCoordBytes)).map fun P =>
    uBytes (Nat.ofDigits 256 ((clampScalar scalarBytes).toList.map UInt8.toNat) • P)

end CryptWalker.NIKE.X25519

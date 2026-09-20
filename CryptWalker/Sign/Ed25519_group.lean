/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Ed25519_math
import CryptWalker.NIKE.X25519

/-! # Ed25519's group, by transport from Curve25519

`Ed25519Math.Point` has no `AddCommGroup` instance: its addition law is the raw twisted-Edwards
formula, and proving associativity for it directly would mean formalizing Edwards-curve group
theory from scratch. But Ed25519 and Curve25519 are the same group — Ed25519 is, by construction,
a twisted Edwards curve birationally equivalent to Curve25519 — and `NIKE.X25519.Point` already
has a full `AddCommGroup` instance, inherited for free from Mathlib's `WeierstrassCurve.Affine`.
This file transports that structure across the birational map instead of re-deriving it.

The map, in both directions:

    Montgomery (u, v) ↦ Edwards (x, y) := (-c * u / v, (u - 1) / (u + 1))
    Edwards (x, y) ↦ Montgomery (u, v) := ((1 + y) / (1 - y), -c * u / x)

where `c := sqrtNeg486664` satisfies `c ^ 2 = -486664` — `486664 = 486662 + 2` is `X25519`'s curve
coefficient plus 2, and its negation is the constant this specific pair of curves needs (Ed25519 is
a *twisted* Edwards curve, `a = -1`; the untwisted case would use `sqrt 486664` instead). The
identity `(0, 1)` is the map's only exceptional point: every other Edwards point has `y ≠ 1`. -/

namespace CryptWalker.Sign.Ed25519Group

open CryptWalker.Sign.Ed25519Math (F p d onCurve Point)
open CryptWalker.NIKE.X25519 (curve)

/-- `sqrt(-486664)`, the constant the Edwards/Montgomery map for this pair of curves needs. -/
def sqrtNeg486664 : F :=
  (6853475219497561581579357271197624642482790079785650197046958215289687604742 : ℕ)

lemma sq_sqrtNeg486664 : sqrtNeg486664 ^ 2 = -486664 := by
  show ((6853475219497561581579357271197624642482790079785650197046958215289687604742 : ℕ) : F) ^ 2
    = (-486664 : F)
  rw [eq_neg_iff_add_eq_zero,
    show (486664 : F) = ((486664 : ℕ) : F) by norm_num,
    ← Nat.cast_pow, ← Nat.cast_add, ZMod.natCast_eq_zero_iff]
  show CryptWalker.NIKE.X25519Common.p ∣ _
  norm_num [CryptWalker.NIKE.X25519Common.p]

/-- The birational map's on-curve compatibility: an Edwards point with `x ≠ 0` maps to a genuine
point of `X25519`'s curve. `hx` rules out both `y = 1` (the identity, `toWeierstrass`'s own
separate case below) and `y = -1` (the curve's unique order-2 point, which never arises in the
odd-order-`ℓ` subgroup this file actually needs). -/
lemma montgomery_onCurve {x y : F} (hxy : onCurve ⟨x, y⟩) (hx : x ≠ 0) :
    CryptWalker.NIKE.X25519.onCurve ((1 + y) / (1 - y))
      (-sqrtNeg486664 * ((1 + y) / (1 - y)) / x) := by
  have hxy' : -x ^ 2 + y ^ 2 = 1 + d * x ^ 2 * y ^ 2 := hxy
  have h121666 : (121666 : F) ≠ 0 := by
    have : (121666 : F) = ((121666 : ℕ) : F) := by norm_num
    rw [this, Ne, ZMod.natCast_eq_zero_iff]
    show ¬ CryptWalker.NIKE.X25519Common.p ∣ _
    norm_num [CryptWalker.NIKE.X25519Common.p]
  have hd1 : d + 1 ≠ 0 := by
    show (-121665 / 121666 : F) + 1 ≠ 0
    rw [div_add' _ _ _ h121666]
    simp only [ne_eq, div_eq_zero_iff, h121666, or_false]
    norm_num
  have hy1 : (1 : F) - y ≠ 0 := by
    intro hcontra
    apply hx
    have hy : y = 1 := by linear_combination -hcontra
    rw [hy] at hxy'
    have hx2 : x ^ 2 * (d + 1) = 0 := by linear_combination -hxy'
    exact pow_eq_zero_iff two_ne_zero |>.mp ((mul_eq_zero.mp hx2).resolve_right hd1)
  show (-sqrtNeg486664 * ((1 + y) / (1 - y)) / x) ^ 2
    = ((1 + y) / (1 - y)) ^ 3 + 486662 * ((1 + y) / (1 - y)) ^ 2 + (1 + y) / (1 - y)
  rw [show d = -121665 / 121666 from rfl] at hxy'
  have hxy'' : 121666 * (-x ^ 2 + y ^ 2) = 121666 * (1 + -121665 / 121666 * x ^ 2 * y ^ 2) := by
    rw [hxy']
  field_simp at hxy''
  field_simp
  linear_combination (1 + y - y ^ 2 - y ^ 3) * sq_sqrtNeg486664 + (4 * y + 4) * hxy''

/-- The birational map, total over all of `Ed25519Math.Point` (including points off the curve,
which never arise from an honest `Ed25519Math` value but aren't ruled out by the bare `Point`
structure): the identity `(x, y) = (0, 1)` and the order-2 point `(0, -1)` both go to `0`; every
other on-curve point goes to its image under `montgomery_onCurve`. Off-curve input also falls back
to `0` — junk, since no theorem below is stated for it. -/
noncomputable def toWeierstrass (q : Point) : CryptWalker.NIKE.X25519.Point :=
  if _hy : q.y = 1 then 0
  else if hx : q.x = 0 then 0
  else if h : onCurve q then CryptWalker.NIKE.X25519.mkPoint (montgomery_onCurve h hx)
  else 0

@[simp] lemma toWeierstrass_zero : toWeierstrass Ed25519Math.zero = 0 := by
  simp [toWeierstrass, Ed25519Math.zero]

lemma toWeierstrass_of_ne {q : Point} (hy : q.y ≠ 1) (hx : q.x ≠ 0) (h : onCurve q) :
    toWeierstrass q = CryptWalker.NIKE.X25519.mkPoint (montgomery_onCurve h hx) := by
  simp only [toWeierstrass, dif_neg hy, dif_neg hx, dif_pos h]

end CryptWalker.Sign.Ed25519Group

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Ed25519_math
import CryptWalker.Sign.Ed25519_facts

/-! # Edwards-side facts: completeness and the special sums

`Ed25519Math.add` is the affine twisted-Edwards formula with a division, so it means nothing
where a denominator vanishes. Because `d` is not a square, no denominator ever vanishes on curve
points (`complete`), which is what lets the transport in `Ed25519_group` treat `add` as a total
group law. -/

namespace CryptWalker.Sign.Ed25519Edwards

open CryptWalker.Sign.Ed25519Facts
open CryptWalker.Sign.Ed25519Math (Point onCurve)

lemma d_eq : CryptWalker.Sign.Ed25519Math.d = d := rfl

lemma onCurve_iff {q : Point} : onCurve q ↔ -q.x ^ 2 + q.y ^ 2 = 1 + d * q.x ^ 2 * q.y ^ 2 :=
  Iff.rfl

lemma d_add_one_ne_zero : d + 1 ≠ 0 := by
  intro h
  have := d_rel
  have h1 : (1 : F) = 0 := by linear_combination (121666 : F) * h - this
  exact one_ne_zero h1

/-- On a curve point `1 + d y² ≠ 0`. -/
lemma one_add_d_sq_ne {x y : F} (h : -x ^ 2 + y ^ 2 = 1 + d * x ^ 2 * y ^ 2) : 1 + d * y ^ 2 ≠ 0 := by
  intro h0
  have hy : y ^ 2 = 1 := by linear_combination h + x ^ 2 * h0
  apply d_add_one_ne_zero
  rw [hy] at h0
  linear_combination h0

/-- **Completeness of the Edwards law.** The denominators `1 ± d x₁x₂y₁y₂` never vanish on curve
points, because `d` is a non-square. -/
theorem complete {x1 y1 x2 y2 : F} (h1 : -x1 ^ 2 + y1 ^ 2 = 1 + d * x1 ^ 2 * y1 ^ 2)
    (h2 : -x2 ^ 2 + y2 ^ 2 = 1 + d * x2 ^ 2 * y2 ^ 2) : (d * x1 * x2 * y1 * y2) ^ 2 ≠ 1 := by
  intro ht
  have e1 : x1 ^ 2 * (1 + d * y1 ^ 2) = y1 ^ 2 - 1 := by linear_combination -h1
  have e2 : x2 ^ 2 * (1 + d * y2 ^ 2) = y2 ^ 2 - 1 := by linear_combination -h2
  have n1 := one_add_d_sq_ne h1
  have n2 := one_add_d_sq_ne h2
  have F1 : d ^ 2 * (x1 ^ 2 * x2 ^ 2 * y1 ^ 2 * y2 ^ 2) = 1 := by linear_combination ht
  have P : (d * (y1 ^ 2 * y2 ^ 2) + 1) * (d * (y1 ^ 2 * y2 ^ 2) - d * (y1 ^ 2 + y2 ^ 2) - 1) = 0 := by
    linear_combination (1 + d * y1 ^ 2) * (1 + d * y2 ^ 2) * F1
      - d ^ 2 * y1 ^ 2 * y2 ^ 2 * (x2 ^ 2 * (1 + d * y2 ^ 2)) * e1
      - d ^ 2 * y1 ^ 2 * y2 ^ 2 * (y1 ^ 2 - 1) * e2
  rcases mul_eq_zero.mp P with hA | hB
  · have hy : y1 * y2 ≠ 0 := by
      intro h0
      have : (d * (y1 ^ 2 * y2 ^ 2) + 1) = 1 := by
        have : y1 ^ 2 * y2 ^ 2 = 0 := by rw [← mul_pow, h0]; ring
        rw [this]; ring
      rw [this] at hA
      exact one_ne_zero hA
    exact not_sq_of_d_mul hy (s := i) (by linear_combination hA - i_sq)
  · have key : (1 + d * y1 ^ 2) * (1 + d * y2 ^ 2) * (x1 ^ 2 * y2 ^ 2 - x2 ^ 2 * y1 ^ 2) = 0 := by
      linear_combination (y2 ^ 2 * (1 + d * y2 ^ 2)) * e1 - (y1 ^ 2 * (1 + d * y1 ^ 2)) * e2
        - (y1 ^ 2 - y2 ^ 2) * hB
    have hm : x1 ^ 2 * y2 ^ 2 = x2 ^ 2 * y1 ^ 2 := by
      have := (mul_eq_zero.mp key).resolve_left (mul_ne_zero n1 n2)
      linear_combination this
    have hsq : (d * (x1 ^ 2 * y2 ^ 2)) ^ 2 = 1 := by
      linear_combination F1 + d ^ 2 * (x1 ^ 2 * y2 ^ 2) * hm
    have hne : x1 * y2 ≠ 0 := by
      intro h0
      have : (d * (x1 ^ 2 * y2 ^ 2)) = 0 := by
        have : x1 ^ 2 * y2 ^ 2 = 0 := by rw [← mul_pow, h0]; ring
        rw [this]; ring
      rw [this] at hsq
      norm_num at hsq
    have hcases : d * (x1 ^ 2 * y2 ^ 2) = 1 ∨ d * (x1 ^ 2 * y2 ^ 2) = -1 := by
      have : (d * (x1 ^ 2 * y2 ^ 2) - 1) * (d * (x1 ^ 2 * y2 ^ 2) + 1) = 0 := by
        linear_combination hsq
      rcases mul_eq_zero.mp this with h | h
      · left; linear_combination h
      · right; linear_combination h
    rcases hcases with h | h
    · exact not_sq_of_d_mul hne (s := 1) (by linear_combination h)
    · exact not_sq_of_d_mul hne (s := i) (by linear_combination h - i_sq)

lemma one_sub_sq_ne {q r : Point} (hq : onCurve q) (hr : onCurve r) :
    1 - (d * q.x * r.x * q.y * r.y) ^ 2 ≠ 0 := by
  intro h
  exact complete hq hr (by linear_combination -h)

lemma one_add_ne {q r : Point} (hq : onCurve q) (hr : onCurve r) :
    1 + d * q.x * r.x * q.y * r.y ≠ 0 := by
  intro h
  apply one_sub_sq_ne hq hr
  have : d * q.x * r.x * q.y * r.y = -1 := by linear_combination h
  rw [this]; ring

lemma one_sub_ne {q r : Point} (hq : onCurve q) (hr : onCurve r) :
    1 - d * q.x * r.x * q.y * r.y ≠ 0 := by
  intro h
  apply one_sub_sq_ne hq hr
  have : d * q.x * r.x * q.y * r.y = 1 := by linear_combination -h
  rw [this]; ring

section add

open CryptWalker.Sign.Ed25519Math (add zero)

lemma add_def (q r : Point) :
    add q r = ⟨(q.x * r.y + q.y * r.x) / (1 + d * q.x * r.x * q.y * r.y),
               (q.y * r.y + q.x * r.x) / (1 - d * q.x * r.x * q.y * r.y)⟩ := rfl

lemma add_comm' (q r : Point) : add q r = add r q := by
  rw [add_def, add_def]
  congr 1 <;> congr 1 <;> ring

/-- Adding the order-2 point `(0, -1)` negates both coordinates. -/
lemma add_two_torsion (q : Point) : add q ⟨0, -1⟩ = ⟨-q.x, -q.y⟩ := by
  rw [add_def]
  simp

lemma add_zero' (q : Point) : add q zero = q := by
  rw [add_def]
  simp [zero]

lemma zero_add' (q : Point) : add zero q = q := by
  rw [add_comm']; exact add_zero' q

/-- `q + (-x, y) = (0, 1)`: the negative of `(x, y)` is `(-x, y)`. -/
lemma add_neg (q : Point) (hq : onCurve q) : add q ⟨-q.x, q.y⟩ = zero := by
  have hq' := hq
  have hr : onCurve (⟨-q.x, q.y⟩ : Point) := by
    rw [onCurve_iff] at hq ⊢; simpa using hq
  have h1 := one_sub_ne hq hr
  have h1' : 1 + d * q.x ^ 2 * q.y ^ 2 ≠ 0 := by
    intro h; apply h1; simp only; linear_combination h
  rw [add_def]
  simp only [zero]
  have e : (q.y * q.y + q.x * -q.x) = 1 - d * q.x * -q.x * q.y * q.y := by
    rw [onCurve_iff] at hq'; linear_combination hq'
  congr 1
  · have : q.x * q.y + q.y * -q.x = 0 := by ring
    rw [this, zero_div]
  · rw [e]; exact div_self h1

/-- `q + (x, -y) = (0, -1)`. -/
lemma add_conj (q : Point) (hq : onCurve q) : add q ⟨q.x, -q.y⟩ = ⟨0, -1⟩ := by
  have hr : onCurve (⟨q.x, -q.y⟩ : Point) := by
    rw [onCurve_iff] at hq ⊢; simpa using hq
  have h1 := one_sub_ne hq hr
  rw [add_def]
  have e : (q.y * -q.y + q.x * q.x) = -(1 - d * q.x * q.x * q.y * -q.y) := by
    rw [onCurve_iff] at hq; linear_combination -hq
  congr 1
  · have : q.x * -q.y + q.y * q.x = 0 := by ring
    rw [this, zero_div]
  · rw [e, neg_div, div_self h1]

end add

end CryptWalker.Sign.Ed25519Edwards

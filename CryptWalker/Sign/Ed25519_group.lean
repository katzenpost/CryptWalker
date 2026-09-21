/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Ed25519_math
import CryptWalker.Sign.Ed25519_facts
import CryptWalker.Sign.Ed25519_edwards
import CryptWalker.Sign.Ed25519_identities
import CryptWalker.NIKE.X25519

/-! # Ed25519's group law, by transport from Curve25519

`Ed25519Math.add` is the raw twisted-Edwards formula; proving it associative directly would mean
formalizing Edwards-curve group theory from scratch. Ed25519 is birationally equivalent to
Curve25519, and `NIKE.X25519.Point` already carries a full `AddCommGroup` from Mathlib. This file
transports across the map

    ψ : Curve25519 → Edwards,   (u, v) ↦ (x, y) = (-c·u/v, (u-1)/(u+1)),   c² = -486664,

and proves `ψ (P + Q) = Ed25519Math.add (ψ P) (ψ Q)` for **all** `P Q`. Every exceptional point is
handled: the identity, the order-2 point `T = (0,0)` (which `ψ` sends to `(0,-1)`), and the
sums that land on `T`. No axiom is used beyond `X25519.p_prime`: that `d` is a non-square (which
makes the Edwards law complete and rules out any other exceptional point) is Euler's criterion
evaluated by the kernel, see `Ed25519_facts`. -/

namespace CryptWalker.Sign.Ed25519Group

open CryptWalker.Sign.Ed25519Facts
open CryptWalker.Sign.Ed25519Edwards
open CryptWalker.Sign.Ed25519Math (Point onCurve add zero)
open WeierstrassCurve.Affine (Point.zero Point.some)

abbrev W := CryptWalker.NIKE.X25519.Point
abbrev curve := CryptWalker.NIKE.X25519.curve

/-- The curve equation on the Curve25519 side. -/
lemma w_eq {u v : F} (h : curve.Nonsingular u v) : v ^ 2 = u ^ 3 + 486662 * u ^ 2 + u :=
  CryptWalker.NIKE.X25519.nonsingular_iff_onCurve.mp h

lemma w_ns {u v : F} (h : v ^ 2 = u ^ 3 + 486662 * u ^ 2 + u) : curve.Nonsingular u v :=
  CryptWalker.NIKE.X25519.nonsingular_iff_onCurve.mpr h

lemma u_add_one_ne {u v : F} (hv : v ^ 2 = u ^ 3 + 486662 * u ^ 2 + u) : u + 1 ≠ 0 := by
  intro h
  have hu : u = -1 := by linear_combination h
  apply no_u_minus_one v
  rw [hv, hu]; norm_num

lemma u_eq_zero_of_v_eq_zero {u v : F} (hv : v ^ 2 = u ^ 3 + 486662 * u ^ 2 + u) (h0 : v = 0) :
    u = 0 := by
  have : u * (u ^ 2 + 486662 * u + 1) = 0 := by rw [h0] at hv; linear_combination -hv
  exact (mul_eq_zero.mp this).resolve_right (no_other_two_torsion u)

lemma v_ne_zero_of_u_ne_zero {u v : F} (hv : v ^ 2 = u ^ 3 + 486662 * u ^ 2 + u) (hu : u ≠ 0) :
    v ≠ 0 := fun h0 => hu (u_eq_zero_of_v_eq_zero hv h0)

/-- The transport map Curve25519 → Edwards. Total: the point at infinity goes to the Edwards
identity, and the order-2 point `(0,0)` (where the formula divides by `v = 0`) goes to `(0,-1)`. -/
def psi : W → Point
  | .zero => ⟨0, 1⟩
  | .some u v _ => ⟨-c * u / v, (u - 1) / (u + 1)⟩

@[simp] lemma psi_zero : psi 0 = ⟨0, 1⟩ := rfl

lemma psi_some {u v : F} (h : curve.Nonsingular u v) :
    psi (.some u v h) = ⟨-c * u / v, (u - 1) / (u + 1)⟩ := rfl

/-- The order-2 point `(0, 0)`. -/
def T : W := .some 0 0 (w_ns (by ring))

lemma psi_T : psi T = ⟨0, -1⟩ := by
  simp [T, psi]

theorem psi_onCurve (P : W) : onCurve (psi P) := by
  cases P with
  | zero => rw [onCurve_iff]; simp [psi]
  | some u v h =>
    have hv := w_eq h
    by_cases hu : u = 0
    · have hv0 : v = 0 := by
        subst hu; have : v ^ 2 = 0 := by rw [hv]; ring
        exact pow_eq_zero_iff two_ne_zero |>.mp this
      subst hu; subst hv0
      rw [onCurve_iff]; simp [psi]
    · rw [onCurve_iff]
      simp only [psi]
      exact CryptWalker.Sign.Ed25519Identities.psi_curve_aux u v hv
        (v_ne_zero_of_u_ne_zero hv hu) (u_add_one_ne hv)

lemma psi_neg (P : W) : psi (-P) = ⟨-(psi P).x, (psi P).y⟩ := by
  cases P with
  | zero =>
    change psi (-(0 : W)) = ⟨-(psi 0).x, (psi 0).y⟩
    rw [neg_zero]; simp
  | some u v h =>
    rw [WeierstrassCurve.Affine.Point.neg_some]
    simp only [psi, WeierstrassCurve.Affine.negY, CryptWalker.NIKE.X25519.curve]
    have e : (-v - 0 * u - 0 : F) = -v := by ring
    rw [e]
    congr 1
    rw [div_neg]

lemma some_congr {x x' y y' : F} {h : curve.Nonsingular x y} {h' : curve.Nonsingular x' y'}
    (hx : x = x') (hy : y = y') : (WeierstrassCurve.Affine.Point.some x y h : W) = .some x' y' h' := by
  subst hx; subst hy; rfl

lemma curve_a₁ : curve.a₁ = 0 := rfl
lemma curve_a₂ : curve.a₂ = 486662 := rfl
lemma curve_a₃ : curve.a₃ = 0 := rfl
lemma curve_a₄ : curve.a₄ = 1 := rfl

lemma addX_eq (x1 x2 l : F) : curve.addX x1 x2 l = l ^ 2 - 486662 - x1 - x2 := by
  simp only [WeierstrassCurve.Affine.addX, curve_a₁, curve_a₂]; ring

lemma addY_eq (x1 x2 y1 l : F) :
    curve.addY x1 x2 y1 l = -(l * (l ^ 2 - 486662 - x1 - x2 - x1) + y1) := by
  simp only [WeierstrassCurve.Affine.addY, WeierstrassCurve.Affine.negAddY,
    WeierstrassCurve.Affine.negY, addX_eq, curve_a₁, curve_a₃]
  ring

lemma negY_eq (x y : F) : curve.negY x y = -y := by
  simp only [WeierstrassCurve.Affine.negY, curve_a₁, curve_a₃]; ring

/-- `u`-coordinate of `P + Q` for `u₁ ≠ u₂`. -/
def U3 (u1 u2 v1 v2 : F) : F := ((v1 - v2) / (u1 - u2)) ^ 2 - 486662 - u1 - u2

/-- `v`-coordinate of `P + Q` for `u₁ ≠ u₂`. -/
def V3 (u1 u2 v1 v2 : F) : F := -(((v1 - v2) / (u1 - u2)) * (U3 u1 u2 v1 v2 - u1) + v1)

lemma add_X_ne_eq {u1 v1 u2 v2 : F} (h1 : curve.Nonsingular u1 v1) (h2 : curve.Nonsingular u2 v2)
    (hne : u1 ≠ u2) :
    ∃ h3 : curve.Nonsingular (U3 u1 u2 v1 v2) (V3 u1 u2 v1 v2),
      (WeierstrassCurve.Affine.Point.some u1 v1 h1 : W) + .some u2 v2 h2
        = .some (U3 u1 u2 v1 v2) (V3 u1 u2 v1 v2) h3 := by
  have hx : curve.addX u1 u2 (curve.slope u1 u2 v1 v2) = U3 u1 u2 v1 v2 := by
    rw [addX_eq, WeierstrassCurve.Affine.slope_of_X_ne hne]; rfl
  have hy : curve.addY u1 u2 v1 (curve.slope u1 u2 v1 v2) = V3 u1 u2 v1 v2 := by
    rw [addY_eq, WeierstrassCurve.Affine.slope_of_X_ne hne]; rfl
  have h3 : curve.Nonsingular (U3 u1 u2 v1 v2) (V3 u1 u2 v1 v2) := by
    have := WeierstrassCurve.Affine.nonsingular_add h1 h2 (fun hxy => hne hxy.1)
    rwa [hx, hy] at this
  exact ⟨h3, (WeierstrassCurve.Affine.Point.add_of_X_ne (h₁ := h1) (h₂ := h2) hne).trans
    (some_congr hx hy)⟩

/-- `u`-coordinate of `2P`. -/
def U3d (u v : F) : F := ((3 * u ^ 2 + 973324 * u + 1) / (2 * v)) ^ 2 - 486662 - u - u

/-- `v`-coordinate of `2P`. -/
def V3d (u v : F) : F := -(((3 * u ^ 2 + 973324 * u + 1) / (2 * v)) * (U3d u v - u) + v)

lemma add_double_eq {u v : F} (h : curve.Nonsingular u v) (hv : v ≠ 0) :
    ∃ h3 : curve.Nonsingular (U3d u v) (V3d u v),
      (WeierstrassCurve.Affine.Point.some u v h : W) + .some u v h = .some (U3d u v) (V3d u v) h3 := by
  have hy0 : v ≠ curve.negY u v := by
    rw [negY_eq]
    intro e; apply hv
    have : (2 : F) * v = 0 := by linear_combination e
    exact (mul_eq_zero.mp this).resolve_left two_ne
  have hℓ : curve.slope u u v v = (3 * u ^ 2 + 973324 * u + 1) / (2 * v) := by
    rw [WeierstrassCurve.Affine.slope_of_Y_ne rfl hy0, negY_eq, curve_a₁, curve_a₂, curve_a₄]
    congr 1 <;> ring
  have hx : curve.addX u u (curve.slope u u v v) = U3d u v := by
    rw [addX_eq, hℓ]; rfl
  have hy : curve.addY u u v (curve.slope u u v v) = V3d u v := by
    rw [addY_eq, hℓ]; rfl
  have h3 : curve.Nonsingular (U3d u v) (V3d u v) := by
    have := WeierstrassCurve.Affine.nonsingular_add h h (fun hxy => hy0 hxy.2)
    rwa [hx, hy] at this
  exact ⟨h3, (WeierstrassCurve.Affine.Point.add_self_of_Y_ne (h₁ := h) hy0).trans
    (some_congr hx hy)⟩

lemma T_add_T : T + T = 0 :=
  WeierstrassCurve.Affine.Point.add_self_of_Y_eq (by rw [negY_eq]; ring)

/-- Adding the order-2 point `T` negates both Edwards coordinates. -/
lemma psi_add_T (P : W) : psi (P + T) = ⟨-(psi P).x, -(psi P).y⟩ := by
  cases P with
  | zero =>
    change psi (0 + T) = _
    rw [zero_add, psi_T]; simp [psi]
  | some u v h =>
    have hv := w_eq h
    by_cases hu : u = 0
    · have hv0 : v = 0 := u_eq_zero_of_v_eq_zero (u := u) hv |> fun _ => by
        subst hu; have : v ^ 2 = 0 := by rw [hv]; ring
        exact pow_eq_zero_iff two_ne_zero |>.mp this
      subst hu; subst hv0
      have e : (WeierstrassCurve.Affine.Point.some 0 0 h : W) = T := rfl
      rw [e, T_add_T, psi_T]; simp [psi]
    · have hv' := v_ne_zero_of_u_ne_zero hv hu
      have hu1 := u_add_one_ne hv
      obtain ⟨h3, e⟩ := add_X_ne_eq h (w_ns (by ring : (0 : F) ^ 2 = 0 ^ 3 + 486662 * 0 ^ 2 + 0)) hu
      have e' : (WeierstrassCurve.Affine.Point.some u v h : W) + T
          = .some (U3 u 0 v 0) (V3 u 0 v 0) h3 := e
      have hU : U3 u 0 v 0 = 1 / u := by
        unfold U3; field_simp; linear_combination u * hv
      have hV : V3 u 0 v 0 = -v / u ^ 2 := by
        unfold V3; rw [hU]; field_simp; ring
      rw [e', psi_some]
      have h1u : 1 + u ≠ 0 := by rwa [add_comm]
      simp only [psi]
      rw [hU, hV]
      congr 1
      · field_simp
      · field_simp; ring

lemma eq_T_of_v_zero {u v : F} (h : curve.Nonsingular u v) (hv0 : v = 0) :
    (WeierstrassCurve.Affine.Point.some u v h : W) = T := by
  have hu := u_eq_zero_of_v_eq_zero (w_eq h) hv0
  subst hu; subst hv0; rfl

/-- If `P + Q = 0` then `Q = -P`, and Edwards `add` of a point with its negative is the identity. -/
lemma psi_add_of_sum_zero {P Q : W} (hs : P + Q = 0) : psi (P + Q) = add (psi P) (psi Q) := by
  have hQ : Q = -P := eq_neg_of_add_eq_zero_right hs
  rw [hs, hQ, psi_neg, psi_zero]
  exact (add_neg (psi P) (psi_onCurve P)).symm

/-- If `P + Q = T` then `Q = -P + T`, so `ψ Q = (x, -y)`, and Edwards `add` gives `(0,-1) = ψ T`. -/
lemma psi_add_of_sum_T {P Q : W} (hs : P + Q = T) : psi (P + Q) = add (psi P) (psi Q) := by
  have hQ : Q = -P + T := by rw [← hs]; abel
  have hψ : psi Q = ⟨(psi P).x, -(psi P).y⟩ := by
    rw [hQ, psi_add_T, psi_neg]; simp
  rw [hs, psi_T, hψ]
  exact (add_conj (psi P) (psi_onCurve P)).symm

/-- Generic addition of two points with `u₁ ≠ u₂`, neither of order 2, sum not of order 2. -/
lemma psi_add_gen {u1 v1 u2 v2 : F} (h1 : curve.Nonsingular u1 v1) (h2 : curve.Nonsingular u2 v2)
    (hne : u1 ≠ u2) (hv1' : v1 ≠ 0) (hv2' : v2 ≠ 0) (hV : V3 u1 u2 v1 v2 ≠ 0) :
    psi (.some u1 v1 h1 + .some u2 v2 h2) = add (psi (.some u1 v1 h1)) (psi (.some u2 v2 h2)) := by
  obtain ⟨h3, e⟩ := add_X_ne_eq h1 h2 hne
  have hq := psi_onCurve (.some u1 v1 h1 : W)
  have hr := psi_onCurve (.some u2 v2 h2 : W)
  have hu : u1 - u2 ≠ 0 := sub_ne_zero.mpr hne
  have hu3 : U3 u1 u2 v1 v2 + 1 ≠ 0 := u_add_one_ne (w_eq h3)
  simp only [psi_some] at hq hr
  have n1 := one_add_ne hq hr
  have n2 := one_sub_ne hq hr
  have hx := CryptWalker.Sign.Ed25519Identities.gen_x u1 u2 v1 v2 (w_eq h1) (w_eq h2) hu hv1' hv2'
    (u_add_one_ne (w_eq h1)) (u_add_one_ne (w_eq h2)) n1 hV
  have hy := CryptWalker.Sign.Ed25519Identities.gen_y u1 u2 v1 v2 (w_eq h1) (w_eq h2) hu hv1' hv2'
    (u_add_one_ne (w_eq h1)) (u_add_one_ne (w_eq h2)) n2 hu3
  rw [e]
  simp only [psi_some, add_def, Point.mk.injEq, U3, V3]
  exact ⟨hx.symm, hy.symm⟩

/-- Doubling a point not of order 2, when `2P` is not of order 2. -/
lemma psi_add_dbl {u v : F} (h : curve.Nonsingular u v) (hv' : v ≠ 0) (hV : V3d u v ≠ 0) :
    psi (.some u v h + .some u v h) = add (psi (.some u v h)) (psi (.some u v h)) := by
  obtain ⟨h3, e⟩ := add_double_eq h hv'
  have hq := psi_onCurve (.some u v h : W)
  have hu3 : U3d u v + 1 ≠ 0 := u_add_one_ne (w_eq h3)
  simp only [psi_some] at hq
  have n1 := one_add_ne hq hq
  have n2 := one_sub_ne hq hq
  have hx := CryptWalker.Sign.Ed25519Identities.dbl_x u v (w_eq h) hv' (u_add_one_ne (w_eq h))
    n1 hV
  have hy := CryptWalker.Sign.Ed25519Identities.dbl_y u v (w_eq h) hv' (u_add_one_ne (w_eq h))
    n2 hu3
  rw [e]
  simp only [psi_some, add_def, Point.mk.injEq, U3d, V3d]
  exact ⟨hx.symm, hy.symm⟩

/-- **The transport is a homomorphism.** `ψ (P + Q) = ψ P + ψ Q` for every pair of points. -/
theorem psi_add (P Q : W) : psi (P + Q) = add (psi P) (psi Q) := by
  by_cases h0 : P + Q = 0
  · exact psi_add_of_sum_zero h0
  by_cases hT : P + Q = T
  · exact psi_add_of_sum_T hT
  cases P with
  | zero =>
    change psi (0 + Q) = _
    rw [zero_add]; exact (zero_add' _).symm
  | some u1 v1 h1 =>
    cases Q with
    | zero =>
      change psi (_ + 0) = _
      rw [add_zero]; exact (add_zero' _).symm
    | some u2 v2 h2 =>
      by_cases hv1 : v1 = 0
      · rw [eq_T_of_v_zero h1 hv1, add_comm, psi_add_T, psi_T, CryptWalker.Sign.Ed25519Edwards.add_comm', add_two_torsion]
      by_cases hv2 : v2 = 0
      · rw [eq_T_of_v_zero h2 hv2, psi_add_T, psi_T, add_two_torsion]
      by_cases hne : u1 = u2
      · subst hne
        have hvv : v1 = v2 := by
          have hsq : (v1 - v2) * (v1 + v2) = 0 := by
            linear_combination w_eq h1 - w_eq h2
          rcases mul_eq_zero.mp hsq with h | h
          · linear_combination h
          · exfalso; apply h0
            exact WeierstrassCurve.Affine.Point.add_of_Y_eq rfl (by
              rw [negY_eq]; linear_combination h)
        subst hvv
        obtain ⟨h3, e⟩ := add_double_eq h1 hv1
        by_cases hV : V3d u1 v1 = 0
        · exfalso; apply hT
          rw [e]
          have : (WeierstrassCurve.Affine.Point.some (U3d u1 v1) (V3d u1 v1) h3 : W) = T :=
            eq_T_of_v_zero h3 hV
          exact this
        · exact psi_add_dbl h1 hv1 hV
      · obtain ⟨h3, e⟩ := add_X_ne_eq h1 h2 hne
        by_cases hV : V3 u1 u2 v1 v2 = 0
        · exfalso; apply hT
          rw [e]
          exact eq_T_of_v_zero h3 hV
        · exact psi_add_gen h1 h2 hne hv1 hv2 hV

end CryptWalker.Sign.Ed25519Group

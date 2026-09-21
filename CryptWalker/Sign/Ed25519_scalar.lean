/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Ed25519_group
import CryptWalker.Sign.Ed25519_order

/-! # Scalar multiplication through the transport

`Ed25519Math.scalarMul n (ψ P) = ψ (n • P)` for every point `P` of Curve25519, so scalar
multiplication of Ed25519 points inherits everything Mathlib proves about `n • P` in an additive
commutative group. The basepoint is `ψ G`, and `ℓ • G = 0` (from `Ed25519_order`), so
scalars act modulo `ℓ`. -/

namespace CryptWalker.Sign.Ed25519Scalar

open CryptWalker.Sign.Ed25519Facts
open CryptWalker.Sign.Ed25519Group
open CryptWalker.Sign.Ed25519Math (Point add zero scalarMul basepoint ell)

theorem psi_smul (n : ℕ) (P : W) : psi (n • P) = scalarMul n (psi P) := by
  induction n using Nat.strong_induction_on with
  | _ n ih =>
    rw [CryptWalker.Sign.Ed25519Order.scalarMul_eq]
    by_cases h0 : n = 0
    · subst h0; simp [zero]
    · have hn : n = 2 * (n / 2) + n % 2 := (Nat.div_add_mod n 2).symm
      have hlt : n / 2 < n := Nat.div_lt_self (Nat.pos_of_ne_zero h0) (by norm_num)
      have ih' := ih (n / 2) hlt
      by_cases h2 : n % 2 = 0
      · have e : n • P = (n / 2) • P + (n / 2) • P := by
          conv_lhs => rw [hn, h2]
          rw [add_zero, two_mul, add_smul]
        rw [if_neg h0, if_pos h2, e, psi_add, ih']
      · have h2' : n % 2 = 1 := by omega
        have e : n • P = P + ((n / 2) • P + (n / 2) • P) := by
          conv_lhs => rw [hn, h2']
          rw [add_comm, add_smul, one_smul, two_mul, add_smul]
        rw [if_neg h0, if_neg h2, e, psi_add, psi_add, ih']

/-- `ψ 0 = zero`. -/
lemma psi_zero' : psi (0 : W) = zero := rfl

/-- The only point mapping to the Edwards identity is the identity. -/
lemma eq_zero_of_psi_eq_zero {P : W} (h : psi P = zero) : P = 0 := by
  cases P with
  | zero => rfl
  | some u v hp =>
    exfalso
    have hu1 := u_add_one_ne (w_eq hp)
    have hy : (u - 1) / (u + 1) = 1 := by
      have := congrArg Point.y h
      simpa [psi, zero] using this
    rw [div_eq_one_iff_eq hu1] at hy
    have : (2 : F) = 0 := by linear_combination -hy
    exact two_ne this

lemma natCast_ne_zero' {n : ℕ} (h0 : n ≠ 0) (hlt : n < CryptWalker.NIKE.X25519Common.p) :
    ((n : ℕ) : F) ≠ 0 := natCast_ne_zero h0 hlt

/-- **The Ed25519 basepoint is the image of the X25519 basepoint.** -/
theorem psi_G : psi CryptWalker.NIKE.X25519.G = basepoint := by
  have hy0 : CryptWalker.NIKE.X25519.basepointY ≠ 0 := by
    unfold CryptWalker.NIKE.X25519.basepointY CryptWalker.NIKE.X25519.basepointYNat
    exact natCast_ne_zero (by norm_num) (by unfold CryptWalker.NIKE.X25519Common.p; norm_num)
  have h10 : (CryptWalker.NIKE.X25519Common.basepoint + 1 : F) ≠ 0 := by
    have : (CryptWalker.NIKE.X25519Common.basepoint + 1 : F) = ((10 : ℕ) : F) := by
      unfold CryptWalker.NIKE.X25519Common.basepoint; norm_num
    rw [this]
    exact natCast_ne_zero (by norm_num) (by unfold CryptWalker.NIKE.X25519Common.p; norm_num)
  unfold CryptWalker.NIKE.X25519.G CryptWalker.NIKE.X25519.mkPoint
  simp only [psi_some, basepoint, Point.mk.injEq]
  constructor
  · rw [div_eq_iff hy0]
    have h : (((15112221349535400772501151409588531511454012693041857206046113283949847762202 : ℕ) : F)
        * CryptWalker.NIKE.X25519.basepointY + c * 9 = 0) := by
      unfold CryptWalker.NIKE.X25519.basepointY CryptWalker.NIKE.X25519.basepointYNat c
      have : (((15112221349535400772501151409588531511454012693041857206046113283949847762202 *
          14781619447589544791020593568409986887264606134616475288964881837755586237401 +
          6853475219497561581579357271197624642482790079785650197046958215289687604742 * 9 : ℕ)) : F)
          = 0 := by
        rw [ZMod.natCast_eq_zero_iff]
        unfold CryptWalker.NIKE.X25519Common.p
        norm_num
      push_cast at this
      exact this
    have e : (15112221349535400772501151409588531511454012693041857206046113283949847762202 : F)
        = ((15112221349535400772501151409588531511454012693041857206046113283949847762202 : ℕ) : F) :=
      (Nat.cast_ofNat).symm
    rw [e]
    unfold CryptWalker.NIKE.X25519Common.basepoint
    linear_combination -h
  · rw [div_eq_iff h10]
    have e : (46316835694926478169428394003475163141307993866256225615783033603165251855960 : F)
        = ((46316835694926478169428394003475163141307993866256225615783033603165251855960 : ℕ) : F) :=
      (Nat.cast_ofNat).symm
    rw [e]
    unfold CryptWalker.NIKE.X25519Common.basepoint
    have : ((46316835694926478169428394003475163141307993866256225615783033603165251855960 * 10 : ℕ) : F)
        = ((8 : ℕ) : F) := by
      rw [ZMod.natCast_eq_natCast_iff']
      unfold CryptWalker.NIKE.X25519Common.p
      norm_num
    push_cast at this
    linear_combination -this

/-- `ℓ • G = 0` in Curve25519's group: the basepoint has order dividing `ℓ`. -/
theorem ell_smul_G : ell • CryptWalker.NIKE.X25519.G = 0 := by
  apply eq_zero_of_psi_eq_zero
  rw [psi_smul, psi_G]
  exact CryptWalker.Sign.Ed25519Order.scalarMul_ell_basepoint

/-! ### Multiples of the basepoint

Every statement about `scalarMul n basepoint` becomes a statement about `n • G` in an additive
commutative group, where `ℓ • G = 0` makes `n` matter only modulo `ℓ`. -/

lemma smul_mod (n : ℕ) : (n % ell) • CryptWalker.NIKE.X25519.G = n • CryptWalker.NIKE.X25519.G := by
  conv_rhs => rw [← Nat.mod_add_div n ell]
  rw [add_smul, mul_comm ell, mul_smul, ell_smul_G, CryptWalker.NIKE.X25519.nsmul_zero_point, add_zero]

lemma sm_base (n : ℕ) : scalarMul n basepoint = psi (n • CryptWalker.NIKE.X25519.G) := by
  rw [psi_smul, psi_G]

lemma sm_base_onCurve (n : ℕ) : CryptWalker.Sign.Ed25519Math.onCurve (scalarMul n basepoint) := by
  rw [sm_base]; exact psi_onCurve _

lemma sm_sm (a b : ℕ) :
    scalarMul a (scalarMul b basepoint) = scalarMul (a * b) basepoint := by
  rw [sm_base, sm_base, ← psi_smul, ← mul_smul]

lemma sm_mod (n : ℕ) : scalarMul (n % ell) basepoint = scalarMul n basepoint := by
  rw [sm_base, sm_base, smul_mod]

lemma add_sm (a b : ℕ) :
    add (scalarMul a basepoint) (scalarMul b basepoint) = scalarMul (a + b) basepoint := by
  rw [sm_base, sm_base, sm_base, ← psi_add, add_smul]

lemma sm_mod_eq {a b : ℕ} (h : a % ell = b % ell) :
    scalarMul a basepoint = scalarMul b basepoint := by
  rw [← sm_mod a, ← sm_mod b, h]

end CryptWalker.Sign.Ed25519Scalar

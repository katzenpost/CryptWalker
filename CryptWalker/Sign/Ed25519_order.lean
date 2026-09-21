/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Ed25519_math
import CryptWalker.Sign.Ed25519_facts
import CryptWalker.Sign.Ed25519_edwards

/-! # The basepoint has order `ℓ`

`scalarMul ell basepoint = zero` is a computation, not an assumption. `Ed25519Math.scalarMul`
divides in `ZMod p`, whose inverse the kernel cannot evaluate, so the computation runs on a mirror
over plain naturals whose inverse is Fermat's `x ^ (p-2)`. The mirror is proved equal to
`Ed25519Math.add`/`scalarMul` (`cast_eAdd`, `cast_eScalar`), and `decide +kernel` — which adds no
axiom, unlike `native_decide` — evaluates it. -/

namespace CryptWalker.Sign.Ed25519Order

open CryptWalker.Sign.Ed25519Facts
open CryptWalker.Sign.Ed25519Math (Point add zero scalarMul basepoint ell)

/-- `d` as a natural number. -/
def d0 : ℕ := 37095705934669439343138083508754565189542113879843219016388785533085940283555

lemma d0_cast : ((d0 : ℕ) : F) = d := by
  have h : (d0 : F) * 121666 = -121665 := by
    have : ((d0 * 121666 + 121665 : ℕ) : F) = 0 := by
      rw [ZMod.natCast_eq_zero_iff]
      unfold d0 CryptWalker.NIKE.X25519Common.p
      norm_num
    push_cast at this
    linear_combination this
  have := d_rel
  have hne := h121666
  apply mul_right_cancel₀ hne
  rw [h, this]

/-- `x⁻¹` by Fermat. -/
def inv' (x : ℕ) : ℕ := powModAux CryptWalker.NIKE.X25519Common.p 256 x (CryptWalker.NIKE.X25519Common.p - 2) 1

lemma p_sub_two_lt : CryptWalker.NIKE.X25519Common.p - 2 < 2 ^ 256 := by
  unfold CryptWalker.NIKE.X25519Common.p; norm_num

lemma cast_inv' (x : ℕ) : ((inv' x : ℕ) : F) = ((x : ℕ) : F)⁻¹ := by
  unfold inv'
  rw [← pow_eq_powModAux _ x _ 256 p_sub_two_lt]
  by_cases hx : ((x : ℕ) : F) = 0
  · rw [hx, inv_zero]
    exact zero_pow (by unfold CryptWalker.NIKE.X25519Common.p; norm_num)
  · have hp : CryptWalker.NIKE.X25519Common.p - 2 + 1 = CryptWalker.NIKE.X25519Common.p - 1 := by
      unfold CryptWalker.NIKE.X25519Common.p; norm_num
    have h1 : ((x : ℕ) : F) ^ (CryptWalker.NIKE.X25519Common.p - 2) * ((x : ℕ) : F) = 1 := by
      rw [← pow_succ, hp]; exact ZMod.pow_card_sub_one_eq_one hx
    exact eq_inv_of_mul_eq_one_left h1

/-- Edwards addition on naturals. -/
def eAdd (a b : ℕ × ℕ) : ℕ × ℕ :=
  let p := CryptWalker.NIKE.X25519Common.p
  let t := d0 * a.1 % p * b.1 % p * a.2 % p * b.2 % p
  ((a.1 * b.2 + a.2 * b.1) % p * inv' ((1 + t) % p) % p,
   (a.2 * b.2 + a.1 * b.1) % p * inv' ((1 + p - t) % p) % p)

/-- Double-and-add on naturals, structural on fuel. -/
def eScalar : ℕ → ℕ → ℕ × ℕ → ℕ × ℕ
  | 0, _, _ => (0, 1)
  | fuel + 1, n, q =>
    if n = 0 then (0, 1)
    else
      let half := eScalar fuel (n / 2) q
      let dbl := eAdd half half
      if n % 2 = 0 then dbl else eAdd q dbl

def toE (a : ℕ × ℕ) : Point := ⟨(a.1 : F), (a.2 : F)⟩

lemma cast_one_add (t : ℕ) (T : F) (h : (t : F) = T) :
    ((((1 + t) % CryptWalker.NIKE.X25519Common.p : ℕ)) : F) = 1 + T := by
  rw [ZMod.natCast_mod, Nat.cast_add, Nat.cast_one, h]

lemma cast_one_sub (t : ℕ) (T : F) (ht : t < CryptWalker.NIKE.X25519Common.p) (h : (t : F) = T) :
    ((((1 + CryptWalker.NIKE.X25519Common.p - t) % CryptWalker.NIKE.X25519Common.p : ℕ)) : F)
      = 1 - T := by
  rw [ZMod.natCast_mod, Nat.cast_sub (by omega), Nat.cast_add, ZMod.natCast_self, Nat.cast_one, h]
  ring

lemma cast_eAdd (a b : ℕ × ℕ) : toE (eAdd a b) = add (toE a) (toE b) := by
  have hp : 0 < CryptWalker.NIKE.X25519Common.p := by
    unfold CryptWalker.NIKE.X25519Common.p; norm_num
  have ht : d0 * a.1 % CryptWalker.NIKE.X25519Common.p * b.1 % CryptWalker.NIKE.X25519Common.p
      * a.2 % CryptWalker.NIKE.X25519Common.p * b.2 % CryptWalker.NIKE.X25519Common.p
      < CryptWalker.NIKE.X25519Common.p := Nat.mod_lt _ hp
  have hT : ((d0 * a.1 % CryptWalker.NIKE.X25519Common.p * b.1 % CryptWalker.NIKE.X25519Common.p
      * a.2 % CryptWalker.NIKE.X25519Common.p * b.2 % CryptWalker.NIKE.X25519Common.p : ℕ) : F)
      = d * a.1 * b.1 * a.2 * b.2 := by
    simp only [ZMod.natCast_mod, Nat.cast_mul, d0_cast]
  have hI1 := cast_one_add _ _ hT
  have hI2 := cast_one_sub _ _ ht hT
  rw [CryptWalker.Sign.Ed25519Edwards.add_def]
  simp only [toE, eAdd, Point.mk.injEq]
  constructor
  · rw [ZMod.natCast_mod, Nat.cast_mul, ZMod.natCast_mod, cast_inv', hI1, div_eq_mul_inv]
    push_cast; rfl
  · rw [ZMod.natCast_mod, Nat.cast_mul, ZMod.natCast_mod, cast_inv', hI2, div_eq_mul_inv]
    push_cast; rfl

lemma scalarMul_eq (n : ℕ) (q : Point) :
    scalarMul n q = if n = 0 then zero else
      (if n % 2 = 0 then add (scalarMul (n / 2) q) (scalarMul (n / 2) q)
       else add q (add (scalarMul (n / 2) q) (scalarMul (n / 2) q))) := by
  rw [scalarMul]

lemma cast_eScalar : ∀ (fuel n : ℕ) (q : ℕ × ℕ), n < 2 ^ fuel →
    toE (eScalar fuel n q) = scalarMul n (toE q)
  | 0, n, q, h => by
    have : n = 0 := by simpa using h
    subst this
    rw [scalarMul_eq]; simp [eScalar, toE, zero]
  | fuel + 1, n, q, h => by
    rw [scalarMul_eq]
    by_cases h0 : n = 0
    · subst h0; simp [eScalar, toE, zero]
    · have hlt : n / 2 < 2 ^ fuel := by
        have : n < 2 * 2 ^ fuel := by rw [pow_succ] at h; omega
        omega
      have ih := cast_eScalar fuel (n / 2) q hlt
      simp only [eScalar, if_neg h0]
      by_cases h2 : n % 2 = 0
      · simp only [if_pos h2]; rw [cast_eAdd, ih]
      · simp only [if_neg h2]; rw [cast_eAdd, cast_eAdd, ih]

/-- The RFC 8032 basepoint on naturals. -/
def basepointNat : ℕ × ℕ :=
  (15112221349535400772501151409588531511454012693041857206046113283949847762202,
   46316835694926478169428394003475163141307993866256225615783033603165251855960)

lemma toE_basepointNat : toE basepointNat = basepoint := by
  simp [toE, basepointNat, basepoint]

set_option maxRecDepth 100000 in
lemma eScalar_ell : eScalar 253 ell basepointNat = (0, 1) := by
  unfold basepointNat ell
  decide +kernel

/-- **The basepoint has order `ℓ`.** -/
theorem scalarMul_ell_basepoint : scalarMul ell basepoint = zero := by
  have h := cast_eScalar 253 ell basepointNat (by unfold ell; norm_num)
  rw [eScalar_ell, toE_basepointNat] at h
  rw [← h]; simp [toE, zero]

end CryptWalker.Sign.Ed25519Order

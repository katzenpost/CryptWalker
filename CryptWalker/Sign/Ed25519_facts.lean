/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.NumberTheory.LegendreSymbol.Basic
import CryptWalker.NIKE.X25519

/-! # Arithmetic facts about `p = 2^255 - 19` that the Ed25519 group law rests on

Everything here is a theorem: the only assumption anywhere below is `X25519.p_prime`. The
non-square-ness of the Edwards `d` is Euler's criterion evaluated by the kernel (`decide +kernel`
adds no axiom, unlike `native_decide`), using a fuelled square-and-multiply so the 254-bit exponent
never unfolds unary. -/

namespace CryptWalker.Sign.Ed25519Facts

open CryptWalker.NIKE.X25519Common (p)

abbrev F := ZMod p

instance : Fact p.Prime := ⟨CryptWalker.NIKE.X25519.p_prime⟩

/-- Square-and-multiply modulo `m`, structural on fuel so the kernel can evaluate it. -/
def powModAux (m : ℕ) : ℕ → ℕ → ℕ → ℕ → ℕ
  | 0, _, _, acc => acc
  | fuel + 1, b, e, acc =>
    if e = 0 then acc
    else powModAux m fuel (b * b % m) (e / 2) (if e % 2 = 1 then acc * b % m else acc)

lemma powModAux_modEq (m : ℕ) : ∀ (fuel b e acc : ℕ), e < 2 ^ fuel →
    powModAux m fuel b e acc ≡ acc * b ^ e [MOD m] := by
  intro fuel
  induction fuel with
  | zero =>
    intro b e acc he
    have : e = 0 := by simpa using he
    subst this
    simp [powModAux]
    rfl
  | succ n ih =>
    intro b e acc he
    unfold powModAux
    by_cases h0 : e = 0
    · subst h0; simp; rfl
    · rw [if_neg h0]
      have hlt : e / 2 < 2 ^ n := by
        have : e < 2 * 2 ^ n := by rw [pow_succ] at he; omega
        omega
      refine (ih _ _ _ hlt).trans ?_
      have hb : (b * b % m) ^ (e / 2) ≡ (b * b) ^ (e / 2) [MOD m] :=
        (Nat.mod_modEq _ _).pow _
      have hsplit : b ^ e = (if e % 2 = 1 then b else 1) * (b * b) ^ (e / 2) := by
        have : e = 2 * (e / 2) + e % 2 := (Nat.div_add_mod e 2).symm
        rcases Nat.mod_two_eq_zero_or_one e with h | h
        · simp only [h, zero_ne_one, if_false, one_mul]
          conv_lhs => rw [this, h]
          rw [add_zero, pow_mul, sq]
        · simp only [h, if_true]
          conv_lhs => rw [this, h]
          rw [pow_add, pow_mul, sq, mul_comm]; simp
      rw [hsplit]
      by_cases h2 : e % 2 = 1
      · simp only [h2, if_true]
        calc (acc * b % m) * (b * b % m) ^ (e / 2)
            ≡ (acc * b) * (b * b) ^ (e / 2) [MOD m] :=
              ((Nat.mod_modEq _ _).mul hb)
          _ = acc * (b * (b * b) ^ (e / 2)) := by ring
      · simp only [h2, if_false]
        calc acc * (b * b % m) ^ (e / 2) ≡ acc * (b * b) ^ (e / 2) [MOD m] := Nat.ModEq.mul_left _ hb
          _ = acc * (1 * (b * b) ^ (e / 2)) := by ring

/-- `a ^ e` in `ZMod m` computed by binary exponentiation. -/
lemma pow_eq_powModAux (m a e : ℕ) (fuel : ℕ) (he : e < 2 ^ fuel) :
    ((a : ℕ) : ZMod m) ^ e = ((powModAux m fuel a e 1 : ℕ) : ZMod m) := by
  have := powModAux_modEq m fuel a e 1 he
  rw [one_mul] at this
  rw [(ZMod.natCast_eq_natCast_iff _ _ _).mpr this, Nat.cast_pow]

/-- The small integer `-121665 * 121666 mod p`; `d = -121665/121666` is this over `121666^2`. -/
def n0 : ℕ := 57896044618658097711785492504343953926634992332820282019728792003941762326059

lemma powMod_n0 : powModAux p 256 n0 (p / 2) 1 = p - 1 := by
  unfold n0 CryptWalker.NIKE.X25519Common.p
  decide +kernel

lemma p_odd : p % 2 = 1 := by unfold CryptWalker.NIKE.X25519Common.p; norm_num

lemma p_lt_fuel : p / 2 < 2 ^ 256 := by unfold CryptWalker.NIKE.X25519Common.p; norm_num

lemma natCast_ne_zero {n : ℕ} (h0 : n ≠ 0) (hlt : n < p) : ((n : ℕ) : F) ≠ 0 := by
  rw [Ne, ZMod.natCast_eq_zero_iff]
  exact fun hdvd => absurd (Nat.le_of_dvd (Nat.pos_of_ne_zero h0) hdvd) (by omega)

lemma two_ne : (2 : F) ≠ 0 := by
  have := natCast_ne_zero (n := 2) (by norm_num) (by unfold CryptWalker.NIKE.X25519Common.p; norm_num)
  exact_mod_cast this

lemma n0_cast : ((n0 : ℕ) : F) = -121665 * 121666 := by
  have : ((n0 : ℕ) : F) + 121665 * 121666 = 0 := by
    have h : ((n0 + 121665 * 121666 : ℕ) : F) = 0 := by
      rw [ZMod.natCast_eq_zero_iff]
      unfold n0 CryptWalker.NIKE.X25519Common.p
      norm_num
    push_cast at h
    exact h
  linear_combination this

lemma minus_one_ne_one : (-1 : F) ≠ 1 := by
  intro h
  have h2 : (2 : F) = 0 := by linear_combination -h
  have : ((2 : ℕ) : F) = 0 := by exact_mod_cast h2
  rw [ZMod.natCast_eq_zero_iff] at this
  have := Nat.le_of_dvd (by norm_num) this
  unfold CryptWalker.NIKE.X25519Common.p at this
  norm_num at this

lemma n0_nonsquare : ¬ IsSquare ((n0 : ℕ) : F) := by
  have hne : ((n0 : ℕ) : F) ≠ 0 := natCast_ne_zero (by unfold n0; norm_num) (by
    unfold n0 CryptWalker.NIKE.X25519Common.p; norm_num)
  rw [ZMod.euler_criterion p hne]
  rw [pow_eq_powModAux p n0 (p / 2) 256 p_lt_fuel, powMod_n0]
  have hp1 : ((p - 1 : ℕ) : F) = -1 := by
    have : 1 ≤ p := by unfold CryptWalker.NIKE.X25519Common.p; norm_num
    rw [Nat.cast_sub this]
    simp
  rw [hp1]
  exact minus_one_ne_one

/-- Edwards `d` for Ed25519. -/
def d : F := (-121665 : F) / 121666

lemma h121666 : (121666 : F) ≠ 0 := by
  have : (121666 : F) = ((121666 : ℕ) : F) := by norm_num
  rw [this]
  exact natCast_ne_zero (by norm_num) (by unfold CryptWalker.NIKE.X25519Common.p; norm_num)

lemma d_ne_zero : d ≠ 0 := by
  unfold d
  have : (121665 : F) ≠ 0 := by
    have : (121665 : F) = ((121665 : ℕ) : F) := by norm_num
    rw [this]
    exact natCast_ne_zero (by norm_num) (by unfold CryptWalker.NIKE.X25519Common.p; norm_num)
  simp [div_eq_zero_iff, this, h121666]

lemma d_rel : d * 121666 = -121665 := by
  unfold d; exact div_mul_cancel₀ _ h121666

/-- **`d` is not a square in `F`.** Everything about completeness of the Edwards law and about
the exceptional points of the Montgomery model reduces to this. -/
theorem d_nonsquare : ¬ IsSquare d := by
  rintro ⟨s, hs⟩
  apply n0_nonsquare
  refine ⟨s * 121666, ?_⟩
  rw [n0_cast]
  have : d * 121666 ^ 2 = -121665 * 121666 := by
    unfold d; field_simp
  calc (-121665 * 121666 : F) = d * 121666 ^ 2 := this.symm
    _ = s * 121666 * (s * 121666) := by rw [hs]; ring

/-- `d` times a nonzero square is never a square. -/
lemma not_sq_of_d_mul {t s : F} (ht : t ≠ 0) (h : d * t ^ 2 = s ^ 2) : False := by
  apply d_nonsquare
  refine ⟨s / t, ?_⟩
  field_simp
  linear_combination h

/-- `√-1` in `F`. -/
def i : F := ((19681161376707505956807079304988542015446066515923890162744021073123829784752 : ℕ) : F)

lemma i_sq : i ^ 2 = -1 := by
  have : i ^ 2 + 1 = 0 := by
    have h : (((19681161376707505956807079304988542015446066515923890162744021073123829784752 : ℕ) ^ 2 + 1 : ℕ) : F) = 0 := by
      rw [ZMod.natCast_eq_zero_iff]
      unfold CryptWalker.NIKE.X25519Common.p
      norm_num
    push_cast at h
    exact h
  linear_combination this

/-- `c = √-486664`, the constant of the birational map. -/
def c : F := ((6853475219497561581579357271197624642482790079785650197046958215289687604742 : ℕ) : F)

lemma c_sq : c ^ 2 = -486664 := by
  have : c ^ 2 + 486664 = 0 := by
    have h : (((6853475219497561581579357271197624642482790079785650197046958215289687604742 : ℕ) ^ 2 + 486664 : ℕ) : F) = 0 := by
      rw [ZMod.natCast_eq_zero_iff]
      unfold CryptWalker.NIKE.X25519Common.p
      norm_num
    push_cast at h
    exact h
  linear_combination this

lemma c_ne_zero : c ≠ 0 := by
  intro h
  have := c_sq
  rw [h] at this
  have h486664 : (486664 : F) ≠ 0 := by
    have : (486664 : F) = ((486664 : ℕ) : F) := by norm_num
    rw [this]
    exact natCast_ne_zero (by norm_num) (by unfold CryptWalker.NIKE.X25519Common.p; norm_num)
  apply h486664
  linear_combination this

/-- `d * c^2 = 486660`, i.e. `A - 2` for `A = 486662`. -/
lemma d_mul_c_sq : d * c ^ 2 = 486660 := by
  rw [c_sq]; unfold d
  rw [div_mul_eq_mul_div, div_eq_iff h121666]; norm_num

/-- No point of Curve25519 has `u = -1`: that would need `486660` to be a square. -/
theorem no_u_minus_one (v : F) : v ^ 2 ≠ 486660 := by
  intro h
  apply not_sq_of_d_mul c_ne_zero (s := v)
  rw [d_mul_c_sq]; exact h.symm

lemma i_ne_zero : i ≠ 0 := by
  intro h
  have := i_sq
  rw [h] at this
  have h1 : (1 : F) = 0 := by linear_combination this
  exact one_ne_zero h1

/-- `(0,0)` is the only point of Curve25519 with `v = 0`: `u² + 486662u + 1` has no root. -/
theorem no_other_two_torsion (u : F) : u ^ 2 + 486662 * u + 1 ≠ 0 := by
  intro h
  refine not_sq_of_d_mul (t := i * c ^ 2) (mul_ne_zero i_ne_zero (pow_ne_zero 2 c_ne_zero))
    (s := 2 * u + 486662) ?_
  have h1 : d * (i * c ^ 2) ^ 2 = -(d * c ^ 2) * c ^ 2 := by
    have : (i * c ^ 2) ^ 2 = i ^ 2 * c ^ 2 * c ^ 2 := by ring
    rw [this, i_sq]; ring
  rw [h1, d_mul_c_sq, c_sq]
  linear_combination (-4) * h

end CryptWalker.Sign.Ed25519Facts

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Ed25519_math
import CryptWalker.Sign.Ed25519_facts
import CryptWalker.Sign.Ed25519_edwards

/-! # `decodePoint ∘ encodePoint = some`

Ed25519's 32-byte point compression (`y` in the low 255 bits, the parity of `x` in the top bit)
round-trips on every curve point. Decoding recovers `x` from `y` by the `p ≡ 5 (mod 8)` square-root
recipe of RFC 8032, `x₀ = xx^((p+3)/8)` corrected by `√-1`, then fixes the sign by parity;
`sqrt_step` shows the recipe always lands on `±x`, and `parity_fix` that the parity rule picks `x`. -/

namespace CryptWalker.Sign.Ed25519Codec
open CryptWalker.Sign.Ed25519Facts
open CryptWalker.Sign.Ed25519Math (bytesToNat natToBytes leBytes Point onCurve encodePoint decodePoint)

lemma ofDigits_range : ∀ (k n : ℕ),
    Nat.ofDigits 256 ((List.range k).map (fun i => (n >>> (8 * i)) % 256)) = n % 256 ^ k
  | 0, n => by simp [Nat.mod_one]
  | k + 1, n => by
    rw [List.range_succ_eq_map, List.map_cons, List.map_map, Nat.ofDigits_cons]
    have h : ((fun i => (n >>> (8 * i)) % 256) ∘ Nat.succ) = fun i => ((n >>> 8) >>> (8 * i)) % 256 := by
      funext i
      simp only [Function.comp]
      rw [← Nat.shiftRight_add]; congr 2; omega
    rw [h, ofDigits_range k (n >>> 8)]
    simp only [mul_zero, Nat.shiftRight_zero]
    rw [pow_succ', Nat.mod_mul, Nat.shiftRight_eq_div_pow]

lemma bytesToNat_natToBytes (n : ℕ) (h : n < 256 ^ 32) : bytesToNat (natToBytes 32 n) = n := by
  unfold bytesToNat natToBytes
  simp only [List.map_map]
  have hd := ofDigits_range 32 n
  rw [Nat.mod_eq_of_lt h] at hd
  have e : List.map (UInt8.toNat ∘ fun i => (n >>> (8 * i)).toUInt8) (List.range 32)
      = (List.range 32).map (fun i => (n >>> (8 * i)) % 256) := by
    apply List.map_congr_left
    intro i _
    simp
  rw [e, hd]

lemma powAux_eq (b : F) (e : ℕ) : CryptWalker.Sign.Ed25519Math.powAux b e = b ^ e := by
  induction e using Nat.strong_induction_on generalizing b with
  | _ e ih =>
    rw [CryptWalker.Sign.Ed25519Math.powAux]
    by_cases h0 : e = 0
    · subst h0; simp
    · rw [dif_neg h0]
      have hlt : e / 2 < e := Nat.div_lt_self (Nat.pos_of_ne_zero h0) (by norm_num)
      simp only [ih _ hlt]
      have hn : e = 2 * (e / 2) + e % 2 := (Nat.div_add_mod e 2).symm
      by_cases h2 : e % 2 = 1
      · rw [if_pos h2]
        conv_rhs => rw [hn, h2]
        rw [pow_add, pow_mul, sq]; ring
      · rw [if_neg h2]
        have h2' : e % 2 = 0 := by omega
        conv_rhs => rw [hn, h2']
        rw [add_zero, pow_mul, sq]

lemma sqrtMinusOne_eq : CryptWalker.Sign.Ed25519Math.sqrtMinusOne = i := by
  unfold CryptWalker.Sign.Ed25519Math.sqrtMinusOne i
  exact (Nat.cast_ofNat).symm

lemma sqrtMinusOne_sq : CryptWalker.Sign.Ed25519Math.sqrtMinusOne ^ 2 = -1 := by
  rw [sqrtMinusOne_eq]; exact i_sq

open CryptWalker.Sign.Ed25519Math (powAux sqrtMinusOne)
open CryptWalker.NIKE.X25519Common (p)
open CryptWalker.Sign.Ed25519Edwards (one_add_d_sq_ne)

lemma sqrt_step {x y : F} (hq : -x ^ 2 + y ^ 2 = 1 + d * x ^ 2 * y ^ 2) :
    (if (powAux ((y ^ 2 - 1) / (d * y ^ 2 + 1)) ((p + 3) / 8)) ^ 2 = (y ^ 2 - 1) / (d * y ^ 2 + 1)
      then powAux ((y ^ 2 - 1) / (d * y ^ 2 + 1)) ((p + 3) / 8)
      else powAux ((y ^ 2 - 1) / (d * y ^ 2 + 1)) ((p + 3) / 8) * sqrtMinusOne) = x ∨
    (if (powAux ((y ^ 2 - 1) / (d * y ^ 2 + 1)) ((p + 3) / 8)) ^ 2 = (y ^ 2 - 1) / (d * y ^ 2 + 1)
      then powAux ((y ^ 2 - 1) / (d * y ^ 2 + 1)) ((p + 3) / 8)
      else powAux ((y ^ 2 - 1) / (d * y ^ 2 + 1)) ((p + 3) / 8) * sqrtMinusOne) = -x := by
  have hd1 : d * y ^ 2 + 1 ≠ 0 := by
    have := one_add_d_sq_ne hq; rwa [add_comm]
  have hxx : (y ^ 2 - 1) / (d * y ^ 2 + 1) = x ^ 2 := by
    rw [div_eq_iff hd1]; linear_combination hq
  rw [hxx, powAux_eq]
  have hm : 0 < (p + 3) / 8 := by unfold CryptWalker.NIKE.X25519Common.p; norm_num
  by_cases hx : x = 0
  · subst hx
    have : ((0 : F) ^ 2) ^ ((p + 3) / 8) = 0 := by
      rw [zero_pow (by norm_num)]; exact zero_pow (by omega)
    rw [this]; simp
  · have hp1 : (p - 1) / 2 * 2 = p - 1 := by unfold CryptWalker.NIKE.X25519Common.p; norm_num
    have hexp : 2 * ((p + 3) / 8 * 2) = (p - 1) / 2 + 2 := by
      unfold CryptWalker.NIKE.X25519Common.p; norm_num
    have he : (x ^ ((p - 1) / 2)) ^ 2 = 1 := by
      rw [← pow_mul, hp1]; exact ZMod.pow_card_sub_one_eq_one hx
    have hx0 : ((x ^ 2) ^ ((p + 3) / 8)) ^ 2 = x ^ ((p - 1) / 2) * x ^ 2 := by
      rw [← pow_mul, ← pow_mul, hexp, pow_add]
    set x0 := (x ^ 2) ^ ((p + 3) / 8) with hx0def
    set e := x ^ ((p - 1) / 2) with hedef
    have hx2 : x ^ 2 ≠ 0 := pow_ne_zero 2 hx
    have hcases : e = 1 ∨ e = -1 := by
      have : (e - 1) * (e + 1) = 0 := by linear_combination he
      rcases mul_eq_zero.mp this with h | h
      · left; linear_combination h
      · right; linear_combination h
    rcases hcases with h1 | h1
    · have hsq : x0 ^ 2 = x ^ 2 := by linear_combination hx0 + x ^ 2 * h1
      rw [if_pos hsq]
      exact sq_eq_sq_iff_eq_or_eq_neg.mp hsq
    · have hsq : x0 ^ 2 = -(x ^ 2) := by linear_combination hx0 + x ^ 2 * h1
      have hne : x0 ^ 2 ≠ x ^ 2 := by
        intro h
        apply hx2
        have : (2 : F) * x ^ 2 = 0 := by linear_combination hsq - h
        exact (mul_eq_zero.mp this).resolve_left two_ne
      rw [if_neg hne]
      have : (x0 * sqrtMinusOne) ^ 2 = x ^ 2 := by
        rw [mul_pow, hsq, sqrtMinusOne_sq]; ring
      exact sq_eq_sq_iff_eq_or_eq_neg.mp this


lemma ofFn_range (k : ℕ) (g : ℕ → ℕ) :
    List.ofFn (fun i : Fin k => g i.val) = (List.range k).map g := by
  apply List.ext_getElem
  · simp
  · intro i h1 h2
    simp

lemma bytesToNat_ofFn (k n : ℕ) :
    bytesToNat (Vector.ofFn (fun i : Fin k => (n >>> (8 * i.val)).toUInt8)).toList = n % 256 ^ k := by
  unfold bytesToNat
  rw [Vector.toList_ofFn, List.map_ofFn]
  have e : (List.ofFn (UInt8.toNat ∘ fun i : Fin k => (n >>> (8 * i.val)).toUInt8))
      = (List.range k).map (fun i => (n >>> (8 * i)) % 256) := by
    rw [← ofFn_range]
    apply congrArg; funext i; simp
  rw [e, ofDigits_range]

lemma val_lt_pow {z : F} : z.val < 2 ^ 255 := by
  have h := ZMod.val_lt z
  have : CryptWalker.NIKE.X25519Common.p < 2 ^ 255 := by
    unfold CryptWalker.NIKE.X25519Common.p; norm_num
  omega

lemma raw_encode (q : Point) :
    bytesToNat (encodePoint q).toList = q.y.val + 2 ^ 255 * (q.x.val % 2) := by
  have hy : q.y.val < 2 ^ 255 := val_lt_pow
  have hs : q.x.val % 2 < 2 := Nat.mod_lt _ (by norm_num)
  have hys : bytesToNat (leBytes q.y 32) = q.y.val := by
    apply bytesToNat_natToBytes
    calc q.y.val < 2 ^ 255 := hy
      _ ≤ 256 ^ 32 := by norm_num
  have hor : q.y.val ||| ((q.x.val % 2) <<< 255) = q.y.val + 2 ^ 255 * (q.x.val % 2) := by
    rw [Nat.shiftLeft_eq, Nat.or_comm, mul_comm (q.x.val % 2), add_comm,
      Nat.two_pow_add_eq_or_of_lt hy]
  show bytesToNat (Vector.ofFn (fun i : Fin 32 =>
    ((bytesToNat (leBytes q.y 32) ||| ((q.x.val % 2) <<< 255)) >>> (8 * i.val)).toUInt8)).toList = _
  rw [bytesToNat_ofFn, hys, hor]
  apply Nat.mod_eq_of_lt
  have : q.x.val % 2 ≤ 1 := by omega
  calc q.y.val + 2 ^ 255 * (q.x.val % 2) ≤ q.y.val + 2 ^ 255 * 1 := by
        exact Nat.add_le_add_left (Nat.mul_le_mul_left _ this) _
    _ < 256 ^ 32 := by norm_num; omega

lemma parity_fix {x xc : F} (h : xc = x ∨ xc = -x) :
    (if xc.val % 2 = x.val % 2 then xc else -xc) = x := by
  rcases h with h | h
  · subst h; simp
  · by_cases hx : x = 0
    · subst hx; simp at h; simp [h]
    · have hne : (-x).val % 2 ≠ x.val % 2 := by
        rw [ZMod.neg_val, if_neg hx]
        have hlt := ZMod.val_lt x
        have hodd := CryptWalker.Sign.Ed25519Facts.p_odd
        have hpos : 0 < x.val := ZMod.val_pos.mpr hx
        omega
      subst h
      rw [if_neg hne]; simp

theorem decode_encode (q : Point) (hq : onCurve q) : decodePoint (encodePoint q) = some q := by
  have hraw := raw_encode q
  have hy : q.y.val < 2 ^ 255 := val_lt_pow
  have hs : q.x.val % 2 < 2 := Nat.mod_lt _ (by norm_num)
  have hsign : (q.y.val + 2 ^ 255 * (q.x.val % 2)) >>> 255 = q.x.val % 2 := by
    rw [Nat.shiftRight_eq_div_pow, mul_comm, Nat.add_mul_div_right _ _ (by positivity),
      Nat.div_eq_of_lt hy, zero_add]
  have hyN : (q.y.val + 2 ^ 255 * (q.x.val % 2)) % (2 ^ 255) = q.y.val := by
    rw [mul_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hy]
  have hyF : ((q.y.val : ℕ) : F) = q.y := ZMod.natCast_zmod_val q.y
  have hq' : -q.x ^ 2 + q.y ^ 2 = 1 + d * q.x ^ 2 * q.y ^ 2 := hq
  have hsq := sqrt_step hq'
  have hfix := parity_fix (x := q.x) (xc := _) hsq
  unfold decodePoint
  simp only [hraw, hsign, hyN, hyF]
  have hd : CryptWalker.Sign.Ed25519Math.d = d := rfl
  simp only [hd]
  rw [hfix]
  rw [dif_pos hq]

end CryptWalker.Sign.Ed25519Codec

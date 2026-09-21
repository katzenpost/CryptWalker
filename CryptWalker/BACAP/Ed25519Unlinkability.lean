/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Ed25519_blinded
import CryptWalker.Sign.Blindable
import CryptWalker.Util.UniformHit

/-! # BACAP unlinkability, at Ed25519

`Sign.Blindable.blind_unlinkable` says a uniform blinding factor hits each box ID in the image of
`f ↦ blindPub pk f` with probability `1/|Scalar|`, provided that map is injective (it is
`uniformHit_eq_of_injective`, applied here at the concrete types: going through the abstract
`Blindable` record makes Lean unfold `ZMod ℓ` on a 253-bit literal). This file
discharges the injectivity for Ed25519: `blindPub (publicKey s)` is injective whenever `s ≠ 0`,
because the basepoint has order exactly `ℓ` (it divides `ℓ`, `ℓ` is prime, and `G ≠ 0`).

No assumption beyond `p_prime` and `ell_prime`. -/

namespace CryptWalker.BACAP.Ed25519Unlinkability

open OracleComp OracleSpec ENNReal
open CryptWalker.Sign.Ed25519Blinded
open CryptWalker.Sign.Ed25519Scalar
open CryptWalker.Sign.Ed25519Group
open CryptWalker.Sign.Ed25519Math (ell)

/-- `ψ` is injective: `ψ P = ψ Q` makes `ψ (P + -Q)` the Edwards identity. -/
lemma psi_injective {P Q : W} (h : psi P = psi Q) : P = Q := by
  have h0 : psi (P + -Q) = CryptWalker.Sign.Ed25519Math.zero := by
    rw [psi_add, psi_neg, ← h]
    exact CryptWalker.Sign.Ed25519Edwards.add_neg (psi P) (psi_onCurve P)
  exact add_neg_eq_zero.mp (eq_zero_of_psi_eq_zero h0)

lemma G_ne_zero : CryptWalker.NIKE.X25519.G ≠ 0 := by
  unfold CryptWalker.NIKE.X25519.G CryptWalker.NIKE.X25519.mkPoint
  exact WeierstrassCurve.Affine.Point.some_ne_zero _

/-- The basepoint has order exactly `ℓ`. -/
lemma addOrderOf_G : addOrderOf CryptWalker.NIKE.X25519.G = ell := by
  have hd := addOrderOf_dvd_of_nsmul_eq_zero ell_smul_G
  rcases (Nat.dvd_prime ell_prime).mp hd with h1 | h1
  · exfalso
    apply G_ne_zero
    have := addOrderOf_nsmul_eq_zero CryptWalker.NIKE.X25519.G
    rw [h1, one_nsmul] at this
    exact this
  · exact h1

lemma smul_G_inj {a b : ℕ} (ha : a < ell) (hb : b < ell)
    (h : a • CryptWalker.NIKE.X25519.G = b • CryptWalker.NIKE.X25519.G) : a = b := by
  have := nsmul_eq_nsmul_iff_modEq.mp h
  rw [addOrderOf_G] at this
  exact this.eq_of_lt_of_lt ha hb

theorem publicKey_injective : Function.Injective publicKey := by
  intro a b h
  unfold publicKey at h
  have hab := congrArg CryptWalker.Sign.Ed25519Math.decodePoint h
  rw [CryptWalker.Sign.Ed25519Codec.decode_encode _ (sm_base_onCurve _),
    CryptWalker.Sign.Ed25519Codec.decode_encode _ (sm_base_onCurve _)] at hab
  have hpt := Option.some.inj hab
  rw [sm_base, sm_base] at hpt
  exact ZMod.val_injective ell (smul_G_inj (ZMod.val_lt a) (ZMod.val_lt b) (psi_injective hpt))

/-- Blinding a nonzero root key by different factors gives different box IDs. -/
theorem blindPub_injective (s : Scalar) (hs : s ≠ 0) : Function.Injective (blindPub (publicKey s)) := by
  intro f g h
  rw [blindPub_publicKey, blindPub_publicKey] at h
  exact mul_right_cancel₀ hs (publicKey_injective h)

/-- **BACAP unlinkability at Ed25519** (Echomix §4.3, under uniformly random blinding factors).
For a nonzero root secret `s`, a uniformly drawn blinding factor produces any given box ID in the
image with probability exactly `1/ℓ`. -/
theorem ed25519_unlinkable [Fintype Scalar] [SampleableType Scalar] [DecidableEq PubBytes]
    (s : Scalar) (hs : s ≠ 0) {target : PubBytes}
    (ht : target ∈ Set.range (blindPub (publicKey s))) :
    Pr[= true | ($ᵗ Scalar) >>= fun f => pure (decide (blindPub (publicKey s) f = target))] =
      (Fintype.card Scalar : ℝ≥0∞)⁻¹ :=
  CryptWalker.Util.UniformHit.uniformHit_eq_of_injective (blindPub_injective s hs) ht

end CryptWalker.BACAP.Ed25519Unlinkability

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.CryptoFoundations.HardnessAssumptions.DiffieHellman
import CryptWalker.NIKE.X25519
import CryptWalker.Sphinx.nike_sphinx
import CryptWalker.Util.UniformHit

/-! # Wrap-resistance (§4.3)

A fresh uniform blinding factor hits any fixed target group element with probability `1/N`,
since blinding by a generator is a bijection. Single-query case only. KEM-Sphinx has no
analogue: it has no group element to re-blind. -/

namespace CryptWalker.Sphinx.WrapResistance

open OracleComp OracleSpec ENNReal
open CryptWalker.Util.UniformHit (uniformHit_eq)

/-! ## Sphinx's blinding step, for X25519 -/

open CryptWalker.NIKE.X25519 (Point)

/-- Single-query wrap-resistance of the blinding step, assuming scalar multiplication by `pk` is a
bijection on `Fin N`: the probability of hitting `target` is `1/N`. -/
theorem blind_wrapResistance {N : ℕ} [NeZero N] (pk target : Point)
    (hbij : Function.Bijective (fun b : Fin N => (b : ℕ) • pk)) :
    Pr[= true | ($ᵗ Fin N) >>= fun b => pure (decide ((b : ℕ) • pk = target))] =
      (N : ℝ≥0∞)⁻¹ := by
  rw [uniformHit_eq hbij target, Fintype.card_fin]

end CryptWalker.Sphinx.WrapResistance

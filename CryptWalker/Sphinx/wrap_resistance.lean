/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.CryptoFoundations.HardnessAssumptions.DiffieHellman
import CryptWalker.NIKE.X25519
import CryptWalker.Sphinx.interface

/-! # Wrap-resistance (§4.3)

An adversary who picks a target header `(α′, β′, γ′)` and even the mix's own private key `x`
still cannot force processing `(α, x)` to yield exactly that `α′`: each query's blinding factor
`b` is fresh and uniform, and since `α` generates the group, `b ↦ α^b` is a bijection, so any
single query hits `α′` with probability exactly `1/(q−1)` (`c` queries: at most `c/(q−1)`, by a
union bound — the general `c`-query case isn't built here, only the `c = 1` base case).

`Interface.uniformHit_eq` is that argument with the group erased: any bijection composed with a
uniform sample hits a fixed target with probability `1/|domain|`. `blind_wrapResistance` instantiates
it for `X25519.lean`'s group.

**NIKE-Sphinx only**: `NIKESphinx.blind pk factor = factor • pk` is exactly this operation.
**KEM-Sphinx has no analogue** — its per-hop step is an independent KEM encapsulation, no group
element to re-blind; the corresponding claim there would be about ciphertext integrity, not
formalized here. -/

namespace CryptWalker.Sphinx.WrapResistance

open OracleComp OracleSpec ENNReal
open CryptWalker.Sphinx.Interface (uniformHit_eq)

/-! ## Sphinx's blinding step, for X25519 -/

open CryptWalker.NIKE.X25519 (Point)

/-- **Wrap-resistance for NIKE-Sphinx's blinding step**, single-query case: `pk` is the group
element committed to before the blinding factor is drawn, `target` the header being forged.
`hbij` (scalar multiplication by `pk` is a bijection on `Fin N`) holds whenever `pk` has order
exactly `N` — assumed here, on the same footing as `X25519.p_prime`, not re-derived. Given it, no
adversary beats a `1/N` chance of hitting `target`. -/
theorem blind_wrapResistance {N : ℕ} [NeZero N] (pk target : Point)
    (hbij : Function.Bijective (fun b : Fin N => (b : ℕ) • pk)) :
    Pr[= true | ($ᵗ Fin N) >>= fun b => pure (decide ((b : ℕ) • pk = target))] =
      (N : ℝ≥0∞)⁻¹ := by
  rw [uniformHit_eq hbij target, Fintype.card_fin]

end CryptWalker.Sphinx.WrapResistance

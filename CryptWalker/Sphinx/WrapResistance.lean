/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.CryptoFoundations.HardnessAssumptions.DiffieHellman
import CryptWalker.NIKE.X25519
import CryptWalker.Sphinx.Sphinx

/-! # Wrap-resistance (Danezis–Goldberg §4.3)

Wrap-resistance says: given a target header `(α′, β′, γ′)`, an adversary cannot produce
`(α, x)` — even choosing the mix's private key `x` itself — such that processing `(α, x)`
yields that exact `α′`. The paper's proof (eprint 2008/475, §4.3) is short: producing such a
pair requires `α^{h_b(α, α^x)} = α′`, and since `h_b` is a random oracle, every query returns a
*fresh, uniform* blinding factor `b`; because `α` generates the group, `b ↦ α^b` is a bijection,
so any single query hits the specific target `α′` with probability exactly `1/(q−1)`, and `c`
queries give at most `c/(q−1)` by a union bound.

`CryptWalker.Sphinx.Sphinx.uniformHit_eq` is that argument stripped of everything Sphinx-specific:
a uniformly sampled `b` composed with *any* bijection lands on a fixed target with probability
exactly `1/|domain|`, regardless of what the bijection is — it's also what `BlindedScheme`'s
`wrap_resistant` field reduces to for every instance. `blind_wrapResistance` here is the
single-query instance of that fact for `X25519.lean`'s group (the `AddCommGroup Point` from
`Mathlib`'s `WeierstrassCurve.Affine.Point`, not a `Module`/field-of-scalars setup — Curve25519's
scalars are plain `ℕ`-multiples, which every `AddCommGroup` already carries).

This is the *base case* of the paper's bound (`c = 1`); the general `c`-query bound is the same
argument repeated `c` times under a union bound, not built here.

**NIKE-Sphinx only.** `NIKESphinx.blind pk factor = factor • pk` is exactly this operation — see
`NIKESphinx.lean`'s `blind`, one rewrite away from `X25519.dh_commutes`'s picture, modulo going
through `X25519_montgomery_ladder`'s byte-level ladder (`NIKESphinx` runs the ladder, whose own
consistency with the group law is `curve25519_commutes`, itself an axiom — not re-derived here).
`NIKESphinx.lean`'s `NIKESphinxBlinded` is the corresponding `BlindedScheme` instance.
**KEM-Sphinx has no analogue.** Its per-hop step is an independent KEM encapsulation, not a
group element re-blinded (`KEMSphinx.lean`: "no blinding chain, so no `Blind` step, since there
is no group element to re-blind"). The corresponding property there would bound forging a KEM
ciphertext that decapsulates to a chosen shared secret — a claim about the KEM's ciphertext
integrity, not about this group action, and not formalized here. -/

namespace CryptWalker.Sphinx.WrapResistance

open OracleComp OracleSpec ENNReal
open CryptWalker.Sphinx.Sphinx (uniformHit_eq)

/-! ## Sphinx's blinding step, for X25519 -/

open CryptWalker.NIKE.X25519 (Point)

/-- **Wrap-resistance for NIKE-Sphinx's blinding step**, single-query case. `pk` is the group
element the adversary commits to *before* the blinding factor is drawn (matching `blind pk
factor = factor • pk` in `NIKESphinx.lean`, with `factor` ranging over `Fin N` in place of a
raw 32-byte factor); `target` is the header the adversary is trying to forge.

`hbij` — that scalar multiplication by `pk` is a bijection from `Fin N` onto the subgroup `pk`
generates — is the one fact this doesn't derive from first principles: it holds whenever `pk`
has order exactly `N` (the standard case for X25519's basepoint, order a ~2²⁵²-bit prime), on
the same "well-known but not formalized here" footing as `X25519.p_prime`. Given it, no
adversary beats a `1/N` chance of hitting a chosen `target`, no matter how `pk` is chosen. -/
theorem blind_wrapResistance {N : ℕ} [NeZero N] (pk target : Point)
    (hbij : Function.Bijective (fun b : Fin N => (b : ℕ) • pk)) :
    Pr[= true | ($ᵗ Fin N) >>= fun b => pure (decide ((b : ℕ) • pk = target))] =
      (N : ℝ≥0∞)⁻¹ := by
  rw [uniformHit_eq hbij target, Fintype.card_fin]

end CryptWalker.Sphinx.WrapResistance

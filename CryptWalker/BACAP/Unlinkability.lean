/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Util.UniformHit

/-! # BACAP unlinkability (§4.3)

The Echomix paper (arXiv:2501.02933, §4.3) states BACAP's unlinkability as a
δ-indistinguishability game over box IDs, resting on three points: (1) the per-box blinding
factor `K_i^ctx` is indistinguishable from uniform in `𝔽_ℓ` (a KDF/PRF assumption), (2) the
2^256 keyspace makes enumerating `K_i^ctx` infeasible, and (3) recovering the root secret from
two box IDs requires solving ECDLP.

Under idealization (1) — blinding factors are *true*-random, not merely PRF outputs — BACAP's
core claim is provable as something stronger than a hybrid-game bound: independent uniform
scalars applied to any two nonzero group elements hit any target pair with exactly the
probability two independent uniform draws from the group would, whether or not the two elements
share a root secret. That is `δ = 0`: perfect, not just computational, unlinkability under this
idealization. `Sphinx.Indistinguishability` proves a different §4.4 property of this same paper
by an actual hybrid argument; this property doesn't need one.

The proof is one application of `Util.UniformHit.uniformHit_eq_of_injective` (the fact
`Sphinx.NIKESphinx.wrap_resistant` uses the same way) to the product action on `F × F`. Closing the
gap from this idealization to the real HKDF-derived `K_i^ctx` (`BACAP.Ratchet.deriveKForContext`)
via a `PRGScheme` hybrid step, matching `Sphinx.Indistinguishability`'s own `jointKeyPRG`
pattern, is future work — and `Ed25519Unlinkability` instantiates the single-box form at Ed25519. -/

namespace CryptWalker.BACAP.Unlinkability

open OracleComp OracleSpec ENNReal
open CryptWalker.Util.UniformHit (uniformHit_eq_of_injective)

variable {F G : Type} [Field F] [AddCommGroup G] [Module F G]
variable [Fintype F] [SampleableType F] [SampleableType (F × F)] [DecidableEq G]

omit [SampleableType F] in
/-- **Core lemma**: two independent uniform scalars, applied respectively to `P` and `Q`, hit
any target pair in the image with probability exactly `1 / |F × F|` — provided scalar
multiplication by each of `P`, `Q` alone is injective (any nonzero element of a prime-order
group). One instance of `uniformHit_eq_of_injective`, applied to the product map
`(a, b) ↦ (a • P, b • Q)`. Injective rather than bijective: the image is the subgroup the point
generates, not all of `G`. -/
theorem unlinkable {P Q : G}
    (hP : Function.Injective (· • P : F → G)) (hQ : Function.Injective (· • Q : F → G))
    {m n : G} (hm : m ∈ Set.range (· • P : F → G)) (hn : n ∈ Set.range (· • Q : F → G)) :
    Pr[= true | ($ᵗ (F × F)) >>=
        fun kk => pure (decide ((kk.1 • P, kk.2 • Q) = (m, n)))] =
      (Fintype.card (F × F) : ℝ≥0∞)⁻¹ := by
  obtain ⟨a, rfl⟩ := hm
  obtain ⟨b, rfl⟩ := hn
  exact uniformHit_eq_of_injective (Function.Injective.prodMap hP hQ) ⟨(a, b), rfl⟩

omit [SampleableType F] in
/-- **BACAP unlinkability (§4.3), restated in the paper's own terms**: the pair of box IDs
`(Kx • P, Ky • Q)` — `P`, `Q` each `S • B` for *some* root secret `S` and public base point `B`,
possibly the same secret, possibly different — hits any target with the same probability
`1 / |F|²` regardless of whether `P = Q`, `P ≠ Q` but same root secret, or entirely different
root secrets. Nothing about the joint distribution of `(Kx • P, Ky • Q)` depends on the
relationship between `P` and `Q` at all: an adversary given the two resulting box IDs learns
nothing about whether they share a root secret. This is the paper's `X`/`X′` events (§4.3)
being indistinguishable with `δ = 0`, under idealization (1) above. -/
theorem unlinkable_delta_zero {P Q P' Q' : G}
    (hP : Function.Injective (· • P : F → G)) (hQ : Function.Injective (· • Q : F → G))
    (hP' : Function.Injective (· • P' : F → G)) (hQ' : Function.Injective (· • Q' : F → G))
    {m n : G} (hm : m ∈ Set.range (· • P : F → G)) (hn : n ∈ Set.range (· • Q : F → G))
    (hm' : m ∈ Set.range (· • P' : F → G)) (hn' : n ∈ Set.range (· • Q' : F → G)) :
    Pr[= true | ($ᵗ (F × F)) >>=
        fun kk => pure (decide ((kk.1 • P, kk.2 • Q) = (m, n)))] =
      Pr[= true | ($ᵗ (F × F)) >>=
        fun kk => pure (decide ((kk.1 • P', kk.2 • Q') = (m, n)))] := by
  rw [unlinkable hP hQ hm hn, unlinkable hP' hQ' hm' hn']

end CryptWalker.BACAP.Unlinkability

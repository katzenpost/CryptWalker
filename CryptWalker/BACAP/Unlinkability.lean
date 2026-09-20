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

The proof is one application of `Util.UniformHit.uniformHit_eq` (already in the codebase,
reused by `Sphinx.NIKESphinx.wrap_resistant` the same way) to the product action on `F × F`.
Closing the
gap from this idealization to the real HKDF-derived `K_i^ctx` (`BACAP.Ratchet.deriveKForContext`)
via a `PRGScheme` hybrid step, matching `Sphinx.Indistinguishability`'s own `jointKeyPRG`
pattern, is future work — as is connecting `G` here to Ed25519's actual group (blocked on a
homomorphism proof between the Edwards and Montgomery addition laws that turned out to be
substantially larger than the on-curve map in `Sign.Ed25519_group`; see that file's module doc). -/

namespace CryptWalker.BACAP.Unlinkability

open OracleComp OracleSpec ENNReal
open CryptWalker.Util.UniformHit (uniformHit_eq)

variable {F G : Type} [Field F] [AddCommGroup G] [Module F G]
variable [Fintype F] [SampleableType F] [SampleableType (F × F)] [DecidableEq G]

omit [SampleableType F] in
/-- **Core lemma**: two independent uniform scalars, applied respectively to `P` and `Q`, hit
any target pair with probability exactly `1 / |F × F|` — provided scalar multiplication by each
of `P`, `Q` alone is already a bijection onto `G` (the case for any nonzero element of the
prime-order subgroup BACAP's box IDs actually live in). One instance of `uniformHit_eq`, applied
to the product map `(a, b) ↦ (a • P, b • Q)`, which is bijective exactly when each factor is. -/
theorem unlinkable {P Q : G}
    (hP : Function.Bijective (· • P : F → G)) (hQ : Function.Bijective (· • Q : F → G))
    (m n : G) :
    Pr[= true | ($ᵗ (F × F)) >>=
        fun kk => pure (decide ((kk.1 • P, kk.2 • Q) = (m, n)))] =
      (Fintype.card (F × F) : ℝ≥0∞)⁻¹ :=
  uniformHit_eq (hP.prodMap hQ) (m, n)

omit [SampleableType F] in
/-- **BACAP unlinkability (§4.3), restated in the paper's own terms**: the pair of box IDs
`(Kx • P, Ky • Q)` — `P`, `Q` each `S • B` for *some* root secret `S` and public base point `B`,
possibly the same secret, possibly different — hits any target with the same probability
`1 / |F|²` regardless of whether `P = Q`, `P ≠ Q` but same root secret, or entirely different
root secrets. Nothing about the joint distribution of `(Kx • P, Ky • Q)` depends on the
relationship between `P` and `Q` at all: an adversary given the two resulting box IDs learns
nothing about whether they share a root secret. This is the paper's `X`/`X′` events (§4.3)
being indistinguishable with `δ = 0`, under idealization (1) above. -/
theorem unlinkable_delta_zero {P Q : G}
    (hP : Function.Bijective (· • P : F → G)) (hQ : Function.Bijective (· • Q : F → G))
    (P' Q' : G)
    (hP' : Function.Bijective (· • P' : F → G)) (hQ' : Function.Bijective (· • Q' : F → G))
    (m n : G) :
    Pr[= true | ($ᵗ (F × F)) >>=
        fun kk => pure (decide ((kk.1 • P, kk.2 • Q) = (m, n)))] =
      Pr[= true | ($ᵗ (F × F)) >>=
        fun kk => pure (decide ((kk.1 • P', kk.2 • Q') = (m, n)))] := by
  rw [unlinkable hP hQ m n, unlinkable hP' hQ' m n]

end CryptWalker.BACAP.Unlinkability

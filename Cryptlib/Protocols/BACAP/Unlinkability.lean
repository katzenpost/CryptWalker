/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Util.UniformHit

/-! # BACAP unlinkability (Echomix §4.3, arXiv:2501.02933)

Assuming uniformly random blinding factors, box IDs are perfectly unlinkable (`δ = 0`): their
distribution does not depend on whether they share a root secret. -/

namespace Cryptlib.Protocols.BACAP.Unlinkability

open OracleComp OracleSpec ENNReal
open Cryptlib.Util.UniformHit (uniformHit_eq_of_injective)

variable {F G : Type} [Field F] [AddCommGroup G] [Module F G]
variable [Fintype F] [SampleableType F] [SampleableType (F × F)] [DecidableEq G]

omit [SampleableType F] in
/-- Independent uniform scalars applied to `P` and `Q` hit any target pair in the image with
probability `1 / |F × F|`, provided `· • P` and `· • Q` are injective. -/
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
/-- The distribution of `(Kx • P, Ky • Q)` does not depend on `P`, `Q`: two box IDs reveal
nothing about whether they share a root secret. -/
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

end Cryptlib.Protocols.BACAP.Unlinkability

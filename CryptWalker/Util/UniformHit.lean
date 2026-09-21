/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.OracleComp.Constructions.SampleableType

/-! # Hitting a fixed target through a bijection

`uniformHit_eq`: a uniformly sampled value, pushed through a bijection, hits any fixed target
with probability `1 / |domain|`. Shared by `Sphinx.NIKESphinx` (wrap-resistance: "blind by this
freshly drawn factor," hitting a forged header) and `BACAP.Unlinkability`/`Sign.Blindable`
(blinding a public key by a uniform scalar, hitting a chosen box ID) — the same fact about
uniform sampling composed with a bijection, unrelated to Sphinx specifically, so it lives here
rather than in either caller. -/

namespace CryptWalker.Util.UniformHit

open OracleComp OracleSpec ENNReal

/-- A uniformly sampled `b : F`, pushed through an injective `act`, hits any `target` in its image
with probability `1/|F|`. -/
theorem uniformHit_eq_of_injective {F G : Type} [Fintype F] [SampleableType F] [DecidableEq G]
    {act : F → G} (hinj : Function.Injective act) {target : G} (htarget : target ∈ Set.range act) :
    Pr[= true | ($ᵗ F) >>= fun b => pure (decide (act b = target))] =
      (Fintype.card F : ℝ≥0∞)⁻¹ := by
  obtain ⟨b₀, rfl⟩ := htarget
  simp only [probOutput_bind_eq_tsum, probOutput_uniformSample, probOutput_pure]
  rw [tsum_fintype, Finset.sum_eq_single b₀]
  · simp
  · intro b _ hne
    simp [show act b ≠ act b₀ from fun heq => hne (hinj heq)]
  · exact absurd (Finset.mem_univ b₀)

/-- A uniformly sampled `b : F`, pushed through a bijection `act`, hits any fixed `target` with
probability `1/|F|`. -/
theorem uniformHit_eq {F G : Type} [Fintype F] [SampleableType F] [DecidableEq G]
    {act : F → G} (hact : Function.Bijective act) (target : G) :
    Pr[= true | ($ᵗ F) >>= fun b => pure (decide (act b = target))] =
      (Fintype.card F : ℝ≥0∞)⁻¹ :=
  uniformHit_eq_of_injective hact.injective (hact.surjective target)

end CryptWalker.Util.UniformHit

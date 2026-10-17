/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.OracleComp.Constructions.SampleableType
import VCVio.EvalDist.Bool

/-! # §4.2: Integrity

An adversary who knows every mix node's private key cannot forge a header that `N = r + 1` honest
nodes all accept, except with the probability of solving Problem P. The paper's algebraic identity
for the last hop's MAC (`γ_N = a_0 ⊕ ⋯ ⊕ a_{N-1}`) is taken as the hypothesis
`DecompositionWitness`, and Problem P's hardness as `ProblemPHard`. -/

namespace Cryptlib.Protocols.Sphinx.Integrity

open OracleComp OracleSpec ENNReal
open scoped Classical

/-! ## Honest per-hop processing along a forged `α_0`

Each hop advances `α_i ↦ α_i^{hb(α_i, s_i)}` with `s_i = α_i^{x_{n_i}}` (§3.6). -/

section AlphaChain

variable {F G : Type} [Field F] [AddCommGroup G] [Module F G]

/-- The generator and the blinding random oracle `hb` (§3.1). -/
structure Sys (F G : Type) where
  g : G
  hb : G → G → F

/-- `α_i`: `α_0` blinded through `i` hops with private keys `privKeys`. -/
def alphaSeq (S : Sys F G) (privKeys : ℕ → F) (alpha0 : G) : ℕ → G
  | 0 => alpha0
  | i + 1 =>
    let α := alphaSeq S privKeys alpha0 i
    let s := privKeys i • α
    S.hb α s • α

/-- `s_i = α_i^{x_{n_i}}`. -/
def sAt (S : Sys F G) (privKeys : ℕ → F) (alpha0 : G) (i : ℕ) : G :=
  privKeys i • alphaSeq S privKeys alpha0 i

end AlphaChain

/-! ## Problem P (§4.2)

Given random oracles `f_0, ..., f_{2^κ-1}`, `ρ̂`, `ρ0`, find `x, y` with `ρ̂(x) = f_{ρ0(x)}(y)`. -/

section ProblemP

variable {Seed Idx Yy Kappa : Type}

/-- An instance of Problem P. -/
structure ProblemPInstance (Seed Idx Yy Kappa : Type) where
  ρhat : Seed → Kappa
  ρ0 : Seed → Idx
  f : Idx → Yy → Kappa

/-- `(x, y)` solves `P` iff `ρ̂(x) = f_{ρ0(x)}(y)`. -/
def ProblemPInstance.Solves (P : ProblemPInstance Seed Idx Yy Kappa) (xy : Seed × Yy) : Prop :=
  P.ρhat xy.1 = P.f (P.ρ0 xy.1) xy.2

/-- A Problem P adversary: given the instance, output a candidate `(x, y)`. -/
abbrev ProblemPAdversary (Seed Idx Yy Kappa : Type) :=
  ProblemPInstance Seed Idx Yy Kappa → ProbComp (Seed × Yy)

/-- The adversary's success probability against a fixed instance. -/
noncomputable def problemPSuccessProb (P : ProblemPInstance Seed Idx Yy Kappa)
    (B : ProblemPAdversary Seed Idx Yy Kappa) : ℝ≥0∞ :=
  Pr[fun xy => P.Solves xy | B P]

/-- Hypothesis: Problem P is hard. -/
def ProblemPHard (ε : ℝ≥0∞) : Prop :=
  ∀ (P : ProblemPInstance Seed Idx Yy Kappa) (B : ProblemPAdversary Seed Idx Yy Kappa),
    problemPSuccessProb P B ≤ ε

end ProblemP

/-! ## The integrity game and its reduction to Problem P -/

section Integrity

variable {F G Seed Idx Yy Kappa : Type} [Field F] [AddCommGroup G] [Module F G]

/-- A forged header: `N` node private keys, all known to the adversary, and a forged `α_0`. -/
structure Forgery (F G : Type) where
  privKeys : ℕ → F
  alpha0 : G

/-- The Problem P instance a successful `N`-hop forgery reduces to. -/
def inducedInstance (ρhat0 : Seed → Kappa) (ρ0 : Seed → Idx) (f : Idx → Yy → Kappa) :
    ProblemPInstance Seed Idx Yy Kappa :=
  { ρhat := ρhat0, ρ0, f }

/-- `k_0 = hρ(s_0)`, Problem P's `x`. -/
def Forgery.k0 (S : Sys F G) (hρ : G → Seed) (fga : Forgery F G) : Seed :=
  hρ (sAt S fga.privKeys fga.alpha0 0)

/-- Every accepted forgery's `k_0` has a Problem P witness `y = (k_1, ..., k_{N-1}, k_μ)`. -/
def DecompositionWitness (S : Sys F G) (hρ : G → Seed) (ρhat0 : Seed → Kappa) (ρ0 : Seed → Idx)
    (f : Idx → Yy → Kappa) (Accepted : Forgery F G → Prop) : Prop :=
  ∀ fga : Forgery F G, Accepted fga → ∃ y : Yy, ρhat0 (fga.k0 S hρ) = f (ρ0 (fga.k0 S hρ)) y

/-- The reduction adversary: replay the honest chain to compute `k_0` and answer with the witness
from `hDecomp`. -/
noncomputable def reductionAdversary [Nonempty Yy] (S : Sys F G) (hρ : G → Seed)
    (ρhat0 : Seed → Kappa) (ρ0 : Seed → Idx) (f : Idx → Yy → Kappa)
    (Game : ProbComp (Forgery F G)) (Accepted : Forgery F G → Prop)
    (hDecomp : DecompositionWitness S hρ ρhat0 ρ0 f Accepted) :
    ProblemPAdversary Seed Idx Yy Kappa :=
  fun _ => do
    let fga ← Game
    if h : Accepted fga then
      pure (fga.k0 S hρ, (hDecomp fga h).choose)
    else
      pure (fga.k0 S hρ, Classical.arbitrary Yy)

/-- §4.2's bound: given `hDecomp`, the probability that `Game` accepts a forgery is bounded by
Problem P's hardness. -/
theorem integrity_bound [Nonempty Yy]
    (S : Sys F G) (hρ : G → Seed) (ρhat0 : Seed → Kappa) (ρ0 : Seed → Idx) (f : Idx → Yy → Kappa)
    (ε : ℝ≥0∞) (hhard : ProblemPHard (Seed := Seed) (Idx := Idx) (Yy := Yy) (Kappa := Kappa) ε)
    (Game : ProbComp (Forgery F G)) (Accepted : Forgery F G → Prop)
    (hDecomp : DecompositionWitness S hρ ρhat0 ρ0 f Accepted) :
    Pr[Accepted | Game] ≤ ε := by
  classical
  set B := reductionAdversary S hρ ρhat0 ρ0 f Game Accepted hDecomp with hB
  have hstep : Pr[Accepted | Game] ≤
      Pr[fun xy => (inducedInstance ρhat0 ρ0 f).Solves xy | B (inducedInstance ρhat0 ρ0 f)] := by
    have hB' : B (inducedInstance ρhat0 ρ0 f) =
        Game >>= fun fga => if h : Accepted fga then pure (fga.k0 S hρ, (hDecomp fga h).choose)
          else pure (fga.k0 S hρ, Classical.arbitrary Yy) := by
      simp only [hB, reductionAdversary]
    rw [hB', probEvent_bind_eq_tsum, probEvent_eq_tsum_ite]
    refine ENNReal.tsum_le_tsum fun fga => ?_
    by_cases hacc : Accepted fga
    · rw [if_pos hacc, dif_pos hacc, probEvent_pure]
      have hsolve : (inducedInstance ρhat0 ρ0 f).Solves (fga.k0 S hρ, (hDecomp fga hacc).choose) :=
        (hDecomp fga hacc).choose_spec
      rw [if_pos hsolve, mul_one]
    · rw [if_neg hacc]
      exact zero_le
  exact hstep.trans (hhard (inducedInstance ρhat0 ρ0 f) B)

/-- The statement of `integrity_bound`. -/
abbrev IntegrityBoundType [Nonempty Yy] (S : Sys F G) (hρ : G → Seed) (ρhat0 : Seed → Kappa)
    (ρ0 : Seed → Idx) (f : Idx → Yy → Kappa) :=
  ∀ (ε : ℝ≥0∞), ProblemPHard (Seed := Seed) (Idx := Idx) (Yy := Yy) (Kappa := Kappa) ε →
    ∀ (Game : ProbComp (Forgery F G)) (Accepted : Forgery F G → Prop),
    DecompositionWitness S hρ ρhat0 ρ0 f Accepted → Pr[Accepted | Game] ≤ ε

end Integrity

end Cryptlib.Protocols.Sphinx.Integrity

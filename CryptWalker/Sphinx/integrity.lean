/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.OracleComp.Constructions.SampleableType
import VCVio.EvalDist.Bool

/-! # §4.2: Integrity

Claim: an adversary who knows every mix node's private key still cannot forge a header that a
chain of `N = r + 1` honest nodes all accept, except with negligible probability. The paper's
proof replays honest per-hop processing along the adversary's forged `α_0`, derives an algebraic
identity for the last hop's MAC value (`γ_N = a_0 ⊕ ⋯ ⊕ a_{N-1}`) that it calls only "a careful,
but straightforward, calculation" without spelling out, and packages that identity into a
solution of a generic random-oracle problem ("Problem P") whose hardness is argued separately.

That identity — where `N = r + 1` is exactly what makes an adversary-controlled `β_0` term vanish
from `γ_N` — needs the same bit-exact multi-hop routing-info layout `createHeader`/`unwrapNIKE`
already carry, transcribed to `BitVec`s and pushed through an `N`-step induction; not attempted
here. It's instead `γNDecomposition`, a named hypothesis of `integrity_bound` (matching how this
project already isolates paper-asserted-but-unproved facts elsewhere, e.g. `WrapResistance`'s
`hbij`). Everything else here is real: the `α`-chain a forger would replay (`alphaSeq`/`sAt`),
Problem P as an actual game, and the reduction from the decomposition identity to a Problem P
bound. `problemPHard` is the paper's other named hypothesis, used but not re-derived. -/

namespace CryptWalker.Sphinx.Integrity

open OracleComp OracleSpec ENNReal
open scoped Classical

/-! ## Replaying the honest per-hop processing along a forged `α_0`

`sphinx.go`'s node-processing step (§3.6) advances `α_i ↦ α_i^{hb(α_i, s_i)}`, `s_i = α_i^{x_{n_i}}`;
an adversary knowing every `x_{n_i}` can compute this chain exactly as an honest node would. Same
blinding step `NIKESphinx.blind`/`WrapResistance` model, here over an abstract `Module F G`. -/

section AlphaChain

variable {F G : Type} [Field F] [AddCommGroup G] [Module F G]

/-- The generator and blinding random oracle `hb` (§3.1) needed to replay the `α`-chain. -/
structure Sys (F G : Type) where
  g : G
  hb : G → G → F

/-- `α_i` in the paper's notation: blind `α_0` through `i` honest hops, using hop `i`'s
(adversary-known) private key `privKeys i` at each step. -/
def alphaSeq (S : Sys F G) (privKeys : ℕ → F) (alpha0 : G) : ℕ → G
  | 0 => alpha0
  | i + 1 =>
    let α := alphaSeq S privKeys alpha0 i
    let s := privKeys i • α
    S.hb α s • α

/-- `s_i = α_i^{x_{n_i}}` in the paper's notation. -/
def sAt (S : Sys F G) (privKeys : ℕ → F) (alpha0 : G) (i : ℕ) : G :=
  privKeys i • alphaSeq S privKeys alpha0 i

end AlphaChain

/-! ## Problem P (§4.2)

Given a random-oracle family `f_0, ..., f_{2^κ-1} : {0,1}^κ → {0,1}^κ` and random oracles `ρ̂, ρ0`:
find `x, y` with `ρ̂(x) = f_{ρ0(x)}(y)`. Modeled over abstract types (`Seed`, family index `Idx`,
`f`'s domain `Yy`, shared output space `Kappa`) rather than fixed-width bitstrings, with `ρ̂, ρ0, f`
bundled as one `ProblemPInstance`. -/

section ProblemP

variable {Seed Idx Yy Kappa : Type}

/-- One instance of Problem P: the family `f`, and the two single oracles `ρ̂, ρ0`. -/
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

/-- **Hypothesis, not proved here**: the paper's own bound on Problem P — with `ρ̂, ρ0, f` modeled
as random oracles, an adversary doing significantly less than `2^κ` work succeeds only with
negligible probability. Generic random-oracle combinatorics, orthogonal to Sphinx, not re-derived
here. -/
def ProblemPHard (ε : ℝ≥0∞) : Prop :=
  ∀ (P : ProblemPInstance Seed Idx Yy Kappa) (B : ProblemPAdversary Seed Idx Yy Kappa),
    problemPSuccessProb P B ≤ ε

end ProblemP

/-! ## The integrity game and its reduction to Problem P -/

section Integrity

variable {F G Seed Idx Yy Kappa : Type} [Field F] [AddCommGroup G] [Module F G]

/-- A forged header: `N` node private keys (all known to the adversary, per the paper's threat
model) and a forged `α_0`. -/
structure Forgery (F G : Type) where
  privKeys : ℕ → F
  alpha0 : G

/-- An integrity adversary: a probabilistic algorithm producing a `Forgery`. -/
abbrev IntegrityAdversary (F G : Type) := ProbComp (Forgery F G)

/-- The Problem P instance a successful `N`-hop forgery reduces to: `hρ` keys `ρ̂`'s domain and
`f`'s family index off the honest chain's own shared secrets. -/
def inducedInstance (ρhat0 : Seed → Kappa) (ρ0 : Seed → Idx) (f : Idx → Yy → Kappa) :
    ProblemPInstance Seed Idx Yy Kappa :=
  { ρhat := ρhat0, ρ0, f }

/-- `k_0 = hρ(s_0)` for a given forgery — Problem P's own `x`. -/
def Forgery.k0 (S : Sys F G) (hρ : G → Seed) (fga : Forgery F G) : Seed :=
  hρ (sAt S fga.privKeys fga.alpha0 0)

/-- Every accepted forgery's `k_0` admits some Problem P witness `y` against `f`/`ρ0` — the paper's
`y = (k_1, ..., k_{N-1}, k_μ)`, read off the rest of that forgery's honest chain. -/
def DecompositionWitness (S : Sys F G) (hρ : G → Seed) (ρhat0 : Seed → Kappa) (ρ0 : Seed → Idx)
    (f : Idx → Yy → Kappa) (Accepted : Forgery F G → Prop) : Prop :=
  ∀ fga : Forgery F G, Accepted fga → ∃ y : Yy, ρhat0 (fga.k0 S hρ) = f (ρ0 (fga.k0 S hρ)) y

/-- The reduction adversary: replay the honest chain to compute `k_0`, and answer with whatever
decomposition witness `hDecomp` supplies for an accepted forgery (an arbitrary default
otherwise — harmless, since only success on `Accepted` is needed). -/
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

/-- **§4.2's bound**: given a decomposition witness (`hDecomp`, standing in for the paper's
unproved "careful but straightforward calculation") for every accepted forgery, the probability
`Game` produces one is bounded by Problem P's hardness — `reductionAdversary` solves the induced
instance at least as often as `Game` is accepted, and `problemPHard` bounds that. -/
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

/-- `integrity_bound`'s statement, closed over every scheme it's about. -/
abbrev IntegrityBoundType [Nonempty Yy] (S : Sys F G) (hρ : G → Seed) (ρhat0 : Seed → Kappa)
    (ρ0 : Seed → Idx) (f : Idx → Yy → Kappa) :=
  ∀ (ε : ℝ≥0∞), ProblemPHard (Seed := Seed) (Idx := Idx) (Yy := Yy) (Kappa := Kappa) ε →
    ∀ (Game : ProbComp (Forgery F G)) (Accepted : Forgery F G → Prop),
    DecompositionWitness S hρ ρhat0 ρ0 f Accepted → Pr[Accepted | Game] ≤ ε

end Integrity

end CryptWalker.Sphinx.Integrity

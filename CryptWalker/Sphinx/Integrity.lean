/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.OracleComp.Constructions.SampleableType
import VCVio.EvalDist.Bool

/-! # §4.2: Integrity (eprint 2008/475)

The paper's integrity claim: an adversary who knows *every* mix node's private key still cannot
construct a forged header that a chain of `N = r + 1` honest nodes all accept, except with
negligible probability. The proof replays the honest per-hop processing along the adversary's own
forged `α_0` (using the known private keys — "the adversary can process it in the manner of each
mix node in turn"), derives an algebraic identity for the last hop's MAC value
(`γ_N = a_0 ⊕ a_1 ⊕ ⋯ ⊕ a_{N-1}`, `a_j = ρ̂_j(hρ(α_j^{xj}))`) that the paper itself calls only "a
careful, but straightforward, calculation" without spelling out, and packages that identity into
a solution of a generic random-oracle problem ("Problem P") whose own hardness is argued
separately.

## Scope, and why

The identity above is where `N = r + 1` actually earns its keep: for a shorter chain the
computation of `γ_i` still carries `(2r − 1)κ` bits contributed by the adversary's own choice of
`β_0` ("the computation of `γr` contains bits from `β_0`"), so the adversary has real freedom
there and no hardness reduction is possible; at exactly `N = r + 1` hops that budget is *exactly*
exhausted and the `β_0` term vanishes from the formula, leaving `γ_N` a function only of the
(random-oracle) shared secrets. Formalizing that vanishing faithfully needs the same bit-exact,
multi-hop routing-info layout `NIKESphinx.createHeader`/`unwrapNIKE` already carry at the byte
level (the geometry in `Sphinx.Geometry`), transcribed one level down to `BitVec`s and pushed
through an `N`-step induction — real work, and, per the paper's own "not spelled out" treatment,
open-ended enough that this pass does not attempt it (see the project's implementation plan for
this file). Consistent with how this codebase already isolates deep, protocol-orthogonal or
paper-asserted-but-unproved facts as named hypotheses rather than re-deriving them
(`WrapResistance.lean`'s `hbij`, `NIKE.X25519`'s `curve25519_commutes`), that one identity is
`γNDecomposition` below: a hypothesis of `integrity_bound`, not a theorem of this file. Everything
else here is real: the `α`-chain a forging adversary would have to replay (`alphaSeq`/`sAt`,
concrete and provable), Problem P as an actual game (`ProblemPInstance`/`problemPSuccessProb`),
and the packaging step from the decomposition identity to a Problem P bound
(`integrity_bound`'s proof proper). `problemPHard` is the paper's other named hypothesis — a
generic random-oracle combinatorics fact, orthogonal to Sphinx, on the same footing as
`DiffieHellman`'s DDH assumption elsewhere in this project (used, never re-derived). -/

namespace CryptWalker.Sphinx.Integrity

open OracleComp OracleSpec ENNReal
open scoped Classical

/-! ## Replaying the honest per-hop processing along a forged `α_0`

`sphinx.go`'s node-processing step (§3.6) advances `α_i ↦ α_i^{hb(α_i, s_i)}` where
`s_i = α_i^{x_{n_i}}`; an adversary who knows every `x_{n_i}` can compute this chain exactly as an
honest node would (the paper: "the adversary can process it in the manner of each mix node in
turn"). This is genuinely the same blinding step `NIKESphinx.blind`/`WrapResistance` already
model, restated over an abstract `Module F G` rather than X25519, as `WrapResistance.lean` itself
already does for §4.3. -/

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

/-! ## Problem P

eprint 2008/475 §4.2: "Let `f_0, ..., f_{2^κ-1}` be a family of random oracles with range
`{0,1}^κ`. Let `ρ̂` and `ρ0` be other random oracles with range `{0,1}^κ`. ... The problem is to
find `x` and `y` such that `ρ̂(x) = f_{ρ0(x)}(y)`." Modeled here over abstract types (the seed
space `Seed`, the family index `Idx`, `f`'s own domain `Yy`, and the shared output space `Kappa`)
rather than fixed-width bitstrings, and with `ρ̂, ρ0, f` given as one fixed `ProblemPInstance`
(the paper's "modeled as random oracles" is the *reason* `problemPHard` below is a believable
hypothesis, not something this file samples itself — the same treatment `DiffieHellman.lean`'s
`(g, ...)` group parameters get). -/

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

/-- **Hypothesis, not proved here**: eprint 2008/475's own bound on Problem P. With `ρ̂, ρ0, f`
modeled as random oracles, any adversary doing significantly less than `2^κ` work succeeds with
only negligible probability (the paper's own proof, via a birthday-style collision-counting
argument over the query transcript, gives an explicit `(κ-m)/κ · 2^{m-κ}`-shaped bound for an
adversary doing `2^m` work) — a generic random-oracle combinatorics fact, orthogonal to Sphinx's
own design, so not re-derived here. -/
def ProblemPHard (ε : ℝ≥0∞) : Prop :=
  ∀ (P : ProblemPInstance Seed Idx Yy Kappa) (B : ProblemPAdversary Seed Idx Yy Kappa),
    problemPSuccessProb P B ≤ ε

end ProblemP

/-! ## The integrity game and its reduction to Problem P -/

section Integrity

variable {F G Seed Idx Yy Kappa : Type} [Field F] [AddCommGroup G] [Module F G]

/-- A forged header: `N` node private keys (all known to the adversary — the paper's threat
model, "even if we allow the adversary to know all private keys"), and a forged `α_0`. -/
structure Forgery (F G : Type) where
  privKeys : ℕ → F
  alpha0 : G

/-- An integrity adversary: a probabilistic algorithm producing a `Forgery`. -/
abbrev IntegrityAdversary (F G : Type) := ProbComp (Forgery F G)

/-- The Problem P instance a successful `N`-hop forgery reduces to: `hρ` keys `ρ̂`'s domain and
`f`'s family index off the honest chain's own shared secrets. `ρhat`/`f` are the paper's `ρ̂_j`
(hop-indexed) and `f_{ρ0(x)}` families, packaged as one `ProblemPInstance` the way the paper's own
reduction does ("`k_i = hρ(α_i^{xi})` and `kμ = hμ(α_N^{xN})`... this is just problem P"). -/
def inducedInstance (ρhat0 : Seed → Kappa) (ρ0 : Seed → Idx) (f : Idx → Yy → Kappa) :
    ProblemPInstance Seed Idx Yy Kappa :=
  { ρhat := ρhat0, ρ0, f }

/-- `k_0 = hρ(s_0)` for a given forgery — Problem P's own `x`. -/
def Forgery.k0 (S : Sys F G) (hρ : G → Seed) (fga : Forgery F G) : Seed :=
  hρ (sAt S fga.privKeys fga.alpha0 0)

/-- The decomposition hypothesis's shape: every accepted forgery's `k_0` admits *some* Problem P
witness `y` against `f`/`ρ0` (the specific `y` genuinely depends on the forgery — the paper's own
`y = (k_1, ..., k_{N-1}, k_μ)`, read off the rest of that forgery's honest chain). -/
def DecompositionWitness (S : Sys F G) (hρ : G → Seed) (ρhat0 : Seed → Kappa) (ρ0 : Seed → Idx)
    (f : Idx → Yy → Kappa) (Accepted : Forgery F G → Prop) : Prop :=
  ∀ fga : Forgery F G, Accepted fga → ∃ y : Yy, ρhat0 (fga.k0 S hρ) = f (ρ0 (fga.k0 S hρ)) y

/-- The reduction adversary: replay the honest chain far enough to compute `k_0`, and answer
with whatever decomposition witness `hDecomp` supplies for an accepted forgery (any fixed
default otherwise — it costs nothing, since `hDecomp` guarantees the reduction only needs to
succeed on the event `Accepted`, and success elsewhere can only help, never hurt,
`problemPSuccessProb`'s lower bound on that event). -/
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

/-- **§4.2's bound**: if every accepted forgery admits a decomposition witness for `inducedInstance
hρ ρhat0 ρ0 f` (`hDecomp` — the paper's own, unproved-here, "careful but straightforward
calculation"; see the module doc for exactly what it stands in for), then the probability that
`Game` produces one is bounded by Problem P's own hardness. This is the genuinely mechanical half
of the paper's argument: `hDecomp` supplies, event-by-event, a Problem P solution whenever
`Accepted` holds, so the constructed `reductionAdversary` solves the induced instance at least as
often as `Game` is accepted (`probEvent_mono`), and `problemPHard` bounds *that*. -/
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

end Integrity

end CryptWalker.Sphinx.Integrity

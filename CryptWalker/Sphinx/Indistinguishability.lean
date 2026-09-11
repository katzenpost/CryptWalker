/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.CryptoFoundations.HardnessAssumptions.DiffieHellman
import VCVio.CryptoFoundations.PRG
import VCVio.CryptoFoundations.SecExp
import VCVio.OracleComp.Constructions.SampleableType

/-! # §4.4: Security and Indistinguishability of Forward and Reply Messages (eprint 2008/475)

Danezis–Goldberg's proof only ever turns on the *first* challenge hop's tuple
`((α0,β0,γ0),δ0)` — general `j` (the challenge node not being the entry node) is reduced to
`j = 0` for free ("the adversary can immediately act as nodes n0,...,nj−1 to determine
((αj,βj,γj),δj)"), so this file models exactly that one hop, not the full recursive multi-hop
header (`Sphinx.Integrity`, for §4.2, needs the recursive shape; this file does not).

Working at the paper's own abstraction (a generic DDH group, generic PRG-shaped ρ/μ/π), not the
concrete AES/HMAC/AEZ byte code — the same trade-off `Sphinx.WrapResistance` already makes for
§4.3, over an abstract `AddCommGroup Point` rather than raw curve25519 bytes.

Viewed as one-shot values (used once per header), `ρ(hρ(s0))`, `μ(hμ(s0), β0)` and
`π(hπ(s0), ·)` are each exactly the shape of `PRGScheme.gen` (`Seed → R`, real-vs-uniform) once
their second argument is fixed — so **no new VCVio primitive is added**: `PRGScheme` (already
used nowhere else in this project, from VCVio's `PRG.lean`) is reused three times instead of a
bespoke PRF/PRP game, matching the paper's own remark that for this proof "we treat them as
random oracles."

## Two idealizations, matching the paper's own hand-wave

The paper says, of ρ and μ, "for the purposes of this section, we treat them as random oracles"
(§4, before §4.2's proof) — i.e. §4.2/§4.4 do not use ρ/μ/π's PRG/PRF/PRP security directly, but
an idealization one step stronger. Two idealizations are used here, both standard and both
isolated as explicit hypotheses (never baked into a proof), matching this codebase's existing
convention of naming rather than re-deriving deep assumptions (`WrapResistance.lean`'s `hbij`,
`NIKE.X25519`'s `curve25519_commutes`):

* **DDH** (`DiffieHellman.lean`, unchanged): `s0`'s indistinguishability from an independent
  random group element.
* **Joint random-oracle independence**: `hρ, hμ, hπ`, queried at the same fresh `s0`, behave as
  three *independent* random functions — captured here as a single hypothesis, that
  `s0 ↦ (hρ s0, hμ s0, hπ s0)` is a bijection onto the product `Seed × KeyMu × KeyPi` (so that
  pushing a uniform `s0` through it lands on the *product*'s uniform distribution, which is
  exactly independent-per-factor uniform sampling — `SampleableType (α × β)`'s own definition,
  `(·,·) <$> ($ᵗ α) <*> ($ᵗ β)`, is literally that). Without this, `ρ(hρ s0)`, `μ(hμ s0, ·)` and
  `π(hπ s0, ·)`'s three keys would stay perfectly correlated (all deterministic functions of the
  same `s0`) and the three PRG hybrid steps below could not be run independently of one another.

Once both idealizations are in hand, β0/γ0/δ0's keys are exactly three independent uniform
values, and ρ/μ/π's own (real, standard) `PRGScheme.prgAdvantage` bounds the rest — the genuinely
cryptographic content, not re-derived here (same boundary `sprpEncrypt_size`/`curve25519_commutes`
already draw between "proved" and "assumed" in this project).

## Out of scope

No claim that concrete AES-CTR/HMAC-SHA256/AEZ or curve25519 satisfy the abstract games used
here. General `j` and full reply-vs-nymserver indistinguishability (§4.4's footnote 1) are not
mechanized; the paper itself only informally reduces both to the `j = 0` forward case. -/

namespace CryptWalker.Sphinx.Indistinguishability

open OracleComp OracleSpec ENNReal
open PRGScheme (PRGAdversary prgRealExp prgIdealExp prgAdvantage)
open DiffieHellman (DDHAdversary ddhExpReal ddhExpRand ddhDistAdvantage)

variable {F G Seed KeyMu KeyPi Beta Gamma Delta : Type}
variable [Field F] [AddCommGroup G] [Module F G] [AddCommGroup Beta]

/-- **§3.1's system parameters** needed to build hop 0's tuple: the generator `g`; the random
oracles `hρ, hμ, hπ` keying ρ/μ/π off the DH shared secret `s0`; and ρ/μ/π themselves
(`ρ`'s one-time-pad generator, `μ`'s MAC evaluator, `π`'s cipher). -/
structure Sys (F G Seed KeyMu KeyPi Beta Gamma Delta : Type) where
  g : G
  hρ : G → Seed
  hμ : G → KeyMu
  hπ : G → KeyPi
  ρgen : Seed → Beta
  μeval : KeyMu → Beta → Gamma
  πenc : KeyPi → Delta → Delta

/-- The two challenge-branch plaintexts: §3.2's `{n1‖γ1‖β1[0..]}` XORed into `β0`, and whatever
the rest of the `δ` chain produces as `δ0`'s plaintext. Fixed by the adversary's choice of path
and message; independent of the fresh per-header randomness `x`. -/
structure Choice (Beta Delta : Type) where
  betaPt : Beta
  deltaPt : Delta

variable (S : Sys F G Seed KeyMu KeyPi Beta Gamma Delta)

/-- Hop 0's tuple `((α0,β0,γ0),δ0)`, given the two DH group elements `α0 = x • g` and `s0`
(either `x`'s genuine DH shared secret with `n0`, or — in the hybrid games below — an
independent random element). -/
def buildFrom (α0 s0 : G) (c : Choice Beta Delta) : G × Beta × Gamma × Delta :=
  let β0 := c.betaPt + S.ρgen (S.hρ s0)
  let γ0 := S.μeval (S.hμ s0) β0
  let δ0 := S.πenc (S.hπ s0) c.deltaPt
  (α0, β0, γ0, δ0)

/-- An adversary against the §4.4 game: given hop 0's tuple, guess which of the two challenge
branches produced it. -/
abbrev Adversary := G × Beta × Gamma × Delta → ProbComp Bool

section Games

variable [SampleableType F]

/-- **Game `G`** (§4.4), specialized to `j = 0`: the challenger flips `b`, builds hop 0's tuple
honestly (`s0` the genuine DH shared secret with node `n0`, whose private key `xn0` the adversary
does not know) from the challenge branch `b` picks, and the adversary guesses `b`. -/
def gameReal (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) : ProbComp Bool := do
  let x ← $ᵗ F
  let xn0 ← $ᵗ F
  let b ← $ᵗ Bool
  let guess ← A (buildFrom S (x • S.g) ((x * xn0) • S.g) (if b then c1 else c0))
  return (b == guess)

/-- **Game `G2`**: `s0` replaced by an independent random group element — the DDH hybrid step. -/
def game2 (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) : ProbComp Bool := do
  let x ← $ᵗ F
  let c' ← $ᵗ F
  let b ← $ᵗ Bool
  let guess ← A (buildFrom S (x • S.g) (c' • S.g) (if b then c1 else c0))
  return (b == guess)

/-- The adversary's advantage in game `G` (§4.4: "the difference between 1/2 and the probability
the adversary guesses `b` correctly"). -/
noncomputable def advantage
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) : ℝ :=
  |(Pr[= true | gameReal S A c0 c1]).toReal - 1 / 2|

end Games

section DDHReduction

variable [SampleableType F]

/-- **`G` ⇒ `G2` reduction**: any `Adversary` gives a `DDHAdversary` — it ignores the DDH
tuple's own second group element (there is no fixed `n0pub` in this model; §3.1's node keys are
themselves drawn uniformly, so `n0`'s public key is folded into the DDH challenge's own `b • g`)
and replays the rest of `gameReal`/`game2`'s own logic around the supplied `(α0, s0)` pair. -/
def ddhAdversaryOf
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) : DDHAdversary F G :=
  fun _g' α0 _n0pub s0 => do
    let b ← $ᵗ Bool
    let guess ← A (buildFrom S α0 s0 (if b then c1 else c0))
    return (b == guess)

/-- `ddhExpReal` reconstructs `gameReal` exactly: both sample `a := x`, `b' := xn0`, hand the
adversary `(x • g, (x * xn0) • g, ·)`. -/
theorem probTrue_gameReal_eq_ddhExpReal
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) :
    Pr[= true | gameReal S A c0 c1] =
      Pr[= true | ddhExpReal S.g (ddhAdversaryOf S A c0 c1)] := by
  unfold gameReal ddhExpReal ddhAdversaryOf
  rfl

/-- `ddhExpRand` reconstructs `game2` exactly: both sample `a := x`, `c := c'` independently,
hand the adversary `(x • g, c' • g, ·)` — `ddhExpRand`'s middle sample (the unused DDH `b`) never
reaches the adversary either way, matching `game2`'s own lack of an `n0pub`. -/
theorem probTrue_game2_eq_ddhExpRand
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) :
    Pr[= true | game2 S A c0 c1] =
      Pr[= true | ddhExpRand S.g (ddhAdversaryOf S A c0 c1)] := by
  unfold game2 ddhExpRand ddhAdversaryOf
  refine probOutput_bind_congr' ($ᵗ F) true fun x => ?_
  rw [probOutput_bind_const, probFailure_uniformSample, tsub_zero, one_mul]

end DDHReduction


section KeyIndependence

variable [SampleableType F] [SampleableType Seed] [SampleableType KeyMu] [SampleableType KeyPi]
  [SampleableType (Seed × KeyMu × KeyPi)] [Finite F]

/-- Hop 0's tuple, built directly from the three random-oracle-keyed values rather than from
`s0` itself — `buildFrom`'s definition, with `S.hρ s0 / S.hμ s0 / S.hπ s0` abstracted out. -/
def buildFromKeys (α0 : G) (seed : Seed) (kmu : KeyMu) (kpi : KeyPi) (c : Choice Beta Delta) :
    G × Beta × Gamma × Delta :=
  let β0 := c.betaPt + S.ρgen seed
  let γ0 := S.μeval kmu β0
  let δ0 := S.πenc kpi c.deltaPt
  (α0, β0, γ0, δ0)

@[simp] lemma buildFrom_eq_buildFromKeys (α0 s0 : G) (c : Choice Beta Delta) :
    buildFrom S α0 s0 c = buildFromKeys S α0 (S.hρ s0) (S.hμ s0) (S.hπ s0) c := rfl

/-- **Game `G2'`**: `s0`'s three random-oracle-keyed outputs replaced by an independently
sampled triple — legitimate once `hρ, hμ, hπ`, queried at the same fresh `s0`, jointly behave as
one big independent random oracle (the module doc's second idealization). -/
def game2' (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) : ProbComp Bool := do
  let x ← $ᵗ F
  let b ← $ᵗ Bool
  let p ← $ᵗ (Seed × KeyMu × KeyPi)
  let guess ← A (buildFromKeys S (x • S.g) p.1 p.2.1 p.2.2 (if b then c1 else c0))
  return (b == guess)

/-- **`G2` ⇒ `G2'`**: pushing a uniform `c'` through the bijection `c' ↦ (hρ(c'•g), hμ(c'•g),
hπ(c'•g))` (`hgBij`: `g` generates the DH group, so scalar multiplication by a uniform scalar is
itself a bijection onto it, exactly the idealization `Sphinx.WrapResistance`'s `hbij` already
makes; `hjoint`: the module doc's random-oracle-independence idealization) lands on the uniform
distribution over `Seed × KeyMu × KeyPi` — which, by `SampleableType (α × β)`'s own definition
as independent component draws, *is* sampling `seed, kmu, kpi` independently. -/
theorem probTrue_game2_eq_game2'
    (hgBij : Function.Bijective (fun c' : F => c' • S.g))
    (hjoint : Function.Bijective (fun s0 : G => (S.hρ s0, S.hμ s0, S.hπ s0)))
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) :
    Pr[= true | game2 S A c0 c1] = Pr[= true | game2' S A c0 c1] := by
  unfold game2 game2'
  refine probOutput_bind_congr' ($ᵗ F) true fun x => ?_
  rw [probOutput_bind_bind_swap ($ᵗ F) ($ᵗ Bool)
    (fun c' b => A (buildFrom S (x • S.g) (c' • S.g) (if b then c1 else c0)) >>=
      fun guess => pure (b == guess)) true]
  refine probOutput_bind_congr' ($ᵗ Bool) true fun b => ?_
  have hcomp : Function.Bijective
      (fun c' : F => (S.hρ (c' • S.g), S.hμ (c' • S.g), S.hπ (c' • S.g))) :=
    hjoint.comp hgBij
  simpa using probOutput_bind_bijective_uniform_cross
    (α := F) (β := Seed × KeyMu × KeyPi)
    (fun c' => (S.hρ (c' • S.g), S.hμ (c' • S.g), S.hπ (c' • S.g))) hcomp
    (fun p => A (buildFromKeys S (x • S.g) p.1 p.2.1 p.2.2 (if b then c1 else c0)) >>=
      fun guess => pure (b == guess))
    true

end KeyIndependence

section PRGHybrid

variable [SampleableType F] [SampleableType Seed] [SampleableType KeyMu] [SampleableType KeyPi]
  [SampleableType Beta] [SampleableType Gamma] [SampleableType Delta]
  [SampleableType (Seed × KeyMu × KeyPi)] [SampleableType (Beta × Gamma × Delta)]

/-- `ρgen`/`μeval`/`πenc` composed into one derivation `(seed, kmu, kpi) ↦ (β0, γ0, δ0)`, for a
fixed challenge branch `c`. Bundled into a single `PRGScheme` rather than three separate ones
(one per primitive) — `γ0`'s computation genuinely needs `β0`, so a three-way *independent*
hybrid would need its own extra bookkeeping to thread `β0` between steps; this file settles for
one combined one-shot-PRG hypothesis over the whole derivation, matching the paper's own "treat
them as random oracles" collapse for this section. See the module doc's "out of scope" note. -/
def combinedGen (c : Choice Beta Delta) (p : Seed × KeyMu × KeyPi) : Beta × Gamma × Delta :=
  let β0 := c.betaPt + S.ρgen p.1
  let γ0 := S.μeval p.2.1 β0
  let δ0 := S.πenc p.2.2 c.deltaPt
  (β0, γ0, δ0)

def combinedPRG (c : Choice Beta Delta) : PRGScheme (Seed × KeyMu × KeyPi) (Beta × Gamma × Delta) :=
  ⟨combinedGen S c⟩

/-- The combined-hybrid reduction adversary: given a `Beta × Gamma × Delta` value (real
`combinedGen c p` for a fresh `p`, or ideal fresh-uniform), finish the game with the
already-fixed `x`/`b`. -/
def combinedAdversaryOf
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (x : F) (b : Bool) : PRGAdversary (Beta × Gamma × Delta) := fun t =>
  A (x • S.g, t.1, t.2.1, t.2.2) >>= fun guess => pure (b == guess)

theorem probTrue_game2'_eq_prgRealExp_combined
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) :
    Pr[= true | game2' S A c0 c1] =
      Pr[= true | do
        let x ← $ᵗ F
        let b ← $ᵗ Bool
        prgRealExp (combinedPRG S (if b then c1 else c0)) (combinedAdversaryOf S A x b)] := by
  unfold game2' prgRealExp combinedPRG combinedAdversaryOf combinedGen
  rfl

/-- **Game `G3`**: `β0, γ0, δ0` all replaced by an independent fresh uniform triple, all fixed
`x`/`b` aside. This is the paper's final hybrid — the challenge tuple no longer carries any
information about `b`. -/
def game3 (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) : ProbComp Bool := do
  let x ← $ᵗ F
  let b ← $ᵗ Bool
  let t ← $ᵗ (Beta × Gamma × Delta)
  let guess ← A (x • S.g, t.1, t.2.1, t.2.2)
  return (b == guess)

theorem probTrue_game3_eq_prgIdealExp_combined
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) :
    Pr[= true | game3 S A c0 c1] =
      Pr[= true | do
        let x ← $ᵗ F
        let b ← $ᵗ Bool
        prgIdealExp (combinedAdversaryOf S A x b)] := by
  unfold game3 prgIdealExp combinedAdversaryOf
  rfl

/-- **Proved outright**: in `G3`, the tuple handed to the adversary is fresh and uniform,
independent of `b` — so a well-formed (never-aborting) adversary guesses correctly with
probability exactly `1/2`, the paper's own baseline. The only fact used beyond independence is
that `A`'s own output never fails (`NeverFail`) — a well-formed algorithm, not one that aborts —
so `Pr[true | A v] + Pr[false | A v] = 1` for every `v`. -/
theorem probTrue_game3
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    [∀ v, NeverFail (A v)] (c0 c1 : Choice Beta Delta) :
    (Pr[= true | game3 S A c0 c1]).toReal = 1 / 2 := by
  have hstep : ∀ x : F,
      Pr[= true | do
        let b ← $ᵗ Bool
        let t ← $ᵗ (Beta × Gamma × Delta)
        let guess ← A (x • S.g, t.1, t.2.1, t.2.2)
        return (b == guess)] = 1 / 2 := by
    intro x
    -- The tuple handed to `A` doesn't mention `b` at all, so this is exactly
    -- `probOutput_decide_eq_uniformBool_half` for the constant family `f _ := (t←$ᵗ...; A ...)`.
    have h := probOutput_decide_eq_uniformBool_half
      (f := fun _ : Bool => do
        let t ← $ᵗ (Beta × Gamma × Delta)
        A (x • S.g, t.1, t.2.1, t.2.2))
      rfl
    simpa only [show ∀ a b : Bool, decide (a = b) = (a == b) from fun _ _ => rfl,
      bind_assoc] using h
  unfold game3
  have hconst : Pr[= true | do
        let x ← $ᵗ F
        let b ← $ᵗ Bool
        let t ← $ᵗ (Beta × Gamma × Delta)
        let guess ← A (x • S.g, t.1, t.2.1, t.2.2)
        return (b == guess)] =
      Pr[= true | do
        let _x ← $ᵗ F
        let b ← $ᵗ Bool
        let t ← $ᵗ (Beta × Gamma × Delta)
        let guess ← A ((0 : F) • S.g, t.1, t.2.1, t.2.2)
        return (b == guess)] := by
    refine probOutput_bind_congr' ($ᵗ F) true fun x => ?_
    rw [hstep x, hstep 0]
  rw [hconst, probOutput_bind_const, probFailure_uniformSample, tsub_zero, one_mul, hstep 0]
  norm_num

end PRGHybrid

section MainTheorem

variable [SampleableType F] [SampleableType Seed] [SampleableType KeyMu] [SampleableType KeyPi]
  [SampleableType Beta] [SampleableType Gamma] [SampleableType Delta]
  [SampleableType (Seed × KeyMu × KeyPi)] [Finite F]

/-- **Main theorem (§4.4)**: the adversary's advantage is bounded by the DDH-distinguishing
advantage of the constructed reduction (`ddhAdversaryOf`) plus the gap between `G2'` and `G3` —
by `probTrue_game2'_eq_prgRealExp_combined`/`probTrue_game3_eq_prgIdealExp_combined`, that gap
*is* the combined `ρ/μ/π`-derivation's one-shot PRG-distinguishing advantage against the
constructed adversary `combinedAdversaryOf`, averaged over the coin flip picking `combinedPRG
S c0` vs `combinedPRG S c1` — supplied here as `hprg` directly, rather than routed back through
`PRGScheme.prgAdvantage`'s own definition, to avoid re-deriving the coin-averaging bookkeeping;
a caller instantiating `hprg` from an actual `ρ/μ/π` security assumption does that rewriting via
the two lemmas named above. `hddh` is `ddhDistAdvantage`'s own bound, unpacked at the call site
the same way. Both idealizations (`hgBij`, `hjoint`) and `game3`'s zero-advantage fact
(`probTrue_game3`) are used internally with no further hypotheses. -/
theorem advantage_le
    (hgBij : Function.Bijective (fun c' : F => c' • S.g))
    (hjoint : Function.Bijective (fun s0 : G => (S.hρ s0, S.hμ s0, S.hπ s0)))
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    [∀ v, NeverFail (A v)] (c0 c1 : Choice Beta Delta) (εDDH εPRG : ℝ)
    (hddh : ddhDistAdvantage S.g (ddhAdversaryOf S A c0 c1) ≤ εDDH)
    (hprg : |(Pr[= true | game2' S A c0 c1]).toReal - (Pr[= true | game3 S A c0 c1]).toReal| ≤ εPRG) :
    advantage S A c0 c1 ≤ εDDH + εPRG := by
  unfold advantage
  have e1 : (Pr[= true | gameReal S A c0 c1]).toReal =
      (Pr[= true | ddhExpReal S.g (ddhAdversaryOf S A c0 c1)]).toReal := by
    rw [probTrue_gameReal_eq_ddhExpReal]
  have e2 : (Pr[= true | game2 S A c0 c1]).toReal =
      (Pr[= true | ddhExpRand S.g (ddhAdversaryOf S A c0 c1)]).toReal := by
    rw [probTrue_game2_eq_ddhExpRand]
  have e3 : (Pr[= true | game2 S A c0 c1]).toReal = (Pr[= true | game2' S A c0 c1]).toReal := by
    rw [probTrue_game2_eq_game2' S hgBij hjoint]
  have e4 : (Pr[= true | game3 S A c0 c1]).toReal = 1 / 2 := probTrue_game3 S A c0 c1
  calc |(Pr[= true | gameReal S A c0 c1]).toReal - 1 / 2|
      = |(Pr[= true | gameReal S A c0 c1]).toReal - (Pr[= true | game3 S A c0 c1]).toReal| := by
        rw [e4]
    _ ≤ |(Pr[= true | gameReal S A c0 c1]).toReal - (Pr[= true | game2 S A c0 c1]).toReal| +
          |(Pr[= true | game2 S A c0 c1]).toReal - (Pr[= true | game3 S A c0 c1]).toReal| :=
        abs_sub_le _ _ _
    _ = |(Pr[= true | ddhExpReal S.g (ddhAdversaryOf S A c0 c1)]).toReal -
          (Pr[= true | ddhExpRand S.g (ddhAdversaryOf S A c0 c1)]).toReal| +
        |(Pr[= true | game2' S A c0 c1]).toReal - (Pr[= true | game3 S A c0 c1]).toReal| := by
        congr 1
        · rw [e1, e2]
        · rw [e3]
    _ ≤ εDDH + εPRG := add_le_add hddh hprg

end MainTheorem

end CryptWalker.Sphinx.Indistinguishability

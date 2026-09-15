/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.CryptoFoundations.HardnessAssumptions.DiffieHellman
import VCVio.CryptoFoundations.PRG
import VCVio.CryptoFoundations.SecExp
import VCVio.OracleComp.Constructions.SampleableType

/-! # §4.4: Security and Indistinguishability of Forward and Reply Messages

The paper's proof only turns on the *first* challenge hop's tuple `((α0,β0,γ0),δ0)` — general `j`
reduces to `j = 0` for free — so this file models just that one hop, not the full recursive
multi-hop header `Integrity` (§4.2) needs. Works at the paper's own abstraction (generic DDH
group, generic PRG-shaped ρ/μ/π), not concrete AES/HMAC/AEZ byte code, the same trade-off
`WrapResistance` makes for §4.3.

`ρ(hρ(s0))`, `μ(hμ(s0), β0)`, `π(hπ(s0), ·)`, viewed as one-shot values, are each exactly
`PRGScheme.gen`'s shape once their second argument is fixed, so no new VCVio primitive is
needed — `PRGScheme` is reused three times instead of a bespoke PRF/PRP game.

## One idealization, one computational assumption

Two hypotheses, both isolated as explicit arguments rather than baked into a proof:

* **DDH** (`DiffieHellman.lean`, unchanged): `s0`'s indistinguishability from an independent
  random group element.
* **Joint random-oracle independence**: `hρ, hμ, hπ`, queried at the same fresh `s0`, behave as
  three independent random functions. Modeled as a `PRGScheme` (`jointKeyPRG` below) rather than
  an exact bijection — a bijection would be false for any real expanding KDF (pigeonhole) — so
  the gap it introduces is bounded by that PRG's own advantage like the other hybrid steps.

## Out of scope

No claim that concrete AES-CTR/HMAC-SHA256/AEZ or curve25519 satisfy the abstract games here.
General `j` and full reply-vs-nymserver indistinguishability (§4.4 footnote 1) aren't mechanized;
the paper itself only informally reduces both to the `j = 0` forward case. -/

namespace CryptWalker.Sphinx.Indistinguishability

open OracleComp OracleSpec ENNReal
open PRGScheme (PRGAdversary prgRealExp prgIdealExp prgAdvantage)
open DiffieHellman (DDHAdversary ddhExpReal ddhExpRand ddhDistAdvantage)

variable {F G Seed KeyMu KeyPi Beta Gamma Delta : Type}
variable [Field F] [AddCommGroup G] [Module F G] [AddCommGroup Beta]

/-- **§3.1's system parameters** for hop 0's tuple: the generator `g`; the random oracles
`hρ, hμ, hπ` keying ρ/μ/π off the DH shared secret `s0`; and ρ/μ/π themselves. -/
structure Sys (F G Seed KeyMu KeyPi Beta Gamma Delta : Type) where
  g : G
  hρ : G → Seed
  hμ : G → KeyMu
  hπ : G → KeyPi
  ρgen : Seed → Beta
  μeval : KeyMu → Beta → Gamma
  πenc : KeyPi → Delta → Delta

/-- The two challenge-branch plaintexts: §3.2's `{n1‖γ1‖β1[0..]}` XORed into `β0`, and `δ0`'s
plaintext. Fixed by the adversary's choice of path/message, independent of the fresh `x`. -/
structure Choice (Beta Delta : Type) where
  betaPt : Beta
  deltaPt : Delta

variable (S : Sys F G Seed KeyMu KeyPi Beta Gamma Delta)

/-- Hop 0's tuple `((α0,β0,γ0),δ0)`, given `α0 = x • g` and `s0` (either `x`'s genuine DH shared
secret with `n0`, or an independent random element in the hybrid games below). -/
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
honestly from the branch `b` picks (`s0` the genuine DH shared secret, `xn0` unknown to the
adversary), and the adversary guesses `b`. -/
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

/-- The adversary's advantage in game `G`: distance from a coin-flip guess. -/
noncomputable def advantage
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) : ℝ :=
  |(Pr[= true | gameReal S A c0 c1]).toReal - 1 / 2|

end Games

section DDHReduction

variable [SampleableType F]

/-- **`G` ⇒ `G2` reduction**: any `Adversary` gives a `DDHAdversary` — it ignores the DDH tuple's
second group element (no fixed `n0pub` in this model) and replays `gameReal`/`game2`'s logic
around the supplied `(α0, s0)`. -/
def ddhAdversaryOf
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) : DDHAdversary F G :=
  fun _g' α0 _n0pub s0 => do
    let b ← $ᵗ Bool
    let guess ← A (buildFrom S α0 s0 (if b then c1 else c0))
    return (b == guess)

/-- `ddhExpReal` reconstructs `gameReal` exactly. -/
theorem probTrue_gameReal_eq_ddhExpReal
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) :
    Pr[= true | gameReal S A c0 c1] =
      Pr[= true | ddhExpReal S.g (ddhAdversaryOf S A c0 c1)] := by
  unfold gameReal ddhExpReal ddhAdversaryOf
  rfl

/-- `ddhExpRand` reconstructs `game2` exactly (its unused middle DDH sample never reaches the
adversary, matching `game2`'s lack of an `n0pub`). -/
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

/-- `buildFrom`, with `S.hρ s0 / S.hμ s0 / S.hπ s0` abstracted to plain arguments. -/
def buildFromKeys (α0 : G) (seed : Seed) (kmu : KeyMu) (kpi : KeyPi) (c : Choice Beta Delta) :
    G × Beta × Gamma × Delta :=
  let β0 := c.betaPt + S.ρgen seed
  let γ0 := S.μeval kmu β0
  let δ0 := S.πenc kpi c.deltaPt
  (α0, β0, γ0, δ0)

@[simp] lemma buildFrom_eq_buildFromKeys (α0 s0 : G) (c : Choice Beta Delta) :
    buildFrom S α0 s0 c = buildFromKeys S α0 (S.hρ s0) (S.hμ s0) (S.hπ s0) c := rfl

/-- **Game `G2'`**: `s0`'s three random-oracle-keyed outputs replaced by an independently sampled
triple (the module doc's joint-independence idealization). -/
def game2' (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) : ProbComp Bool := do
  let x ← $ᵗ F
  let b ← $ᵗ Bool
  let p ← $ᵗ (Seed × KeyMu × KeyPi)
  let guess ← A (buildFromKeys S (x • S.g) p.1 p.2.1 p.2.2 (if b then c1 else c0))
  return (b == guess)

/-- **`G2` ⇒ `G2'` is a PRG hybrid step, not an exact equality**: the map
`c' ↦ (hρ(c'•g), hμ(c'•g), hπ(c'•g))` is a real key-derivation function (e.g. `NIKESphinx`'s
HKDF-Expand call) that cannot be a bijection onto a larger codomain (pigeonhole), so it's modeled
as this `PRGScheme` instead, with `G2`/`G2'` its real/ideal experiments — bounded by
`jointKeyPRG`'s own `prgAdvantage`, not claimed to vanish. -/
def jointKeyPRG : PRGScheme F (Seed × KeyMu × KeyPi) :=
  ⟨fun c' => (S.hρ (c' • S.g), S.hμ (c' • S.g), S.hπ (c' • S.g))⟩

/-- The joint-key hybrid's reduction adversary: given a `Seed × KeyMu × KeyPi` value (real or
ideal), sample `x`/`b` and finish. -/
def jointAdversaryOf
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) (x : F) : PRGAdversary (Seed × KeyMu × KeyPi) := fun p => do
  let b ← $ᵗ Bool
  let guess ← A (buildFromKeys S (x • S.g) p.1 p.2.1 p.2.2 (if b then c1 else c0))
  return (b == guess)

/-- `prgRealExp (jointKeyPRG) (jointAdversaryOf ... x)` reconstructs `game2` exactly. -/
theorem probTrue_game2_eq_prgRealExp_joint
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) :
    Pr[= true | game2 S A c0 c1] =
      Pr[= true | do
        let x ← $ᵗ F
        prgRealExp (jointKeyPRG S) (jointAdversaryOf S A c0 c1 x)] := by
  unfold game2 prgRealExp jointKeyPRG jointAdversaryOf
  rfl

/-- `prgIdealExp (jointAdversaryOf ... x)` reconstructs `game2'` up to reordering the independent
`b`/`p` samples (`probOutput_bind_bind_swap`). -/
theorem probTrue_game2'_eq_prgIdealExp_joint
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    (c0 c1 : Choice Beta Delta) :
    Pr[= true | game2' S A c0 c1] =
      Pr[= true | do
        let x ← $ᵗ F
        prgIdealExp (jointAdversaryOf S A c0 c1 x)] := by
  unfold game2' prgIdealExp jointAdversaryOf
  refine probOutput_bind_congr' ($ᵗ F) true fun x => ?_
  rw [probOutput_bind_bind_swap ($ᵗ Bool) ($ᵗ (Seed × KeyMu × KeyPi))
    (fun b p => A (buildFromKeys S (x • S.g) p.1 p.2.1 p.2.2 (if b then c1 else c0)) >>=
      fun guess => pure (b == guess)) true]

end KeyIndependence

section PRGHybrid

variable [SampleableType F] [SampleableType Seed] [SampleableType KeyMu] [SampleableType KeyPi]
  [SampleableType Beta] [SampleableType Gamma] [SampleableType Delta]
  [SampleableType (Seed × KeyMu × KeyPi)] [SampleableType (Beta × Gamma × Delta)]

/-- `ρgen`/`μeval`/`πenc` composed into one derivation `(seed, kmu, kpi) ↦ (β0, γ0, δ0)`, for a
fixed challenge branch `c`. One combined `PRGScheme` rather than three separate ones, since
`γ0`'s computation needs `β0`. -/
def combinedGen (c : Choice Beta Delta) (p : Seed × KeyMu × KeyPi) : Beta × Gamma × Delta :=
  let β0 := c.betaPt + S.ρgen p.1
  let γ0 := S.μeval p.2.1 β0
  let δ0 := S.πenc p.2.2 c.deltaPt
  (β0, γ0, δ0)

def combinedPRG (c : Choice Beta Delta) : PRGScheme (Seed × KeyMu × KeyPi) (Beta × Gamma × Delta) :=
  ⟨combinedGen S c⟩

/-- The combined-hybrid reduction adversary: given a `Beta × Gamma × Delta` value (real or
ideal), finish the game with the already-fixed `x`/`b`. -/
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

/-- **Game `G3`**: `β0, γ0, δ0` all replaced by an independent fresh uniform triple — the paper's
final hybrid, where the challenge tuple carries no information about `b`. -/
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

/-- **Proved outright**: in `G3` the tuple handed to the adversary is fresh and uniform,
independent of `b`, so a well-formed (`NeverFail`) adversary guesses correctly with probability
exactly `1/2` — the paper's baseline. -/
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

/-- **Main theorem (§4.4)**: the adversary's advantage is bounded by three gaps, one per hybrid
step (`G ⇒ G2`, `G2 ⇒ G2'`, `G2' ⇒ G3`), each a genuine computational assumption:

* `hddh` — `ddhDistAdvantage`'s bound on the reduction `ddhAdversaryOf`.
* `hjointPRG` — `jointKeyPRG`'s PRG-distinguishing advantage against `jointAdversaryOf`.
* `hprg` — the combined `ρ/μ/π`-derivation's PRG advantage against `combinedAdversaryOf`.

`game3`'s zero-advantage fact (`probTrue_game3`) closes the chain. -/
theorem advantage_le
    (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    [∀ v, NeverFail (A v)] (c0 c1 : Choice Beta Delta) (εDDH εJoint εPRG : ℝ)
    (hddh : ddhDistAdvantage S.g (ddhAdversaryOf S A c0 c1) ≤ εDDH)
    (hjointPRG : |(Pr[= true | game2 S A c0 c1]).toReal -
      (Pr[= true | game2' S A c0 c1]).toReal| ≤ εJoint)
    (hprg : |(Pr[= true | game2' S A c0 c1]).toReal - (Pr[= true | game3 S A c0 c1]).toReal| ≤ εPRG) :
    advantage S A c0 c1 ≤ εDDH + εJoint + εPRG := by
  unfold advantage
  have e1 : (Pr[= true | gameReal S A c0 c1]).toReal =
      (Pr[= true | ddhExpReal S.g (ddhAdversaryOf S A c0 c1)]).toReal := by
    rw [probTrue_gameReal_eq_ddhExpReal]
  have e2 : (Pr[= true | game2 S A c0 c1]).toReal =
      (Pr[= true | ddhExpRand S.g (ddhAdversaryOf S A c0 c1)]).toReal := by
    rw [probTrue_game2_eq_ddhExpRand]
  have e4 : (Pr[= true | game3 S A c0 c1]).toReal = 1 / 2 := probTrue_game3 S A c0 c1
  calc |(Pr[= true | gameReal S A c0 c1]).toReal - 1 / 2|
      = |(Pr[= true | gameReal S A c0 c1]).toReal - (Pr[= true | game3 S A c0 c1]).toReal| := by
        rw [e4]
    _ ≤ |(Pr[= true | gameReal S A c0 c1]).toReal - (Pr[= true | game2 S A c0 c1]).toReal| +
          |(Pr[= true | game2 S A c0 c1]).toReal - (Pr[= true | game3 S A c0 c1]).toReal| :=
        abs_sub_le _ _ _
    _ ≤ |(Pr[= true | gameReal S A c0 c1]).toReal - (Pr[= true | game2 S A c0 c1]).toReal| +
          (|(Pr[= true | game2 S A c0 c1]).toReal - (Pr[= true | game2' S A c0 c1]).toReal| +
           |(Pr[= true | game2' S A c0 c1]).toReal - (Pr[= true | game3 S A c0 c1]).toReal|) := by
        gcongr
        exact abs_sub_le _ _ _
    _ = |(Pr[= true | ddhExpReal S.g (ddhAdversaryOf S A c0 c1)]).toReal -
          (Pr[= true | ddhExpRand S.g (ddhAdversaryOf S A c0 c1)]).toReal| +
        (|(Pr[= true | game2 S A c0 c1]).toReal - (Pr[= true | game2' S A c0 c1]).toReal| +
         |(Pr[= true | game2' S A c0 c1]).toReal - (Pr[= true | game3 S A c0 c1]).toReal|) := by
        congr 1
        rw [e1, e2]
    _ ≤ εDDH + (εJoint + εPRG) := add_le_add hddh (add_le_add hjointPRG hprg)
    _ = εDDH + εJoint + εPRG := by ring

/-- `advantage_le`'s statement, closed over every scheme it's about. -/
abbrev AdvantageLeType :=
  ∀ (A : Adversary (G := G) (Beta := Beta) (Gamma := Gamma) (Delta := Delta))
    [∀ v, NeverFail (A v)] (c0 c1 : Choice Beta Delta) (εDDH εJoint εPRG : ℝ),
    ddhDistAdvantage S.g (ddhAdversaryOf S A c0 c1) ≤ εDDH →
    |(Pr[= true | game2 S A c0 c1]).toReal - (Pr[= true | game2' S A c0 c1]).toReal| ≤ εJoint →
    |(Pr[= true | game2' S A c0 c1]).toReal - (Pr[= true | game3 S A c0 c1]).toReal| ≤ εPRG →
    advantage S A c0 c1 ≤ εDDH + εJoint + εPRG

end MainTheorem

end CryptWalker.Sphinx.Indistinguishability

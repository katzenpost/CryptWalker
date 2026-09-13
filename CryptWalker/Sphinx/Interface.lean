/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.OracleComp.Constructions.SampleableType
import VCVio.EvalDist.Bool

import CryptWalker.Sphinx.Types
import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Indistinguishability
import CryptWalker.Sphinx.Integrity
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.Interface

-- `Sphinx` repeats the namespace, as `NIKE`/`KEM` do theirs; unlike them this file imports
-- Mathlib, so the linter actually sees it.
set_option linter.dupNamespace false

open CryptWalker.Util.Bytes (ofVector)
open OracleComp OracleSpec ENNReal

/-! # The abstract Sphinx interface

A packet scheme: private-key/command types, `wrap`/`unwrap`, `newSURB`/`newPacketFromSURB`, and
a completeness law relating them.

`unwrap`'s forwarded packet is `Vector UInt8 pkt.size` — same length as the input, by the type.
`wrap`/`newSURB` draw their randomness from `State` via `EStateM` (`SeedStream`/`nextSeed`/
`initWith` below, shaped like `KEM.Adapter`'s seed stream); `unwrap`/`newPacketFromSURB` are
deterministic, so plain `Except`. `filler` stays a bare argument regardless — its *length* is
public, unlike a key.

`NIKESphinx`/`KEMSphinx` are the two witnesses. Both lean on axioms rather than proofs, for
`newNIKEPacket_size` and friends (a successful `wrap`/`newSURB` produces exactly
`packetLength`/`surbLength` bytes) and for `unwrap_complete` itself — real work through
`createHeader`'s loops and blinding chain, out of scope for this pass; the vectors and
self-tests check all of it empirically instead. `unwrap_complete` only pins down the forward
payload so far, not `cmds`/`replayTag`/SURB completeness. -/

/-- Counter plus an inexhaustible stream of 32-byte seeds — `wrap`'s randomness source. -/
abbrev SeedStream := Nat × (Nat → Vector UInt8 32)

def nextSeed : EStateM String SeedStream (Vector UInt8 32) :=
  fun (i, str) => .ok (str i) (i + 1, str)

/-- The state an honest run starts from: counter zero over a caller-supplied seed stream, which
must be unpredictable (unchecked here). -/
def initWith (str : Nat → Vector UInt8 32) : SeedStream := (0, str)

/-- Repeatedly `unwrap`, one key per hop, threading the forwarded packet through. Stops at the
first hop with no forward packet. Free-standing since it only needs `unwrap`'s shape, not a full
instance — generalizes what `nike_selftest.lean`/`kem_selftest.lean`'s `unwrapAll` checks
concretely. -/
def unwrapChainAux {PrivateKey Command : Type}
    (unwrap : PrivateKey → (pkt : ByteArray) →
      Except String (Option ByteArray × Vector UInt8 32 × List Command × Option (Vector UInt8 pkt.size))) :
    List PrivateKey → ByteArray → Except String (Option ByteArray)
  | [], _ => pure none
  | sk :: rest, pkt => do
    let (payload, _replayTag, _cmds, forwardPkt) ← unwrap sk pkt
    match forwardPkt with
    | some fwd => unwrapChainAux unwrap rest (ofVector fwd)
    | none => pure payload

structure Sphinx where
  State : Type
  PrivateKey : Type
  Command : Type
  [stateI : Inhabited State]
  [privI : Inhabited PrivateKey]

  geometry : Geometry.Geometry

  /-- Raw bytes — width depends on which NIKE/KEM this scheme wraps, not fixed here. -/
  derivePublicKey : PrivateKey → ByteArray

  wrap : List Types.PathHop → (filler : ByteArray) → Vector UInt8 geometry.forwardPayloadLength →
    EStateM String State (Vector UInt8 geometry.packetLength)

  /-- `(payload, replayTag, cmds, forwardPkt)`. -/
  unwrap : PrivateKey → (pkt : ByteArray) →
    Except String (Option ByteArray × Vector UInt8 32 × List Command × Option (Vector UInt8 pkt.size))

  newSURB : List Types.PathHop → (filler : ByteArray) →
    EStateM String State (Vector UInt8 geometry.surbLength × ByteArray)

  newPacketFromSURB : Vector UInt8 geometry.surbLength → ByteArray →
    Except String (ByteArray × Vector UInt8 32)

  /-- **Completeness**: any packet `wrap` builds, `unwrap` can undo. -/
  unwrap_complete : ∀ (path : List Types.PathHop) (privKeys : List PrivateKey)
      (filler : ByteArray) (payload : Vector UInt8 geometry.forwardPayloadLength) (st : State)
      (pkt : Vector UInt8 geometry.packetLength) (st' : State),
    path ≠ [] →
    path.map (·.publicKey) = privKeys.map derivePublicKey →
    wrap path filler payload st = .ok pkt st' →
    unwrapChainAux unwrap privKeys (ofVector pkt) = .ok (some (ofVector payload))

  /-- **Indistinguishability** (§4.4): `Indistinguishability.advantage_le`, closed over every
  scheme it's about. Free for every instance — see that theorem's own module doc for the games
  and hardness assumptions it reduces to. -/
  indistinguishable : ∀ {F G Seed KeyMu KeyPi Beta Gamma Delta : Type}
      [Field F] [AddCommGroup G] [Module F G] [AddCommGroup Beta]
      [SampleableType F] [SampleableType Seed] [SampleableType KeyMu] [SampleableType KeyPi]
      [SampleableType Beta] [SampleableType Gamma] [SampleableType Delta]
      [SampleableType (Seed × KeyMu × KeyPi)] [Finite F]
      (S : Indistinguishability.Sys F G Seed KeyMu KeyPi Beta Gamma Delta),
      Indistinguishability.AdvantageLeType S :=
    fun S => Indistinguishability.advantage_le S

  /-- **Integrity** (§4.2): `Integrity.integrity_bound`, closed over every scheme it's about.
  Free for every instance — see that theorem's own module doc for `ProblemP`, its named hardness
  hypothesis. -/
  integrity : ∀ {F G Seed Idx Yy Kappa : Type} [Field F] [AddCommGroup G] [Module F G]
      [Nonempty Yy] (S : Integrity.Sys F G) (hρ : G → Seed) (ρhat0 : Seed → Kappa)
      (ρ0 : Seed → Idx) (f : Idx → Yy → Kappa),
      Integrity.IntegrityBoundType S hρ ρhat0 ρ0 f :=
    fun S hρ ρhat0 ρ0 f => Integrity.integrity_bound S hρ ρhat0 ρ0 f

instance : Inhabited Sphinx := ⟨{
  State := SeedStream
  PrivateKey := Unit
  Command := Unit
  geometry :=
    { scheme := .inl ""
      packetLength := 0
      nrHops := 0
      headerLength := 0
      routingInfoLength := 0
      perHopRoutingInfoLength := 0
      surbLength := 0
      sphinxPlaintextHeaderLength := 0
      payloadTagLength := 0
      forwardPayloadLength := 0
      userForwardPayloadLength := 0
      nextNodeHopLength := 0
      sprpKeyMaterialLength := 0 }
  derivePublicKey := fun _ => ByteArray.empty
  wrap := fun _ _ _ => throw "sphinx: uninhabited"
  unwrap := fun _ _ => .ok (none, default, [], none)
  newSURB := fun _ _ => pure (Vector.emptyWithCapacity 0, ByteArray.empty)
  newPacketFromSURB := fun _ _ => .ok (ByteArray.empty, default)
  unwrap_complete := by
    intro path privKeys filler payload st pkt st' _hpath _hkeys hwrap
    cases hwrap
}⟩

/-! ## Wrap-resistance (Danezis–Goldberg §4.3)

`unwrap_complete` is a plain ∀-statement about honest execution, expressible directly in terms
of `wrap`/`unwrap` since it only composes fields the base `Sphinx` structure already has.
Wrap-resistance isn't that shape: it's a probabilistic bound on adversarial forgery, and its
content — "a freshly drawn blinding factor is unlikely to hit a chosen target" — depends on
structure (a public-key element, a factor space, a blinding action) that a scheme built on a
group-element blinding chain has and a KEM-based scheme (independent per-hop encapsulation, no
element to re-blind) does not. `NIKESphinx.NIKESphinxScheme` carries that structure directly;
there is no analogous structure for KEM-Sphinx. -/

/-- A uniformly sampled `b : F`, pushed through a bijection `act`, hits any fixed `target` with
probability exactly `1/|F|`. The whole mathematical content of wrap-resistance's single-query
case: `act` stands for "blind by this freshly drawn factor," `target` for the header an
adversary is trying to forge. -/
theorem uniformHit_eq {F G : Type} [Fintype F] [SampleableType F] [DecidableEq G]
    {act : F → G} (hact : Function.Bijective act) (target : G) :
    Pr[= true | ($ᵗ F) >>= fun b => pure (decide (act b = target))] =
      (Fintype.card F : ℝ≥0∞)⁻¹ := by
  obtain ⟨b₀, rfl⟩ := hact.surjective target
  simp only [probOutput_bind_eq_tsum, probOutput_uniformSample, probOutput_pure]
  rw [tsum_fintype, Finset.sum_eq_single b₀]
  · simp
  · intro b _ hne
    simp [show act b ≠ act b₀ from fun heq => hne (hact.injective heq)]
  · exact absurd (Finset.mem_univ b₀)

end CryptWalker.Sphinx.Interface

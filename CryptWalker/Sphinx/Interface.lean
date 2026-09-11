/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.OracleComp.Constructions.SampleableType
import VCVio.EvalDist.Bool

import CryptWalker.Sphinx.Types
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

  packetLength : Nat
  payloadLength : Nat
  surbLength : Nat

  /-- The public key a node holding `sk` must publish, for `wrap` and `unwrap sk` to agree on
  which hop `sk` is. -/
  derivePublicKey : PrivateKey → Vector UInt8 32

  /-- Build a forward packet from `path` and `payload`, drawing whatever ephemeral key material
  it needs from `State`. -/
  wrap : List Types.PathHop → (filler : ByteArray) → Vector UInt8 payloadLength →
    EStateM String State (Vector UInt8 packetLength)

  /-- `(payload, replayTag, cmds, forwardPkt)`. Deterministic, so `Except`, not `EStateM`. -/
  unwrap : PrivateKey → (pkt : ByteArray) →
    Except String (Option ByteArray × Vector UInt8 32 × List Command × Option (Vector UInt8 pkt.size))

  /-- Build a SURB for `path`, drawing ephemeral key material as `wrap` does. `(surb,
  surbKeys)`; `surbKeys` decrypts what a reply built from `surb` gets encrypted with. -/
  newSURB : List Types.PathHop → (filler : ByteArray) →
    EStateM String State (Vector UInt8 surbLength × ByteArray)

  /-- Build a reply packet from a `surb` (`newSURB`'s output) and a plaintext `payload`.
  `(packet, firstHopID)`. -/
  newPacketFromSURB : Vector UInt8 surbLength → ByteArray →
    Except String (ByteArray × Vector UInt8 32)

  /-- **Completeness**: any packet `wrap` builds, `unwrap` can undo, given `path`'s own private
  keys in order (`derivePublicKey`-matched) and a nonempty `path`. -/
  unwrap_complete : ∀ (path : List Types.PathHop) (privKeys : List PrivateKey)
      (filler : ByteArray) (payload : Vector UInt8 payloadLength) (st : State)
      (pkt : Vector UInt8 packetLength) (st' : State),
    path ≠ [] →
    path.map (·.publicKey) = privKeys.map derivePublicKey →
    wrap path filler payload st = .ok pkt st' →
    unwrapChainAux unwrap privKeys (ofVector pkt) = .ok (some (ofVector payload))

/-- Trivial instance, witnessing satisfiability, as `NIKE`/`KEM`'s own `Inhabited` instances. -/
instance : Inhabited Sphinx := ⟨{
  State := SeedStream
  PrivateKey := Unit
  Command := Unit
  packetLength := 0
  payloadLength := 0
  surbLength := 0
  derivePublicKey := fun _ => Vector.replicate 32 0
  -- Always fails, so `unwrap_complete` holds vacuously.
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
element to re-blind) does not. `BlindedScheme` below is for the former; there is no analogous
structure for the latter here. -/

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

/-- A `Sphinx` scheme whose header carries a re-blindable public-key element: `Envelope` is that
element's type (`parseEnvelope` extracts it from a packet), `Factor` is the space a fresh
blinding value is drawn from, and `blind` is the re-blinding action. `wrap_resistant` needs no
per-instance proof — it's `uniformHit_eq` specialized to `act := blind · e`, true for *every*
instance automatically. Its hypothesis, `Function.Bijective (blind · e)`, is what actually
carries content, and is false (so the implication holds vacuously) for a degenerate `e` such as
a group's identity element — exactly the case a well-formed header never produces. -/
structure BlindedScheme extends Sphinx where
  Envelope : Type
  [envelopeDecEq : DecidableEq Envelope]
  /-- The header's public-key element, read out of a packet. -/
  parseEnvelope : Vector UInt8 packetLength → Envelope
  /-- The space a fresh blinding factor is drawn from. -/
  Factor : Type
  [factorFintype : Fintype Factor]
  [factorSampleable : SampleableType Factor]
  /-- Re-blind an envelope element by a factor. -/
  blind : Factor → Envelope → Envelope
  /-- **Wrap-resistance.** Whenever blinding by `e` is a bijection — the case for any `e` that
  actually generates the (sub)group a well-formed header's element lives in — a freshly drawn
  factor hits a chosen `target` with probability exactly `1/|Factor|`. -/
  wrap_resistant : ∀ (e target : Envelope), Function.Bijective (blind · e) →
      Pr[= true | ($ᵗ Factor) >>= fun b => pure (decide (blind b e = target))] =
        (Fintype.card Factor : ℝ≥0∞)⁻¹ :=
    fun _ target hbij => uniformHit_eq hbij target

end CryptWalker.Sphinx.Interface

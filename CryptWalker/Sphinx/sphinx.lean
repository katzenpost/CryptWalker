/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.OracleComp.Constructions.SampleableType

import CryptWalker.Sphinx.types
import CryptWalker.Sphinx.geometry
import CryptWalker.Sphinx.indistinguishability
import CryptWalker.Sphinx.integrity
import CryptWalker.WideBlockCipher.WideBlockCipher
import CryptWalker.MAC.MAC
import CryptWalker.KDF.KDF
import CryptWalker.StreamCipher.StreamCipher
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.Interface

-- `Sphinx` repeats the namespace, as `NIKE`/`KEM` do theirs; unlike them this file imports
-- Mathlib, so the linter actually sees it.
set_option linter.dupNamespace false

open CryptWalker.Util.Bytes (ofVector)

/-! # The abstract Sphinx interface

Reference for this whole directory: George Danezis and Ian Goldberg, *Sphinx: A Compact and
Provably Secure Mix Format*, IEEE S&P 2009 — <https://eprint.iacr.org/2008/475> (PDF at that URL).
Cited elsewhere here as "Danezis–Goldberg" or "the paper"; a bare `§n.m` is that paper's own
section numbering. Not re-cited file by file.

The paper states four security properties for a mix format; this project formalizes all four:

* **Completeness** — `unwrap_complete` below: any packet `wrap` builds, `unwrap` correctly undoes.
* **Integrity** (§4.2) — the `integrity` field below, via `Integrity.integrity_bound`.
* **Indistinguishability** (§4.4) — the `indistinguishable` field below, via
  `Indistinguishability.advantage_le`.
* **Wrap-resistance** (§4.3) — stated only on `NIKESphinxScheme.wrap_resistant` (`nike_sphinx.lean`),
  not here on the base `Sphinx` structure: it needs a re-blindable public-key element a KEM-based
  scheme has no analogue of. `NIKESphinx.uniformHit_eq` is its scheme-independent mathematical core.

A packet scheme: private-key/command types, `wrap`/`unwrap`, `newSURB`/`newPacketFromSURB`, and
a completeness law relating them.

`unwrap`'s forwarded packet is `Vector UInt8 pkt.size` — same length as the input, by the type.
`wrap`/`newSURB` draw randomness from `State` via `EStateM` (`SeedStream`/`nextSeed`/`initWith`
below); `unwrap`/`newPacketFromSURB` are deterministic, so plain `Except`.

`NIKESphinx`/`KEMSphinx` are the two witnesses, both proving `unwrap_complete` outright
(generic over the abstract `NIKE`/`KEM`/`WideBlockCipher`/`MAC`/`KDF`/`StreamCipher` types) plus
`newNIKEPacket_size` and friends (`wrap`/`newSURB` produce exactly `packetLength`/`surbLength`
bytes). `unwrap_complete` covers only the forward payload, not `cmds`/`replayTag`/SURB
completeness. -/

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

  /-- The four cryptographic primitives every Sphinx instance needs besides its NIKE-or-KEM
  (added by `NIKESphinxScheme`/`KEMSphinxScheme`): a wide-block cipher for the payload, a MAC for
  header integrity, a KDF for per-hop keys, a stream cipher for routing-info encryption. Kept
  abstract so swapping e.g. AEZ for another wide-block cipher needs no change below. -/
  cipher : CryptWalker.WideBlockCipher.WideBlockCipher
  mac    : CryptWalker.MAC.MAC
  kdf    : CryptWalker.KDF.KDF
  stream : CryptWalker.StreamCipher.StreamCipher

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

  /-- Which starting states are guaranteed not to run into the backing scheme's rare correctness
  failure over an unbounded run. `True` for every perfect-correctness backing — every NIKE, and
  any Diffie-Hellman-based KEM (`KEM.KEM.Reliable`'s own default, unchanged) — since neither has a
  decoding step with a failure mode to name. A KEM-Sphinx instance backed by a lattice-based KEM
  (e.g. ML-KEM) overrides this with the real per-draw guarantee its own `KEM.Reliable` needs. -/
  unwrapReliable : State → Prop := fun _ => True

  /-- **Completeness**: any packet `wrap` builds, `unwrap` can undo, given `path` is well-formed —
  no hop's `commands` already contains `null` or `nextNodeHop` (both wire-level sentinels this
  port only ever constructs itself, never something a caller supplies), and the last hop carries
  no `surbReply` (a real command, just one that changes `unwrap`'s terminal-hop behavior — its own
  completeness is tracked separately). -/
  unwrap_complete : ∀ (path : List Types.PathHop) (privKeys : List PrivateKey)
      (filler : ByteArray) (payload : Vector UInt8 geometry.forwardPayloadLength) (st : State)
      (pkt : Vector UInt8 geometry.packetLength) (st' : State),
    path ≠ [] →
    unwrapReliable st →
    path.map (·.publicKey) = privKeys.map derivePublicKey →
    (∀ hop ∈ path, ∀ c ∈ hop.commands, c ≠ .null ∧ (∀ id m, c ≠ .nextNodeHop id m)) →
    (∀ c ∈ (path[path.length - 1]!).commands, ∀ id, c ≠ .surbReply id) →
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
  cipher := default
  mac    := default
  kdf    := default
  stream := default
  derivePublicKey := fun _ => ByteArray.empty
  wrap := fun _ _ _ => throw "sphinx: uninhabited"
  unwrap := fun _ _ => .ok (none, default, [], none)
  newSURB := fun _ _ => pure (Vector.emptyWithCapacity 0, ByteArray.empty)
  newPacketFromSURB := fun _ _ => .ok (ByteArray.empty, default)
  unwrap_complete := by
    intro path privKeys filler payload st pkt st' _hpath _hrel _hkeys _hcmds _hsurb hwrap
    cases hwrap
}⟩

end CryptWalker.Sphinx.Interface

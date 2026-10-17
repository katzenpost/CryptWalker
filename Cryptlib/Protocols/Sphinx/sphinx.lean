/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import VCVio.OracleComp.Constructions.SampleableType

import Cryptlib.Protocols.Sphinx.types
import Cryptlib.Protocols.Sphinx.geometry
import Cryptlib.Protocols.Sphinx.indistinguishability
import Cryptlib.Protocols.Sphinx.integrity
import Cryptlib.Primitives.WideBlockCipher.WideBlockCipher
import Cryptlib.Primitives.MAC.MAC
import Cryptlib.Primitives.KDF.KDF
import Cryptlib.Primitives.StreamCipher.StreamCipher
import Cryptlib.Util.Bytes

namespace Cryptlib.Protocols.Sphinx.Interface

-- `Sphinx` repeats the namespace name.
set_option linter.dupNamespace false

open Cryptlib.Util.Bytes (ofVector)

/-! # The abstract Sphinx interface

Reference: George Danezis and Ian Goldberg, *Sphinx: A Compact and Provably Secure Mix Format*,
IEEE S&P 2009, <https://eprint.iacr.org/2008/475>. A bare `§n.m` in this directory refers to that
paper's sections.

A packet scheme with completeness (`unwrap_complete`), integrity (§4.2) and indistinguishability
(§4.4). Wrap-resistance (§4.3) is stated on `NIKESphinxScheme` only, since it needs a re-blindable
group element. -/

/-- Counter plus an infinite stream of 32-byte seeds. -/
abbrev SeedStream := Nat × (Nat → Vector UInt8 32)

def nextSeed : EStateM String SeedStream (Vector UInt8 32) :=
  fun (i, str) => .ok (str i) (i + 1, str)

/-- Initial state: counter zero over a seed stream, which must be unpredictable. -/
def initWith (str : Nat → Vector UInt8 32) : SeedStream := (0, str)

/-- `n` bytes from the seed stream starting at seed `i`: byte `k` is byte `k % 32` of seed
`i + k / 32`. -/
def seedBytes (str : Nat → Vector UInt8 32) (i n : Nat) : ByteArray :=
  ⟨Array.ofFn fun k : Fin n => (str (i + k.val / 32))[k.val % 32]'(Nat.mod_lt _ (by decide))⟩

theorem seedBytes_size (str : Nat → Vector UInt8 32) (i n : Nat) :
    (seedBytes str i n).size = n := by
  simp [seedBytes, ByteArray.size]

/-- Draw `n` bytes from the seed stream, consuming `⌈n/32⌉` seeds. -/
def drawBytes (n : Nat) : EStateM String SeedStream ByteArray :=
  fun (i, str) => .ok (seedBytes str i n) (i + (n + 31) / 32, str)

/-- Routing-info bytes a `nrHops`-hop path leaves unused. These are filled with random bytes, not
zeros, which would reveal the path length (Kuhn et al., S&P 2020). -/
def fillerLength (geom : Geometry.Geometry) (nrHops : Nat) : Nat :=
  (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength

/-- Repeatedly `unwrap`, one key per hop, stopping at the first hop with no forward packet. -/
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

  /-- Wide-block cipher for the payload, MAC for header integrity, KDF for per-hop keys, stream
  cipher for routing-info encryption. -/
  cipher : Cryptlib.Primitives.WideBlockCipher.WideBlockCipher
  mac    : Cryptlib.Primitives.MAC.MAC
  kdf    : Cryptlib.Primitives.KDF.KDF
  stream : Cryptlib.Primitives.StreamCipher.StreamCipher

  /-- Raw public key bytes. -/
  derivePublicKey : PrivateKey → ByteArray

  /-- Unused routing-info slots are filled with random bytes drawn from `State`. -/
  wrap : List Types.PathHop → Vector UInt8 geometry.forwardPayloadLength →
    EStateM String State (Vector UInt8 geometry.packetLength)

  /-- `(payload, replayTag, cmds, forwardPkt)`. -/
  unwrap : PrivateKey → (pkt : ByteArray) →
    Except String (Option ByteArray × Vector UInt8 32 × List Command × Option (Vector UInt8 pkt.size))

  newSURB : List Types.PathHop →
    EStateM String State (Vector UInt8 geometry.surbLength × ByteArray)

  newPacketFromSURB : Vector UInt8 geometry.surbLength → ByteArray →
    Except String (ByteArray × Vector UInt8 32)

  /-- Starting states from which the backing scheme never hits a decryption failure. `True` for
  perfectly correct schemes. -/
  unwrapReliable : State → Prop := fun _ => True

  /-- Completeness: `unwrap` undoes `wrap` on the forward payload, given no hop's `commands`
  contains `null` or `nextNodeHop` and the last hop carries no `surbReply`. -/
  unwrap_complete : ∀ (path : List Types.PathHop) (privKeys : List PrivateKey)
      (payload : Vector UInt8 geometry.forwardPayloadLength) (st : State)
      (pkt : Vector UInt8 geometry.packetLength) (st' : State),
    path ≠ [] →
    unwrapReliable st →
    path.map (·.publicKey) = privKeys.map derivePublicKey →
    (∀ hop ∈ path, ∀ c ∈ hop.commands, c ≠ .null ∧ (∀ id m, c ≠ .nextNodeHop id m)) →
    (∀ c ∈ (path[path.length - 1]!).commands, ∀ id, c ≠ .surbReply id) →
    wrap path payload st = .ok pkt st' →
    unwrapChainAux unwrap privKeys (ofVector pkt) = .ok (some (ofVector payload))

  /-- Indistinguishability (§4.4). See `Indistinguishability.advantage_le`. -/
  indistinguishable : ∀ {F G Seed KeyMu KeyPi Beta Gamma Delta : Type}
      [Field F] [AddCommGroup G] [Module F G] [AddCommGroup Beta]
      [SampleableType F] [SampleableType Seed] [SampleableType KeyMu] [SampleableType KeyPi]
      [SampleableType Beta] [SampleableType Gamma] [SampleableType Delta]
      [SampleableType (Seed × KeyMu × KeyPi)] [Finite F]
      (S : Indistinguishability.Sys F G Seed KeyMu KeyPi Beta Gamma Delta),
      Indistinguishability.AdvantageLeType S :=
    fun S => Indistinguishability.advantage_le S

  /-- Integrity (§4.2). See `Integrity.integrity_bound`. -/
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
    { packetLength := 0
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
      sprpKeyMaterialLength := 0
      nikeName := ""
      kemName := "" }
  cipher := default
  mac    := default
  kdf    := default
  stream := default
  derivePublicKey := fun _ => ByteArray.empty
  wrap := fun _ _ => throw "sphinx: uninhabited"
  unwrap := fun _ _ => .ok (none, default, [], none)
  newSURB := fun _ => pure (Vector.emptyWithCapacity 0, ByteArray.empty)
  newPacketFromSURB := fun _ _ => .ok (ByteArray.empty, default)
  unwrap_complete := by
    intro path privKeys payload st pkt st' _hpath _hrel _hkeys _hcmds _hsurb hwrap
    cases hwrap
}⟩

end Cryptlib.Protocols.Sphinx.Interface

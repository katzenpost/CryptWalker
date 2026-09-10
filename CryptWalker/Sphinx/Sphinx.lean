/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Types
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.Sphinx

open CryptWalker.Util.Bytes (ofVector)

/-! # The abstract Sphinx interface

A packet scheme, bundling its private-key/command types with `wrap` and `unwrap`.

`unwrap`'s return type depends on its own `pkt` argument: the forwarded packet, when there is
one, is `Vector UInt8 pkt.size` — same length as the input, by the type, not by a theorem proved
about it afterward. No named result type; a plain product carries it fine.

`wrap`'s randomness (the client's ephemeral key for `NIKESphinx`, one seed per hop for
`KEMSphinx`) is drawn from `State` via `EStateM`, the same way `KEM.KEM`'s `encap`/`generate`
draw theirs — `SeedStream`/`nextSeed`/`initWith` below are the same "counter plus an
inexhaustible seed stream" shape as `KEM.Adapter.St`/`nextSeed`/`initWith`, just yielding
32-byte seeds instead of `KEM.Adapter.Bytes32` (the same type, not shared, to keep this file
independent of `KEM.Adapter`). `filler` (hop-count-hiding padding) stays an explicit argument:
its *length* is public and geometry-derived, unlike a key.

`newSURB`/`newPacketFromSURB` are `wrap`/`unwrap`'s SURB-side counterparts: `surbLength` is a
fixed geometry constant exactly like `packetLength` (the SURB header doesn't depend on the
actual path length, only the geometry's `nrHops` ceiling), so `newSURB`'s output gets the same
type-level size guarantee `wrap`'s does; `newPacketFromSURB` is deterministic like `unwrap`, so
`Except`, not `EStateM` — and its output packet is a plain `ByteArray`, not `Vector UInt8
packetLength`, since a reply payload's length is the caller's choice, independent of the
forward geometry.

`NIKESphinx.unwrapNIKE`/`wrapNIKE`/`wrapNIKESURB`/`SURB.newPacketFromSURB` and `KEMSphinx`'s
equivalents are the witnesses that a real implementation can meet this signature. The facts
they lean on without proving from first principles: `Crypto.AEZ`'s
`sprpEncrypt_size`/`sprpDecrypt_size`, and each variant's own
`newNIKEPacket_size`/`newKEMPacket_size`/`newNIKESURB_size`/`newKEMSURB_size` (that a successful
`wrap`/`newSURB` produces exactly `packetLength`/`surbLength` bytes) — all axioms, for the
reason `NIKE.X25519` leaves `curve25519_commutes` one: pushing a `for`-loop's size invariant
through `Id.run do` elaboration is mechanical but long, and out of scope for this pass.

`unwrap_complete` is the correctness/completeness law, as `NIKE.NIKE`'s `commutes` or
`KEM.KEM`'s `roundTrip_ok`: whatever `wrap` builds for `path`, walking `unwrapChainAux` over the
private keys matching `path`'s public keys (in order, via `derivePublicKey`) recovers `payload`
exactly. Each concrete instance discharges it with an axiom too, for the same reason as the
size ones above — this is the harder of the two (it's the actual onion-decrypts-correctly
property, not just a length count), but it's the one every vector and self-test already checks
empirically, hop by hop. Only the forward payload is specified this way for now; `cmds`,
`replayTag`, and SURB completeness are unstated. -/

/-- Counter plus an inexhaustible stream of 32-byte seeds — `wrap`'s randomness source. -/
abbrev SeedStream := Nat × (Nat → Vector UInt8 32)

def nextSeed : EStateM String SeedStream (Vector UInt8 32) :=
  fun (i, str) => .ok (str i) (i + 1, str)

/-- The state an honest run starts from: counter zero over a caller-supplied seed stream, which
must be unpredictable (unchecked here). -/
def initWith (str : Nat → Vector UInt8 32) : SeedStream := (0, str)

/-- Repeatedly `unwrap`, once per key in `privKeys`, threading the forwarded packet through —
one hop peeled off per key, in order. Stops at the first hop with no forward packet, returning
whatever payload it produced (`none` if `privKeys` runs out first). Free-standing rather than a
method on `Sphinx` itself, since it only needs `unwrap`'s shape, not a full instance — the shape
`nike_selftest.lean`/`kem_selftest.lean`'s `unwrapAll` already checks concretely, generalized. -/
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

  /-- The public key a node holding `sk` must publish as its `Types.PathHop.publicKey` for
  `wrap`'s encryption to it, and `unwrap sk`'s decryption of that layer, to be talking about the
  same hop. -/
  derivePublicKey : PrivateKey → Vector UInt8 32

  /-- Build a forward packet from `path` and `payload`, drawing whatever ephemeral key material
  it needs from `State`. -/
  wrap : List Types.PathHop → (filler : ByteArray) → Vector UInt8 payloadLength →
    EStateM String State (Vector UInt8 packetLength)

  /-- `(payload, replayTag, cmds, forwardPkt)`. Deterministic, so `Except`, not `EStateM`. -/
  unwrap : PrivateKey → (pkt : ByteArray) →
    Except String (Option ByteArray × Vector UInt8 32 × List Command × Option (Vector UInt8 pkt.size))

  /-- Build a SURB usable later, by anyone, to route a reply back through `path` without
  knowing its private keys — drawing whatever ephemeral key material it needs from `State`, as
  `wrap` does. `(surb, surbKeys)`; `surbKeys` is what `newPacketFromSURB`'s result decrypts
  with. -/
  newSURB : List Types.PathHop → (filler : ByteArray) →
    EStateM String State (Vector UInt8 surbLength × ByteArray)

  /-- Build a reply packet from a `surb` (`newSURB`'s output) and a plaintext `payload`.
  `(packet, firstHopID)`. -/
  newPacketFromSURB : Vector UInt8 surbLength → ByteArray →
    Except String (ByteArray × Vector UInt8 32)

  /-- **Completeness**: any packet `wrap` builds, `unwrap` can undo. `privKeys` must match
  `path` — same length, same order, `derivePublicKey`-images equal `path`'s own public keys —
  and `path` must be nonempty (a `wrap` that somehow succeeds on `path = []` has nothing to
  recover; no real instance's `wrap` does). Walking `unwrapChainAux` over `privKeys` then
  recovers `payload`, exactly. -/
  unwrap_complete : ∀ (path : List Types.PathHop) (privKeys : List PrivateKey)
      (filler : ByteArray) (payload : Vector UInt8 payloadLength) (st : State)
      (pkt : Vector UInt8 packetLength) (st' : State),
    path ≠ [] →
    path.map (·.publicKey) = privKeys.map derivePublicKey →
    wrap path filler payload st = .ok pkt st' →
    unwrapChainAux unwrap privKeys (ofVector pkt) = .ok (some (ofVector payload))

/-- Trivial instance, witnessing satisfiability — matches `NIKE`/`KEM`'s own `Inhabited`
instances, which exist for the same reason: an interface no scheme could ever inhabit would be
worth noticing. -/
instance : Inhabited Sphinx := ⟨{
  State := SeedStream
  PrivateKey := Unit
  Command := Unit
  packetLength := 0
  payloadLength := 0
  surbLength := 0
  derivePublicKey := fun _ => Vector.replicate 32 0
  -- Always fails, so `unwrap_complete` holds vacuously — simplest possible witness, since
  -- `packetLength = 0` leaves no room to build a real inhabitant of `unwrap_complete` otherwise.
  wrap := fun _ _ _ => throw "sphinx: uninhabited"
  unwrap := fun _ _ => .ok (none, default, [], none)
  newSURB := fun _ _ => pure (Vector.emptyWithCapacity 0, ByteArray.empty)
  newPacketFromSURB := fun _ _ => .ok (ByteArray.empty, default)
  unwrap_complete := by
    intro path privKeys filler payload st pkt st' _hpath _hkeys hwrap
    cases hwrap
}⟩

end CryptWalker.Sphinx.Sphinx

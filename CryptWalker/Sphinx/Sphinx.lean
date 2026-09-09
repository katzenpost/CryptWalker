/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Types

namespace CryptWalker.Sphinx.Sphinx

/-! # The abstract Sphinx interface

A packet scheme, bundling its private-key/command types with `wrap` and `unwrap`.

`unwrap`'s return type depends on its own `pkt` argument: the forwarded packet, when there is
one, is `Vector UInt8 pkt.size` — same length as the input, by the type, not by a theorem proved
about it afterward. No named result type; a plain product carries it fine.

`wrap`'s randomness (the client's ephemeral key for `NikeSphinx`, one seed per hop for
`KemSphinx`) is drawn from `State` via `EStateM`, the same way `KEM.KEM`'s `encap`/`generate`
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

`NikeSphinx.unwrapNike`/`wrapNike`/`wrapNikeSURB`/`SURB.newPacketFromSURB` and `KemSphinx`'s
equivalents are the witnesses that a real implementation can meet this signature. The facts
they lean on without proving from first principles: `Crypto.AEZ`'s
`sprpEncrypt_size`/`sprpDecrypt_size`, and each variant's own
`newNikePacket_size`/`newKEMPacket_size`/`newNikeSURB_size`/`newKemSURB_size` (that a successful
`wrap`/`newSURB` produces exactly `packetLength`/`surbLength` bytes) — all axioms, for the
reason `NIKE.X25519` leaves `curve25519_commutes` one: pushing a `for`-loop's size invariant
through `Id.run do` elaboration is mechanical but long, and out of scope for this pass. -/

/-- Counter plus an inexhaustible stream of 32-byte seeds — `wrap`'s randomness source. -/
abbrev SeedStream := Nat × (Nat → Vector UInt8 32)

def nextSeed : EStateM String SeedStream (Vector UInt8 32) :=
  fun (i, str) => .ok (str i) (i + 1, str)

/-- The state an honest run starts from: counter zero over a caller-supplied seed stream, which
must be unpredictable (unchecked here). -/
def initWith (str : Nat → Vector UInt8 32) : SeedStream := (0, str)

structure Sphinx where
  State : Type
  PrivateKey : Type
  Command : Type
  [stateI : Inhabited State]
  [privI : Inhabited PrivateKey]

  packetLength : Nat
  payloadLength : Nat
  surbLength : Nat

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
  wrap := fun _ _ _ => pure (Vector.emptyWithCapacity 0)
  unwrap := fun _ _ => .ok (none, default, [], none)
  newSURB := fun _ _ => pure (Vector.emptyWithCapacity 0, ByteArray.empty)
  newPacketFromSURB := fun _ _ => .ok (ByteArray.empty, default)
}⟩

end CryptWalker.Sphinx.Sphinx

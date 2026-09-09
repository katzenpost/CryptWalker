/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Sphinx.Sphinx

/-! # The abstract Sphinx interface

In the spirit of `NIKE.NIKE`/`KEM.KEM`: a `structure` bundling the operation(s) a Sphinx packet
scheme provides, so that a concrete port (`NikeSphinx`, and eventually a KEM-Sphinx analogue)
*instantiates* it rather than standing alone. Only `unwrap` is here so far — `wrap`/`createHeader`
needs an explicit-randomness or `EStateM`-threaded-seed-stream story of its own (see
`NikeSphinx.createHeader`'s doc comment) that hasn't been unified across the NIKE and KEM
variants yet.

## The packet-length invariance rule, as a type

One of Sphinx's structural rules: unwrapping a packet at a forwarding hop produces a new packet
*exactly as long as the one that came in*. `NIKE.NIKE` and `KEM.KEM` state their rules this way
— as types, not as separate theorems proved about otherwise-unconstrained functions:
`derivePublicKey`'s codomain, `groupAction`'s `Safe`-gated signature, `KEM.encap`'s plain
`Ciphertext × Plaintext` product, `KEM.generate`'s correctness witness riding in a `Σ'`. Neither
interface reaches for a bespoke named result structure to do this — a plain product (or, for
`generate`, a dependent pair) is enough. `unwrap` follows the same shape: its return type is

  `Except String (Option ByteArray × Vector UInt8 32 × List Command × Option (Vector UInt8 pkt.size))`
                    payload            replayTag         cmds              forwardPkt

*depending on `pkt`, `unwrap`'s own argument* — so the last component is forced to carry exactly
`pkt`'s length, for every instance, not just the ones an author remembered to prove something
about. No named `UnwrapResult` type is needed for that; the dependency is carried by the product
type itself. `NikeSphinx.unwrapNike` is the witness that a real implementation can meet this
signature; the one fact it leans on that isn't proved from first principles is `Crypto.AEZ`'s
`sprpEncrypt_size`/`sprpDecrypt_size` — axioms there, for the same reason `NIKE.X25519` leaves
`curve25519_commutes` an axiom (see that file's doc comment). -/

/-- A Sphinx packet-processing scheme: a private key type, a routing-command type, and
`unwrap`. -/
structure Sphinx where
  PrivateKey : Type
  Command : Type
  [privI : Inhabited PrivateKey]

  /-- Deterministic — unlike `NIKE.groupAction`/`KEM.decap`, `unwrap` needs no state or
  randomness, so this is a plain function returning `Except`, not `EStateM`. `String` (matching
  `NikeSphinx.unwrapNike`'s own choice) rather than a dedicated error type: the rejections
  (truncated packet, bad version, MAC mismatch, truncated/invalid payload) don't yet need to be
  matched on by any caller in this pass.

  The result, in order: the terminal payload (`none` when forwarding), the replay tag, the
  parsed per-hop routing commands, and — only when there is a next hop — the packet to forward
  on, of exactly the same length as `pkt`. -/
  unwrap : PrivateKey → (pkt : ByteArray) →
    Except String (Option ByteArray × Vector UInt8 32 × List Command × Option (Vector UInt8 pkt.size))

/-- Trivial instance, witnessing satisfiability — matches `NIKE`/`KEM`'s own `Inhabited`
instances, which exist for the same reason: an interface no scheme could ever inhabit would be
worth noticing. -/
instance : Inhabited Sphinx := ⟨{
  PrivateKey := Unit
  Command := Unit
  unwrap := fun _ _ => .ok (none, default, [], none)
}⟩

end CryptWalker.Sphinx.Sphinx

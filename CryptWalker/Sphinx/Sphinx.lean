/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Sphinx.Sphinx

/-! # The abstract Sphinx interface

A packet scheme, bundling its private-key/command types with `unwrap`. Only `unwrap` is here;
`wrap`/`createHeader` needs a randomness story shared between the NIKE and KEM variants that
doesn't exist yet.

`unwrap`'s return type depends on its own `pkt` argument: the forwarded packet, when there is
one, is `Vector UInt8 pkt.size` — same length as the input, by the type, not by a theorem proved
about it afterward. No named result type; a plain product carries it fine.

`NikeSphinx.unwrapNike` is the witness that a real implementation can meet this signature. The
one fact it leans on without proving it from first principles is `Crypto.AEZ`'s
`sprpEncrypt_size`/`sprpDecrypt_size`, left as axioms. -/

structure Sphinx where
  PrivateKey : Type
  Command : Type
  [privI : Inhabited PrivateKey]

  /-- `(payload, replayTag, cmds, forwardPkt)`. Deterministic, so `Except`, not `EStateM`. -/
  unwrap : PrivateKey → (pkt : ByteArray) →
    Except String (Option ByteArray × Vector UInt8 32 × List Command × Option (Vector UInt8 pkt.size))

instance : Inhabited Sphinx := ⟨{
  PrivateKey := Unit
  Command := Unit
  unwrap := fun _ _ => .ok (none, default, [], none)
}⟩

end CryptWalker.Sphinx.Sphinx

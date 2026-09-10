/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Commands

namespace CryptWalker.Sphinx.Types

open CryptWalker.Sphinx.Commands

/-- A hop in a Sphinx path: node ID, its public key (an X25519 public key for `NIKESphinx`, a
`kemX25519` ciphertext-target public key for `KEMSphinx` — both `Vector UInt8 32`), and its
non-`NextNodeHop` routing commands. Shared between the two variants, as Go's `PathHop` is (one
struct with both a `NIKEPublicKey` and a `KEMPublicKey` field, only one populated per use) —
concretely one field here since a given path is never both at once. -/
structure PathHop where
  id : Vector UInt8 32
  publicKey : Vector UInt8 32
  commands : List RoutingCommand
  deriving Inhabited

/-- The per-hop SPRP key + IV pair `createHeader` derives alongside the header, for onion
payload encryption. -/
structure SPRPKey where
  key : Vector UInt8 48
  iv : Vector UInt8 16
  deriving Inhabited

end CryptWalker.Sphinx.Types

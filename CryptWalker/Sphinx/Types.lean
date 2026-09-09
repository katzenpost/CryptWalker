/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Commands

namespace CryptWalker.Sphinx.Types

open CryptWalker.Sphinx.Commands

/-- A hop in a NIKE-Sphinx path: node ID, its X25519 public key, and its non-`NextNodeHop`
routing commands. Concrete to X25519 (`Vector UInt8 32`) rather than an abstract NIKE, matching
this pass's X25519-only scope — the Go original's `PathHop` carries a `nike.PublicKey`
interface value plus a separate, unused-here `KEMPublicKey` field. -/
structure PathHop where
  id : Vector UInt8 32
  nikePublicKey : Vector UInt8 32
  commands : List RoutingCommand
  deriving Inhabited

/-- The per-hop SPRP key + IV pair `createHeader` derives alongside the header, for onion
payload encryption. -/
structure SPRPKey where
  key : Vector UInt8 48
  iv : Vector UInt8 16
  deriving Inhabited

/-- A hop in a KEM-Sphinx path: node ID, its KEM public key (`kemX25519`'s, 32 bytes), and its
non-`NextNodeHop` routing commands. -/
structure KemPathHop where
  id : Vector UInt8 32
  kemPublicKey : Vector UInt8 32
  commands : List RoutingCommand
  deriving Inhabited

end CryptWalker.Sphinx.Types

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.commands

namespace CryptWalker.Sphinx.Types

open CryptWalker.Sphinx.Commands

/-- A hop in a Sphinx path: node ID, its public key (raw bytes — width depends on which
registered NIKE/KEM this path is for), and its non-`NextNodeHop` routing commands. Shared
between NIKE/KEM-Sphinx, as Go's `PathHop` is. -/
structure PathHop where
  id : Vector UInt8 32
  publicKey : ByteArray
  commands : List RoutingCommand
  deriving Inhabited

/-- The per-hop SPRP key + IV pair `createHeader` derives alongside the header, for onion
payload encryption. -/
structure SPRPKey where
  key : Vector UInt8 48
  iv : Vector UInt8 16
  deriving Inhabited

end CryptWalker.Sphinx.Types

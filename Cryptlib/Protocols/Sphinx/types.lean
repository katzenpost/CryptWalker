/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Protocols.Sphinx.commands

namespace Cryptlib.Protocols.Sphinx.Types

open Cryptlib.Protocols.Sphinx.Commands

/-- A path hop: node ID, raw public key bytes, and routing commands other than `nextNodeHop`. -/
structure PathHop where
  id : Vector UInt8 32
  publicKey : ByteArray
  commands : List RoutingCommand
  deriving Inhabited

/-- Per-hop SPRP key and IV for payload encryption. -/
structure SPRPKey where
  key : Vector UInt8 48
  iv : Vector UInt8 16
  deriving Inhabited

end Cryptlib.Protocols.Sphinx.Types

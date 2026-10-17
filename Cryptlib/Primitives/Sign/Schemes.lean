/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.Sign.Sign
import Cryptlib.Primitives.Sign.Blindable
import Cryptlib.Primitives.Sign.Combiner
import Cryptlib.Primitives.Sign.Convert
import Cryptlib.Primitives.Sign.Ed25519_blinded

/-! # Ed25519 with key blinding, and a hybrid -/

namespace Cryptlib.Primitives.Sign.Schemes

open Cryptlib.Primitives.Sign.Sign
open Cryptlib.Primitives.Sign.Blindable

/-- Ed25519 as a plain signature scheme. -/
abbrev ed25519Signature : Signature := Ed25519Blinded.signature

/-- Ed25519 with key blinding: blinding is scalar multiplication modulo `ℓ`. -/
abbrev ed25519Blindable : Blindable := Ed25519Blinded.blindable

/-- A hybrid signature: Ed25519 paired with a second scheme, here Ed25519 again. -/
def ed25519Hybrid : Signature :=
  Combiner.combineSign ed25519Signature ed25519Signature

end Cryptlib.Primitives.Sign.Schemes

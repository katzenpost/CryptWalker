/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Sign
import CryptWalker.Sign.Blindable
import CryptWalker.Sign.Combiner
import CryptWalker.Sign.Convert
import CryptWalker.Sign.Ed25519_blinded

/-! # Ed25519 with key blinding, and a hybrid -/

namespace CryptWalker.Sign.Schemes

open CryptWalker.Sign.Sign
open CryptWalker.Sign.Blindable

/-- Ed25519 as a plain signature scheme. -/
abbrev ed25519Signature : Signature := Ed25519Blinded.signature

/-- Ed25519 with key blinding: blinding is scalar multiplication modulo `ℓ`. -/
abbrev ed25519Blindable : Blindable := Ed25519Blinded.blindable

/-- A hybrid signature: Ed25519 paired with a second scheme, here Ed25519 again. -/
def ed25519Hybrid : Signature :=
  Combiner.combineSign ed25519Signature ed25519Signature

end CryptWalker.Sign.Schemes

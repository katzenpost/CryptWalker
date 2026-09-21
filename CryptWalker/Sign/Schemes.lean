/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Sign
import CryptWalker.Sign.Blindable
import CryptWalker.Sign.Combiner
import CryptWalker.Sign.Convert
import CryptWalker.Sign.Ed25519_blinded

/-! # Ed25519 with key blinding, and a hybrid

The instance is `Ed25519_blinded`'s, which is real: RFC 8032 arithmetic over `ZMod p`, with every
law a theorem. This file only names it for the abstractions in this directory and builds the
hybrid. The two assumptions underneath are `X25519.p_prime` and `Ed25519Blinded.ell_prime`,
primality of the field prime and of the group order; `Sign.Check` pins that. -/

namespace CryptWalker.Sign.Schemes

open CryptWalker.Sign.Sign
open CryptWalker.Sign.Blindable

/-- Ed25519 as a plain signature scheme. -/
abbrev ed25519Signature : Signature := Ed25519Blinded.signature

/-- Ed25519 with key blinding: blinding a private key *is* scalar multiplication,
`S_i^ctx = S_R × K_i^ctx mod ℓ`, exactly as the paper states it. -/
abbrev ed25519Blindable : Blindable := Ed25519Blinded.blindable

/-- A hybrid signature: Ed25519 paired with a second scheme. Instantiated here with Ed25519
twice, since no post-quantum scheme exists in CryptWalker yet; the intended pairing is
Ed25519 + Falcon, matching hpqc's `sign/hybrid`. -/
def ed25519Hybrid : Signature :=
  Combiner.combineSign ed25519Signature ed25519Signature

end CryptWalker.Sign.Schemes

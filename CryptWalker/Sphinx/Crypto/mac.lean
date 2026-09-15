/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Crypto.hmac
import CryptWalker.Sphinx.common

namespace CryptWalker.Sphinx.Crypto.MAC

/-! # Message authentication codes, generically

The same shape as `NIKE`, `KEM`, `Hash`, `HKDF`, `StreamCipher`, `WideBlockCipher`: a plain
structure, so callers depend only on its fields, never a specific algorithm's name. `key` is a
plain `ByteArray` (`keySize` informational only); the output stays a `Vector UInt8 tagSize`.

No law fields: unforgeability is a computational, adversary-quantified claim no `Prop` field
could state; determinism needs no stating either, since `mac` being a plain function already
gives it for free. -/

structure MAC where
  keySize : Nat
  tagSize : Nat

  mac : ByteArray → ByteArray → Vector UInt8 tagSize

/-- The empty MAC: a placeholder so `MAC` is demonstrably inhabited. Obviously not a MAC (constant
output, ignores both arguments). -/
instance : Inhabited MAC := ⟨{
  keySize := 0
  tagSize := 0
  mac := fun _ _ => #v[]
}⟩

/-- HMAC-SHA256, as a `MAC`: Sphinx's own `mac`/`hmacSha256` wrapper (`Common.mac`), keyed via
`toVecN` to bridge the plain-`ByteArray` key this structure wants. -/
def hmacSha256MAC : MAC where
  keySize := 32
  tagSize := 32
  mac := fun key msg => CryptWalker.Sphinx.Common.mac (CryptWalker.Sphinx.Common.toVecN 32 key) msg

end CryptWalker.Sphinx.Crypto.MAC

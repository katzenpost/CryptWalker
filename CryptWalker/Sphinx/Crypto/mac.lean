/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Crypto.hmac
import CryptWalker.Sphinx.common

namespace CryptWalker.Sphinx.Crypto.MAC

/-! # Message authentication codes, generically

The same shape as `NIKE`, `KEM`, `Hash`, `HKDF`, `StreamCipher` and `WideBlockCipher`: a plain
structure, so callers depend only on its fields, never on a specific algorithm's name.

`key` is a plain `ByteArray`, not `Vector UInt8 keySize` — `keySize` stays informational only
(the same choice `WideBlockCipher.encrypt`/`decrypt` already makes for their key argument), so a
caller holding a fixed-width `Vector UInt8 32` key can pass any `MAC` instance's `mac` directly via
`ofVector`, with no equality proof tying that 32 to whatever `keySize` a given instance declares.
Only the output stays a `Vector UInt8 tagSize` — that width guarantee is worth keeping, and every
caller here immediately reinterprets it as a `ByteArray` (`ofVector`) before comparing or
concatenating, so its exact value never has to be threaded through call sites either.

## Why this structure has no law fields at all

Unlike its siblings, `MAC` states no `Prop` field, not even a size fact — `tagSize` already pins
the output width at the type level. The one property that would actually matter — unforgeability,
that no adversary without `key` can produce `(msg, tag)` with `mac key msg = tag` for a fresh
`msg` — is exactly the kind of computational, adversary-quantified claim `Hash.lean`'s doc comment
explains can never be a struct field: no concrete instance could discharge it as a `Prop`, since it
isn't one. Determinism ("same key and message, same tag") isn't stated either, for the opposite
reason: `mac` is a plain Lean function, so it holds of *any* value this field could be given,
vacuously — it can't distinguish a real MAC from garbage, so writing it down adds nothing an
instance could fail. What Sphinx's completeness proof actually needs from a MAC is exactly this:
recomputing `mac` on the same key and message the sender used always reproduces the same tag,
which is simply what it means for `mac` to be a function of its arguments — no separate law
required. -/

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
`toVecN` — `Common.mac` itself takes a fixed `Vector UInt8 32`, so the plain-`ByteArray` key this
structure's shape wants is reinterpreted the same way every other 32-byte key in this codebase is
(`Common.toVecN`, total via `ByteArray.get!`'s default-on-out-of-range behavior, never exercised
here since callers always supply exactly 32 bytes). -/
def hmacSha256MAC : MAC where
  keySize := 32
  tagSize := 32
  mac := fun key msg => CryptWalker.Sphinx.Common.mac (CryptWalker.Sphinx.Common.toVecN 32 key) msg

end CryptWalker.Sphinx.Crypto.MAC

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.KDF

/-! # Key-derivation functions, generically

The same shape as `NIKE`, `KEM`, `Hash`, `StreamCipher`, `MAC`, `WideBlockCipher`: a plain
structure whose one law is a field.

Lighter than `Hash.HKDF`, which models the full Extract-then-Expand construction: this interface
skips Extract, taking the raw input keying material directly — just expand it into exactly `len`
bytes, deterministically. `HKDF.lean`'s `hkdfSha256Expand` is the one instance so far, matching
what Sphinx's own KDF needs (see `Sphinx.KDF`). -/

structure KDF where
  /-- Expand `(ikm, info)` into exactly `len` bytes of output key material. -/
  expand : ByteArray → ByteArray → (len : Nat) → ByteArray

  expand_size : ∀ ikm info len, (expand ikm info len).size = len

/-- The empty KDF: a placeholder so `KDF` is demonstrably inhabited. Obviously not a KDF
(all-zero output, ignores both inputs). -/
instance : Inhabited KDF := ⟨{
  expand := fun _ _ len => ⟨Array.replicate len 0⟩
  expand_size := fun _ _ len => by simp [ByteArray.size]
}⟩

end CryptWalker.KDF

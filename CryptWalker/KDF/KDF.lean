/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.KDF

/-! # Key-derivation functions

Expand-only: the input keying material is used directly, with no Extract step. -/

structure KDF where
  /-- Expand `(ikm, info)` into exactly `len` bytes of output key material. -/
  expand : ByteArray → ByteArray → (len : Nat) → ByteArray

  expand_size : ∀ ikm info len, (expand ikm info len).size = len

/-- The empty KDF, to show `KDF` is inhabited. Not a KDF. -/
instance : Inhabited KDF := ⟨{
  expand := fun _ _ len => ⟨Array.replicate len 0⟩
  expand_size := fun _ _ len => by simp [ByteArray.size]
}⟩

end CryptWalker.KDF

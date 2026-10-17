/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace Cryptlib.Primitives.StreamCipher

/-! # Stream ciphers, generically

Pseudorandomness is computational and not stated. The one law is that a request for `len` bytes
of keystream produces exactly `len` bytes. `keySize`/`ivSize` are informational. -/

structure StreamCipher where
  keySize : Nat
  ivSize : Nat

  /-- `len` bytes of keystream from a key and IV. `len` need not be a block multiple. -/
  keystream : ByteArray → ByteArray → (len : Nat) → ByteArray

  keystream_size : ∀ key iv len, (keystream key iv len).size = len

/-- An all-zero keystream, showing the law is satisfiable. Provides no security. -/
instance : Inhabited StreamCipher := ⟨{
  keySize := 0
  ivSize  := 0
  keystream      := fun _ _ len => ⟨Array.replicate len 0⟩
  keystream_size := fun _ _ len => by simp [ByteArray.size]
}⟩

end Cryptlib.Primitives.StreamCipher

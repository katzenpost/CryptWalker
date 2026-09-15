/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.StreamCipher

/-! # Stream ciphers, generically

The same shape as `NIKE`, `KEM`, `Hash`, `HKDF`, `MAC`, `WideBlockCipher`: a plain structure whose
one law is a field. `key`/`iv` are plain `ByteArray`s, `keySize`/`ivSize` informational only.

Pseudorandomness is computational, so it can't be a field here (as `Hash.lean` explains for
collision resistance); determinism needs no stating, since `keystream` being a plain function
already gives it. What *is* statable, and what routing-info encryption depends on to line up
sender and receiver, is the one structural constraint: a request for `len` bytes of keystream
produces exactly `len` bytes. -/

structure StreamCipher where
  keySize : Nat
  ivSize : Nat

  /-- `len` bytes of keystream, from a key and nonce/IV. Any size `len`, including one not a
  multiple of the cipher's underlying block size. -/
  keystream : ByteArray → ByteArray → (len : Nat) → ByteArray

  keystream_size : ∀ key iv len, (keystream key iv len).size = len

/-- The empty stream cipher: a placeholder so `StreamCipher` is demonstrably inhabited. Obviously
not a stream cipher (every output is all-zero). -/
instance : Inhabited StreamCipher := ⟨{
  keySize := 0
  ivSize  := 0
  keystream      := fun _ _ len => ⟨Array.replicate len 0⟩
  keystream_size := fun _ _ len => by simp [ByteArray.size]
}⟩

end CryptWalker.StreamCipher

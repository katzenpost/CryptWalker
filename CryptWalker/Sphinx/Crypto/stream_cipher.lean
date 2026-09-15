/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Crypto.stream
import CryptWalker.Sphinx.common
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.Crypto.StreamCipher

open CryptWalker.Util.Bytes

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

/-! ## AES-256-CTR, as a `StreamCipher` -/

namespace AES256CTR

open CryptWalker.Cipher.AES

/-- Generic over the per-block function `f` — never needs to name `Stream.counterBlock`, which is
private to `Stream.lean`; unification against the unfolded goal below supplies it. -/
private theorem fold16_size (f : Nat → Vector UInt8 16) (n : Nat) :
    ((List.range n).foldl (fun (out : ByteArray) i => out ++ ofVector (f i))
      ByteArray.empty).size = 16 * n := by
  induction n with
  | zero => simp
  | succ n ih =>
    rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
    simp [ByteArray.size_append, ih, Nat.mul_succ]

theorem keystream_size (key : Vector UInt8 32) (iv : Vector UInt8 16) (len : Nat) :
    (Stream.keystream key iv len).size = len := by
  unfold Stream.keystream
  dsimp only
  rw [ByteArray.size_extract, fold16_size]
  have : len ≤ 16 * ((len + 15) / 16) := by omega
  omega

end AES256CTR

/-- `Stream.keystream` reinterpreted at plain-`ByteArray` key/IV, via `Common.toVecN`, as
`MAC.hmacSha256MAC` does. -/
def aes256CTR : StreamCipher where
  keySize := 32
  ivSize  := 16
  keystream := fun key iv len =>
    CryptWalker.Sphinx.Crypto.Stream.keystream (CryptWalker.Sphinx.Common.toVecN 32 key)
      (CryptWalker.Sphinx.Common.toVecN 16 iv) len
  keystream_size := fun key iv len =>
    AES256CTR.keystream_size (CryptWalker.Sphinx.Common.toVecN 32 key)
      (CryptWalker.Sphinx.Common.toVecN 16 iv) len

end CryptWalker.Sphinx.Crypto.StreamCipher

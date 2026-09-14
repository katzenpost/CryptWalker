/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Crypto.Stream
import CryptWalker.Sphinx.Common
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.Crypto.StreamCipher

open CryptWalker.Util.Bytes

/-! # Stream ciphers, generically

The same shape as `NIKE`, `KEM`, `Hash`, `HKDF`, `MAC` and `WideBlockCipher`: a plain structure
whose one law is a field, so no instance can exist without discharging it.

`key`/`iv` are plain `ByteArray`, not `Vector UInt8 keySize`/`Vector UInt8 ivSize` — `keySize`/
`ivSize` stay informational only, as `WideBlockCipher.encrypt`/`decrypt`'s key already does, so a
caller holding fixed-width `Vector`s can pass any `StreamCipher` instance's `keystream` directly
via `ofVector`, with no equality proof tying those widths to whatever an instance declares.

## What can and cannot be a law here

Pseudorandomness (that `keystream key iv` is indistinguishable from true random bits without
`key`) is computational — it quantifies over adversaries and negligible functions — so it cannot
be a field here, for the same reason `Hash.lean` gives for collision resistance: no instance could
ever discharge it as a `Prop`. Determinism ("same inputs, same output") is likewise not stated:
`keystream` is a plain Lean function, so it holds of *any* value this field could be given,
vacuously, and can't distinguish a real stream cipher from garbage.

What *is* statable, and is exactly what Sphinx's routing-info encryption depends on to line up
sender and receiver, is the one genuine structural constraint: a request for `len` bytes of
keystream actually produces `len` bytes, for every `len` — not fewer (which would silently pad
with implicit zeros wherever `xorBytes` reads past the end) and not more (which would silently
truncate). -/

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

/-- `Stream.keystream` reinterpreted at plain-`ByteArray` key/IV, via `Common.toVecN` — the same
total, default-on-wrong-length reinterpretation `MAC.hmacSha256MAC` uses, never exercised here
since callers always supply exactly 32/16 bytes. -/
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

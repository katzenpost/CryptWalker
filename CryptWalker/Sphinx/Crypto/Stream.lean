/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Cipher.AES
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.Crypto.Stream

open CryptWalker.Cipher.AES
open CryptWalker.Util.Bytes

/-! # AES-256-CTR (Sphinx's header/routing-info stream cipher)

`crypto.NewStream` (`katzenpost/core/sphinx/internal/crypto/crypto.go`) is
`cipher.NewCTR(blk, iv)` from Go's standard library, keyed with the full 32-byte
`StreamKeyLength` (AES-256) and a 16-byte IV.

Go's `crypto/cipher.NewCTR` treats the **entire** IV as one big-endian 128-bit counter that
increments (with wraparound) once per block — this is *not* the same counter convention as
`Cipher.AESGCMSIV`'s `counterBlock`/`keystreamBlock`, which is RFC 8452's 32-bit
little-endian counter confined to the first four bytes. The two cannot share code; this file
reimplements the standard big-endian full-block counter.

`crypto.Stream.KeyStream` zero-fills its destination buffer and then XORs the keystream into
it, i.e. it returns the keystream itself — so `keystream` below is what the vectors record. -/

/-- 16 bytes read as a big-endian 128-bit natural number. -/
private def toNat128 (v : Vector UInt8 16) : Nat :=
  v.toList.foldl (fun acc b => acc * 256 + b.toNat) 0

/-- The inverse, wrapping modulo `2^128` (`crypto/cipher.NewCTR`'s counter overflow behavior). -/
private def ofNat128 (n : Nat) : Vector UInt8 16 :=
  Vector.ofFn fun i : Fin 16 => UInt8.ofNat ((n % 2 ^ 128) >>> (8 * (15 - i.val)))

/-- Counter block `i`: the IV as a 128-bit big-endian integer, plus `i`. -/
private def counterBlock (iv : Vector UInt8 16) (i : Nat) : Vector UInt8 16 :=
  ofNat128 (toNat128 iv + i)

/-- `len` bytes of AES-256-CTR keystream. The key is scheduled once and reused across blocks. -/
def keystream (key : Vector UInt8 32) (iv : Vector UInt8 16) (len : Nat) : ByteArray :=
  let rk := expandKey key
  ((List.range ((len + 15) / 16)).foldl
    (fun out i => out ++ ofVector (encryptBlock rk (counterBlock iv i)))
    ByteArray.empty).extract 0 len

end CryptWalker.Sphinx.Crypto.Stream

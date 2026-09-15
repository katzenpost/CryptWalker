/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Hash.Sha2

namespace CryptWalker.Sphinx.Crypto.HMAC

open CryptWalker.Hash.Sha2

/-! # HMAC-SHA256

Sphinx's header MAC (`crypto.NewMAC` in `katzenpost/core/sphinx/internal/crypto/crypto.go`):
`hmac.New(sha256.New, key)`, used at the full 32-byte tag width (`MACLength = 32`).

RFC 2104, following the same shape as `Hash.HKDF`'s inline `blake2b512.hmac64` — sized to
SHA-256's 64-byte block instead of BLAKE2b-512's 128-byte one, and calling `Sha256.hash`
directly rather than going through the abstract `Hash` structure, matching that file's
established pattern of calling the concrete hash function rather than its `Hash.hash` field. -/

private def blockSize : Nat := 64

private def xorPad (key : ByteArray) (pad : UInt8) : ByteArray :=
  let padded := key ++ ⟨Array.replicate (blockSize - key.size) 0⟩
  ⟨padded.data.map (fun b => b ^^^ pad)⟩

/-- `Sha256.hash` as a `Vector UInt8 32`, unwrapping the subtype. -/
private def hash32 (m : ByteArray) : Vector UInt8 32 :=
  ⟨(Sha256.hash m).1.data, (Sha256.hash m).2⟩

/-- **HMAC-SHA256**, full 32-byte tag. Keys longer than the block are first hashed down, per
RFC 2104 §2. -/
def hmacSha256 (key msg : ByteArray) : Vector UInt8 32 :=
  let key := if key.size > blockSize then ⟨(hash32 key).toArray⟩ else key
  hash32 (xorPad key 0x5c ++ ⟨(hash32 (xorPad key 0x36 ++ msg)).toArray⟩)

end CryptWalker.Sphinx.Crypto.HMAC

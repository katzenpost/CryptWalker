/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Hash.Sha2
import CryptWalker.MAC.MAC

namespace CryptWalker.MAC.HMAC

open CryptWalker.Hash.Sha2

/-! # HMAC-SHA256

RFC 2104, sized to SHA-256's 64-byte block, calling `Sha256.hash` directly. -/

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

/-- HMAC-SHA256, as a `MAC`: `hmacSha256`'s own signature already matches `MAC.mac`'s shape
exactly, no `ByteArray`/`Vector` reinterpretation needed. -/
def hmacSha256MAC : CryptWalker.MAC.MAC where
  keySize := 32
  tagSize := 32
  mac := hmacSha256

end CryptWalker.MAC.HMAC

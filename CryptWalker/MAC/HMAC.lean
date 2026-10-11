/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Hash.Hash
import CryptWalker.Hash.Sha2
import CryptWalker.MAC.MAC
import CryptWalker.Util.Bytes

namespace CryptWalker.MAC.HMAC

open CryptWalker.Hash.Hash
open CryptWalker.Util.Bytes (ofVector)

/-! # HMAC (RFC 2104), over any `Hash` -/

private def xorPad (H : Hash) (key : ByteArray) (pad : UInt8) : ByteArray :=
  let padded := key ++ ⟨Array.replicate (H.blockSize - key.size) 0⟩
  ⟨padded.data.map (fun b => b ^^^ pad)⟩

/-- Keys longer than the hash's block are first hashed down, per RFC 2104 §2. -/
def hmac (H : Hash) (key msg : ByteArray) : Vector UInt8 H.digestSize :=
  let key := if key.size > H.blockSize then ofVector (H.hash key) else key
  H.hash (xorPad H key 0x5c ++ ofVector (H.hash (xorPad H key 0x36 ++ msg)))

def hmacMAC (H : Hash) : CryptWalker.MAC.MAC where
  keySize := H.digestSize
  tagSize := H.digestSize
  mac := hmac H

def hmacSha256 (key msg : ByteArray) : Vector UInt8 32 :=
  hmac CryptWalker.Hash.Sha2.Sha256.Scheme key msg

def hmacSha256MAC : CryptWalker.MAC.MAC where
  keySize := 32
  tagSize := 32
  mac := hmacSha256

end CryptWalker.MAC.HMAC

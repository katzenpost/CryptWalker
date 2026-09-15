/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Crypto.hmac
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.Crypto.KDF

open CryptWalker.Sphinx.Crypto.HMAC
open CryptWalker.Util.Bytes

/-! # Sphinx's `PacketKeys` derivation

`crypto.KDF` is HKDF-SHA256 (RFC 5869) **Expand only**: the raw DH/KEM shared secret is used
directly as the PRK, no Extract step, reading 160 bytes of OKM sliced into five fields. Deferred
per the project's vectors-first pass: no laws are stated about this module.

The fifth slice, `blindingFactorSeed`, is the raw 32 bytes Go's `KDF` feeds to derive the NIKE
`BlindingFactor` private key; turning it into one is `NIKE.lean`'s `privateKeyFromSeed`'s job
(unused for KEM-Sphinx), not this module's. -/

/-- Not `private`: `GenericKDF.packetKeysFrom` reuses this exact string to slice `PacketKeys` out
of any `GenericKDF.KDF` instance's `expand`, not just this file's own `expand`. -/
def kdfInfo : ByteArray := ⟨"katzenpost-kdf-v0-hkdf-sha256".toUTF8.data⟩

/-- RFC 5869 §2.3 Expand: iterated HMAC-SHA256 over `(PRK, T(i-1) ‖ info ‖ i)`. `prk` is the raw
input keying material — Sphinx's Extract-skipping shortcut. -/
def expand (prk info : ByteArray) (len : Nat) : ByteArray :=
  if len = 0 then ByteArray.empty
  else
    let blocks := (len + 31) / 32
    let rec go : Nat → Nat → ByteArray → ByteArray → ByteArray
      | 0, _, _, out => out.extract 0 len
      | fuel + 1, i, prev, out =>
        let t_i := ofVector (hmacSha256 prk (prev ++ info ++ ⟨#[i.toUInt8]⟩))
        go fuel (i + 1) t_i (out ++ t_i)
    go blocks 1 ByteArray.empty ByteArray.empty

/-- The per-hop Sphinx packet keys, one field per slice of the 160-byte OKM, in order. -/
structure PacketKeys where
  headerMAC          : Vector UInt8 32
  headerEncryption   : Vector UInt8 32
  headerEncryptionIV : Vector UInt8 16
  payloadEncryption  : Vector UInt8 48
  blindingFactorSeed : Vector UInt8 32

/-- Reinterpret a `len`-byte slice of a `ByteArray` as a fixed-width vector (never out of range in
practice, since the caller always supplies a 160-byte `okm`). Not `private`:
`GenericKDF.packetKeysFrom` reuses it too. -/
def sliceV (b : ByteArray) (off len : Nat) : Vector UInt8 len :=
  Vector.ofFn fun i : Fin len => b.data.getD (off + i.val) 0

/-- **Sphinx's KDF**: expand the raw shared secret into 160 bytes of OKM and slice it into
`PacketKeys`, exactly as `crypto.KDF` does. -/
def sphinxKDF (ikm : ByteArray) : PacketKeys :=
  let okm := expand ikm kdfInfo (32 + 32 + 16 + 48 + 32)
  { headerMAC          := sliceV okm 0 32
    headerEncryption   := sliceV okm 32 32
    headerEncryptionIV := sliceV okm 64 16
    payloadEncryption  := sliceV okm 80 48
    blindingFactorSeed := sliceV okm 128 32 }

end CryptWalker.Sphinx.Crypto.KDF

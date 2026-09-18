/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.KDF.KDF
import CryptWalker.KDF.HKDF
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.KDF

open CryptWalker.Util.Bytes

/-! # Sphinx's `PacketKeys` derivation

`crypto.KDF` (`katzenpost/core/sphinx/internal/crypto/crypto.go`) is `CryptWalker.KDF.HKDF`'s
Expand-only construction, keyed by the raw DH/KEM shared secret, reading 160 bytes of OKM sliced
into five fields. Deferred per the project's vectors-first pass: no laws are stated about this
module.

The fifth slice, `blindingFactorSeed`, is the raw 32 bytes Go's `KDF` feeds to derive the NIKE
`BlindingFactor` private key; turning it into one is `NIKE.lean`'s `privateKeyFromSeed`'s job
(unused for KEM-Sphinx), not this module's. -/

/-- Not `private`: `packetKeysFrom` reuses this exact string to slice `PacketKeys` out of any
`KDF.KDF` instance's `expand`, not just `hkdfSha256Expand`'s own. -/
def kdfInfo : ByteArray := ⟨"katzenpost-kdf-v0-hkdf-sha256".toUTF8.data⟩

/-- The per-hop Sphinx packet keys, one field per slice of the 160-byte OKM, in order. -/
structure PacketKeys where
  headerMAC          : Vector UInt8 32
  headerEncryption   : Vector UInt8 32
  headerEncryptionIV : Vector UInt8 16
  payloadEncryption  : Vector UInt8 48
  blindingFactorSeed : Vector UInt8 32

/-- Reinterpret a `len`-byte slice of a `ByteArray` as a fixed-width vector (never out of range in
practice, since the caller always supplies a 160-byte `okm`). -/
def sliceV (b : ByteArray) (off len : Nat) : Vector UInt8 len :=
  Vector.ofFn fun i : Fin len => b.data.getD (off + i.val) 0

/-- **Sphinx's KDF**: expand the raw shared secret into 160 bytes of OKM and slice it into
`PacketKeys`, exactly as `crypto.KDF` does. -/
def sphinxKDF (ikm : ByteArray) : PacketKeys :=
  let okm := CryptWalker.KDF.HKDF.expand ikm kdfInfo (32 + 32 + 16 + 48 + 32)
  { headerMAC          := sliceV okm 0 32
    headerEncryption   := sliceV okm 32 32
    headerEncryptionIV := sliceV okm 64 16
    payloadEncryption  := sliceV okm 80 48
    blindingFactorSeed := sliceV okm 128 32 }

/-- `PacketKeys`, generic over which `KDF` does the expansion — Sphinx's domain-separation string
and the five fields' offsets/widths are fixed, only the KDF algorithm varies. Agrees with
`sphinxKDF` exactly when `kdf = CryptWalker.KDF.HKDF.hkdfSha256Expand`. `blindingFactorSeed` is
included for parity even though KEM-Sphinx never reads it. -/
def packetKeysFrom (kdf : CryptWalker.KDF.KDF) (ikm : ByteArray) : PacketKeys :=
  let okm := kdf.expand ikm kdfInfo (32 + 32 + 16 + 48 + 32)
  { headerMAC          := sliceV okm 0 32
    headerEncryption   := sliceV okm 32 32
    headerEncryptionIV := sliceV okm 64 16
    payloadEncryption  := sliceV okm 80 48
    blindingFactorSeed := sliceV okm 128 32 }

/-- Sanity check: `packetKeysFrom` at the concrete `hkdfSha256Expand` instance is definitionally
`sphinxKDF` — the generalization above didn't change Sphinx's actual key derivation. -/
theorem packetKeysFrom_hkdfSha256Expand (ikm : ByteArray) :
    packetKeysFrom CryptWalker.KDF.HKDF.hkdfSha256Expand ikm = sphinxKDF ikm := rfl

end CryptWalker.Sphinx.KDF

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.KDF.KDF
import Cryptlib.Primitives.KDF.HKDF
import Cryptlib.Util.Bytes

namespace Cryptlib.Protocols.Sphinx.KDF

open Cryptlib.Util.Bytes

/-! # Sphinx packet key derivation

HKDF-Expand of the shared secret into 160 bytes, sliced into five keys. -/

def kdfInfo : ByteArray := ⟨"katzenpost-kdf-v0-hkdf-sha256".toUTF8.data⟩

/-- The per-hop packet keys, in OKM order. -/
structure PacketKeys where
  headerMAC          : Vector UInt8 32
  headerEncryption   : Vector UInt8 32
  headerEncryptionIV : Vector UInt8 16
  payloadEncryption  : Vector UInt8 48
  blindingFactorSeed : Vector UInt8 32

/-- A `len`-byte slice of `b` as a fixed-width vector. -/
def sliceV (b : ByteArray) (off len : Nat) : Vector UInt8 len :=
  Vector.ofFn fun i : Fin len => b.data.getD (off + i.val) 0

/-- Derive `PacketKeys` from a shared secret with HKDF-SHA256. -/
def sphinxKDF (ikm : ByteArray) : PacketKeys :=
  let okm := Cryptlib.Primitives.KDF.HKDF.expand Cryptlib.Primitives.Hash.Sha2.Sha256.Scheme ikm kdfInfo (32 + 32 + 16 + 48 + 32)
  { headerMAC          := sliceV okm 0 32
    headerEncryption   := sliceV okm 32 32
    headerEncryptionIV := sliceV okm 64 16
    payloadEncryption  := sliceV okm 80 48
    blindingFactorSeed := sliceV okm 128 32 }

/-- Derive `PacketKeys` with an arbitrary `KDF`. -/
def packetKeysFrom (kdf : Cryptlib.Primitives.KDF.KDF) (ikm : ByteArray) : PacketKeys :=
  let okm := kdf.expand ikm kdfInfo (32 + 32 + 16 + 48 + 32)
  { headerMAC          := sliceV okm 0 32
    headerEncryption   := sliceV okm 32 32
    headerEncryptionIV := sliceV okm 64 16
    payloadEncryption  := sliceV okm 80 48
    blindingFactorSeed := sliceV okm 128 32 }

/-- `packetKeysFrom hkdfSha256Expand` is `sphinxKDF`. -/
theorem packetKeysFrom_hkdfSha256Expand (ikm : ByteArray) :
    packetKeysFrom Cryptlib.Primitives.KDF.HKDF.hkdfSha256Expand ikm = sphinxKDF ikm := rfl

end Cryptlib.Protocols.Sphinx.KDF

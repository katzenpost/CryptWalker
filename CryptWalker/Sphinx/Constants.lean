/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Sphinx.Constants

/-! # Sphinx Packet Format constants

The truly fixed constants — everything else (header/routing-info/packet lengths) is *computed*
from these plus a NIKE/KEM scheme's key/ciphertext size, in `Geometry.lean`. Two sources:

* `katzenpost/core/sphinx/constants/constants.go`
* `katzenpost/core/sphinx/internal/crypto/crypto.go` (the crypto-primitive-derived sizes) —
  cross-referenced against the ported primitives in `Sphinx.Crypto` rather than restated as
  independent literals, so the two can't silently drift apart. -/

/-- `constants.NodeIDLength`. -/
def nodeIDLength : Nat := 32

/-- `constants.RecipientIDLength`. -/
def recipientIDLength : Nat := 32

/-- `constants.SURBIDLength`. -/
def surbIDLength : Nat := 16

/-- `constants.CommandTagLength`: the one-byte command-type tag every routing command starts
with. -/
def commandTagLength : Nat := 1

/-- `internal/crypto.MACLength`: `HMAC.hmacSha256`'s full tag width. -/
def macLength : Nat := 32

/-- `internal/crypto.HashLength`: `sha512_256`'s digest width, used for the replay tag. -/
def hashLength : Nat := 32

/-- `internal/crypto.StreamKeyLength`/`StreamIVLength`: `Crypto.Stream.keystream`'s key/IV. -/
def streamKeyLength : Nat := 32
def streamIVLength : Nat := 16

/-- `internal/crypto.SPRPKeyLength`/`SPRPIVLength`: `Crypto.AEZ`'s key/nonce. -/
def sprpKeyLength : Nat := 48
def sprpIVLength : Nat := streamIVLength

/-- `internal/crypto.privateKeySeedSize`: width of `KDF.PacketKeys.blindingFactorSeed`. -/
def privateKeySeedSize : Nat := 32

/-- `geo.nextNodeHopLength`: `1 (tag) + NodeIDLength + MACLength`. -/
def nextNodeHopLength : Nat := commandTagLength + nodeIDLength + macLength

/-- `geo.surbReplyLength`: `1 (tag) + SURBIDLength`. -/
def surbReplyLength : Nat := commandTagLength + surbIDLength

/-- `geo.adLength`: the two-byte version/domain prefix on every Sphinx header. -/
def adLength : Nat := 2

/-- `geo.payloadTagLength`: the all-zero tag a correctly-onion-decrypted payload ends in. -/
def payloadTagLength : Nat := 32

/-- `geo.sphinxPlaintextHeaderLength`. -/
def sphinxPlaintextHeaderLength : Nat := 2

/-- `geo.sprpKeyMaterialLength`: `SPRPKeyLength + SPRPIVLength`, one SURB reply-payload key. -/
def sprpKeyMaterialLength : Nat := sprpKeyLength + sprpIVLength

end CryptWalker.Sphinx.Constants

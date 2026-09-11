/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Constants
import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Common
import CryptWalker.Sphinx.Crypto.AEZ
import CryptWalker.Util.Bytes

/-! # Single-use reply blocks (SURB)

`surb.go`'s `NewPacketFromSURB` (below) and `DecryptSURBPayload`, both shared between NIKE- and
KEM-Sphinx (Go has them as plain `*Sphinx` methods needing only `s.geometry`, not which header
variant built the SURB) — so they live here alongside `newNIKESURB`/`newKEMSURB` in
`NIKESphinx.lean`/`KEMSphinx.lean`, the halves that *do* differ (each calls its own
`createHeader`/`createKEMHeader`). -/

namespace CryptWalker.Sphinx.SURB

open CryptWalker.Sphinx.Constants
open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.Common (toVec32)
open CryptWalker.Sphinx.Crypto.AEZ (sprpEncrypt sprpDecrypt)
open CryptWalker.Util.Bytes (ofVector)

/-- **`DecryptSURBPayload`**. `keys` is `nrHops * sprpKeyMaterialLength` bytes: `nrHops`
`(key[48] ++ iv[16])` chunks, in the reverse-hop order `surb.go` serializes them in. All but the
last chunk *encrypts* (undoing one decrypt layer `Unwrap` applied while forwarding the reply);
the last chunk decrypts, matching what the replier's own `NewPacketFromSURB` encrypted with. -/
def decryptSURBPayload (geom : Geometry) (keys payload : ByteArray) : Except String ByteArray := do
  if keys.size % sprpKeyMaterialLength ≠ 0 || keys.size / sprpKeyMaterialLength < 1 then
    throw "sphinx: invalid SURB decryption keys"
  if payload.size < geom.payloadTagLength then throw "sphinx: truncated payload"
  let nrHops := keys.size / sprpKeyMaterialLength
  let mut b := payload
  for i in [0:nrHops] do
    let off := i * sprpKeyMaterialLength
    let key := (keys.extract off (off + sprpKeyLength)).data
    let iv := keys.extract (off + sprpKeyLength) (off + sprpKeyMaterialLength)
    b := if i == nrHops - 1 then sprpDecrypt key iv b else sprpEncrypt key iv b
  let tag := b.extract 0 geom.payloadTagLength
  if !tag.data.all (· == 0) then throw "sphinx: payload auth failed"
  pure (b.extract geom.payloadTagLength b.size)

/-- **`NewPacketFromSURB`**: build a reply packet from a SURB and a payload. `surb` is
`header ‖ firstHopID(32) ‖ sprpKey(48) ‖ sprpIV(16)` (`SURBLength = HeaderLength + 32 + 64`
bytes) — `newNIKESURB`/`newKEMSURB`'s wire layout. Returns `(packet, firstHopID)`. -/
def newPacketFromSURB (geom : Geometry) (surb payload : ByteArray) :
    Except String (ByteArray × Vector UInt8 32) := do
  if surb.size ≠ geom.surbLength then throw "sphinx: invalid packet, truncated SURB"
  let idOff := geom.headerLength
  let keyOff := idOff + nodeIDLength
  let ivOff := keyOff + sprpKeyLength
  let hdr := surb.extract 0 geom.headerLength
  let nodeID := toVec32 (surb.extract idOff keyOff)
  let sprpKey := (surb.extract keyOff ivOff).data
  let sprpIV := surb.extract ivOff surb.size
  let body := (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload
  pure (hdr ++ sprpEncrypt sprpKey sprpIV body, nodeID)

end CryptWalker.Sphinx.SURB

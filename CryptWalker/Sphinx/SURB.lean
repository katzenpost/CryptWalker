/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Constants
import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Crypto.AEZ

/-! # Single-use reply blocks (SURB): decrypt side only

`surb.go`'s creation side (`newNikeSURB`/`newKemSURB`/`NewPacketFromSURB`) isn't ported yet;
`DecryptSURBPayload` is, since it's what `Phase 4`'s vendored `sphinx_vectors.json` needs — its
`SurbKeys` field is already the decryption-keys blob, not something a test has to construct. -/

namespace CryptWalker.Sphinx.SURB

open CryptWalker.Sphinx.Constants
open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.Crypto.AEZ (sprpEncrypt sprpDecrypt)

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

end CryptWalker.Sphinx.SURB

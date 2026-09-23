/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.MKEM.Adapter
import CryptWalker.NIKE.X25519
import CryptWalker.Cipher.AESGCMSIV
import CryptWalker.Hash.Hash
import CryptWalker.Hash.Blake2b

/-! # Concrete MKEM instances

`mkemX25519` is `mkemOfNike` over X25519, AES-256-GCM-SIV and BLAKE2b-256. It shows the whole
construction typechecks against real primitives, with every `MKEM` law discharged.

**Not byte-compatible with `hpqc`.** hpqc's MKEM uses ChaCha20-Poly1305 and, in deployment, the
CTIDH1024-X25519 hybrid NIKE (`kem/mkem/testdata/mkem.json` covers only that). CryptWalker has
neither CTIDH nor Poly1305, so there are no vectors to check this against; when both exist,
instantiate `mkemOfNike` with them and run the vector file. -/

namespace CryptWalker.MKEM.Schemes

open CryptWalker.Hash.Hash (Hash)

/-- BLAKE2b-256 as a `Hash`, accumulating the message and hashing at `finalize`, as
`HKDF.blake2b_hashScheme` does for BLAKE2b-512. -/
@[reducible] def blake2b256Scheme : Hash where
  State      := ByteArray
  name       := "BLAKE2b-256"
  digestSize := 32
  blockSize  := 128
  init       := ByteArray.empty
  update     := fun s m => s ++ m
  finalize   := CryptWalker.Hash.Blake2b.hash256
  hash       := CryptWalker.Hash.Blake2b.hash256
  hash_spec     := fun m => by rw [ByteArray.empty_append]
  update_append := fun _ _ _ => ByteArray.append_assoc

/-- MKEM over X25519, AES-256-GCM-SIV and BLAKE2b-256. -/
def mkemX25519 : CryptWalker.MKEM.MKEM.MKEM :=
  CryptWalker.MKEM.Adapter.mkemOfNike CryptWalker.NIKE.X25519.Scheme
    CryptWalker.Cipher.AESGCMSIV.Scheme blake2b256Scheme rfl

end CryptWalker.MKEM.Schemes

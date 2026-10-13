/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.MKEM.Adapter
import CryptWalker.NIKE.X25519
import CryptWalker.Cipher.AESGCMSIV
import CryptWalker.Hash.Hash
import CryptWalker.Hash.Blake2b

/-! # Concrete MKEM instances -/

namespace CryptWalker.MKEM.Schemes

open CryptWalker.Hash.Hash (Hash)

/-- BLAKE2b-256 as a `Hash`, hashing the accumulated message at `finalize`. -/
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

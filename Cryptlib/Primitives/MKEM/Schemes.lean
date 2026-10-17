/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.MKEM.Adapter
import Cryptlib.Primitives.NIKE.X25519
import Cryptlib.Primitives.Cipher.AESGCMSIV
import Cryptlib.Primitives.Hash.Hash
import Cryptlib.Primitives.Hash.Blake2b

/-! # Concrete MKEM instances -/

namespace Cryptlib.Primitives.MKEM.Schemes

open Cryptlib.Primitives.Hash.Hash (Hash)

/-- BLAKE2b-256 as a `Hash`, hashing the accumulated message at `finalize`. -/
@[reducible] def blake2b256Scheme : Hash where
  State      := ByteArray
  name       := "BLAKE2b-256"
  digestSize := 32
  blockSize  := 128
  init       := ByteArray.empty
  update     := fun s m => s ++ m
  finalize   := Cryptlib.Primitives.Hash.Blake2b.hash256
  hash       := Cryptlib.Primitives.Hash.Blake2b.hash256
  hash_spec     := fun m => by rw [ByteArray.empty_append]
  update_append := fun _ _ _ => ByteArray.append_assoc

/-- MKEM over X25519, AES-256-GCM-SIV and BLAKE2b-256. -/
def mkemX25519 : Cryptlib.Primitives.MKEM.MKEM.MKEM :=
  Cryptlib.Primitives.MKEM.Adapter.mkemOfNike Cryptlib.Primitives.NIKE.X25519.Scheme
    Cryptlib.Primitives.Cipher.AESGCMSIV.Scheme blake2b256Scheme rfl

end Cryptlib.Primitives.MKEM.Schemes

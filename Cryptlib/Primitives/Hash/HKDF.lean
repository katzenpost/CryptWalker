/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.Hash.Hash
import Cryptlib.Primitives.Hash.Blake2b
import Cryptlib.Primitives.KDF.HKDF
import Cryptlib.Util.Bytes

namespace Cryptlib.Primitives.Hash.HKDF

open Cryptlib.Primitives.Hash.Hash
open Cryptlib.Util.Bytes (ofVector toVecN)

/-! # HKDF: HMAC-based Key Derivation Function (RFC 5869)

Extract maps `(salt, IKM)` to a digest-sized `PRK`; Expand maps `(PRK, info, len)` to exactly
`len` bytes. -/

structure HKDF where
  hash : Hash

  PRK : Type
  encodePRK : PRK → Vector UInt8 hash.digestSize
  decodePRK : Vector UInt8 hash.digestSize → Option PRK

  extract : ByteArray → ByteArray → PRK
  expand  : PRK → ByteArray → (len : Nat) → Vector UInt8 len

  decode_encode_prk : ∀ prk, decodePRK (encodePRK prk) = some prk
  expand_size : ∀ prk info len, (expand prk info len).toArray.size = len

def trivialHKDF : HKDF where
  hash := default
  PRK := Unit
  encodePRK := fun _ => #v[]
  decodePRK := fun _ => some ()
  extract := fun _ _ => ()
  expand := fun _ _ len => Vector.replicate len 0
  decode_encode_prk := fun _ => rfl
  expand_size := fun _ _ len => by unfold Vector.toArray Vector.replicate; simp

instance : Inhabited HKDF := ⟨trivialHKDF⟩

/-! ## HKDF-BLAKE2b-512 -/

/-- BLAKE2b-512 as a `Hash`: accumulate the message, hash at finalize. -/
@[reducible] def blake2b_hashScheme : Hash where
  State      := ByteArray
  name       := "BLAKE2b-512"
  digestSize := 64
  blockSize  := 128
  init       := ByteArray.empty
  update     := fun s m => s ++ m
  finalize   := Cryptlib.Primitives.Hash.Blake2b.hash
  hash       := Cryptlib.Primitives.Hash.Blake2b.hash
  hash_spec     := fun m => by rw [ByteArray.empty_append]
  update_append := fun _ _ _ => ByteArray.append_assoc

/-- Extract-then-Expand over any `Hash`, the PRK being one digest. -/
def ofHash (H : Hash) : HKDF where
  hash      := H
  PRK       := Vector UInt8 H.digestSize
  encodePRK := fun v => v
  decodePRK := some
  extract   := Cryptlib.Primitives.KDF.HKDF.extract H
  expand    := fun prk info len =>
    toVecN len (Cryptlib.Primitives.KDF.HKDF.expand H (ofVector prk) info len)
  decode_encode_prk := fun _ => rfl
  expand_size := fun _ _ _ => Vector.size_toArray _

def blake2b512_hkdf : HKDF := ofHash blake2b_hashScheme

end Cryptlib.Primitives.Hash.HKDF

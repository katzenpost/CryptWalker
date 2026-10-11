/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Hash.Hash
import CryptWalker.Hash.Blake2b
import CryptWalker.KDF.HKDF
import CryptWalker.Util.Bytes

namespace CryptWalker.Hash.HKDF

open CryptWalker.Hash.Hash
open CryptWalker.Util.Bytes (ofVector toVecN)

/-! # HKDF: HMAC-based Key Derivation Function (RFC 5869)

## How this differs from `Hash`

A hash takes arbitrary input and produces a fixed-size digest. HKDF has two phases
with different types:

* **Extract** `(salt, IKM) → PRK`: a fixed-size intermediate key whose width equals the
  hash digest size. The `PRK` type is abstract — its width is a dependent type carried
  by `encodePRK` into `Vector UInt8 hash.digestSize`.
* **Expand** `(PRK, info, len) → OKM`: variable-length output. The `len` parameter
  appears in the return type `Vector UInt8 len`, giving a type-level width guarantee.

The laws bind the two phases: the output width is exactly `len`. These are structural
properties of the Extract-then-Expand composition, distinct from `Hash`'s
`update_append` law. -/

/-- HKDF: HMAC-based Key Derivation Function (RFC 5869). -/
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

/-- BLAKE2b-512 as a `Hash` instance.
    Stateful form matching SHA-512's `Scheme`: accumulate the message, hash at finalize. -/
@[reducible] def blake2b_hashScheme : Hash where
  State      := ByteArray
  name       := "BLAKE2b-512"
  digestSize := 64
  blockSize  := 128
  init       := ByteArray.empty
  update     := fun s m => s ++ m
  finalize   := CryptWalker.Hash.Blake2b.hash
  hash       := CryptWalker.Hash.Blake2b.hash
  hash_spec     := fun m => by rw [ByteArray.empty_append]
  update_append := fun _ _ _ => ByteArray.append_assoc

/-- Extract-then-Expand over any `Hash`, the PRK being one digest. -/
def ofHash (H : Hash) : HKDF where
  hash      := H
  PRK       := Vector UInt8 H.digestSize
  encodePRK := fun v => v
  decodePRK := some
  extract   := CryptWalker.KDF.HKDF.extract H
  expand    := fun prk info len =>
    toVecN len (CryptWalker.KDF.HKDF.expand H (ofVector prk) info len)
  decode_encode_prk := fun _ => rfl
  expand_size := fun _ _ _ => Vector.size_toArray _

def blake2b512_hkdf : HKDF := ofHash blake2b_hashScheme

end CryptWalker.Hash.HKDF

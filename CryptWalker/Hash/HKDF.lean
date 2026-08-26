/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Hash.Hash
import CryptWalker.Hash.Blake2b

namespace CryptWalker.Hash.HKDF

open CryptWalker.Hash.Hash

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

namespace blake2b512

private def block_size : Nat := 128

private def xorPad (key : ByteArray) (pad : UInt8) : ByteArray :=
  let padded := key ++ ⟨Array.replicate (block_size - key.size) 0⟩
  ⟨padded.data.map (fun b => b ^^^ pad)⟩

private def hmac64 (key msg : ByteArray) : Vector UInt8 64 :=
  let key := if key.size > block_size then ⟨(CryptWalker.Hash.Blake2b.hash key).toArray⟩ else key
  CryptWalker.Hash.Blake2b.hash
    (xorPad key 0x5c ++ ⟨(CryptWalker.Hash.Blake2b.hash (xorPad key 0x36 ++ msg)).toArray⟩)

def extractPRK (salt ikm : ByteArray) : Vector UInt8 64 :=
  let salt := if salt.size = 0 then ⟨Array.replicate 64 0⟩ else salt
  hmac64 salt ikm

/-- RFC 5869 Expand: iterated HMAC over (PRK, info, counter).
    Produces a `ByteArray` of exactly `len` bytes. -/
def expandRaw (prk : Vector UInt8 64) (info : ByteArray) (len : Nat) : ByteArray :=
  if len = 0 then ByteArray.empty
  else
    let prkBytes := ⟨prk.toArray⟩
    let blocks := (len + 63) / 64
    let rec go : Nat → Nat → ByteArray → ByteArray → ByteArray
      | 0, _, _, out => out.extract 0 len
      | fuel+1, i, prev, out =>
        let t_i := ⟨(hmac64 prkBytes (prev ++ info ++ ⟨#[i.toUInt8]⟩)).toArray⟩
        go fuel (i + 1) t_i (out ++ t_i)
    go blocks 1 ByteArray.empty ByteArray.empty

end blake2b512

/-- HKDF-BLAKE2b-512: concrete `HKDF` instance.

PRK is a 64-byte vector (one BLAKE2b-512 digest). Extract and expand are
implemented from the same underlying HMAC. -/
def blake2b512_hkdf : HKDF where
  hash      := blake2b_hashScheme
  PRK       := Vector UInt8 64
  encodePRK := fun v => v
  decodePRK := some

  extract := fun salt ikm => blake2b512.extractPRK salt ikm

  expand := fun prk info len =>
    let raw := blake2b512.expandRaw prk info len
    Vector.ofFn fun i : Fin len => raw[i.val]!

  decode_encode_prk := fun _ => rfl

  expand_size := fun prk info len =>
    (Vector.ofFn fun i : Fin len => (blake2b512.expandRaw prk info len)[i]!).size_toArray

end CryptWalker.Hash.HKDF

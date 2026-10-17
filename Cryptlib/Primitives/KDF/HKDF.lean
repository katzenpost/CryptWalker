/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.MAC.HMAC
import Cryptlib.Primitives.KDF.KDF
import Cryptlib.Util.Bytes

namespace Cryptlib.Primitives.KDF.HKDF

open Cryptlib.Primitives.Hash.Hash
open Cryptlib.Primitives.MAC.HMAC (hmac)
open Cryptlib.Util.Bytes (ofVector)

/-! # HKDF (RFC 5869), over any `Hash` -/

/-- RFC 5869 §2.2 Extract. An empty salt stands for `digestSize` zero bytes. -/
def extract (H : Hash) (salt ikm : ByteArray) : Vector UInt8 H.digestSize :=
  hmac H (if salt.size = 0 then ⟨Array.replicate H.digestSize 0⟩ else salt) ikm

/-- RFC 5869 §2.3 Expand: iterated HMAC over `(PRK, T(i-1) ‖ info ‖ i)`, truncated to `len`. -/
def expand (H : Hash) (prk info : ByteArray) (len : Nat) : ByteArray :=
  let rec go : Nat → Nat → ByteArray → ByteArray → ByteArray
    | 0, _, _, out => out
    | fuel + 1, i, prev, out =>
      let t := ofVector (hmac H prk (prev ++ info ++ ⟨#[i.toUInt8]⟩))
      go fuel (i + 1) t (out ++ t)
  let blocks := (len + H.digestSize - 1) / H.digestSize
  (go blocks 1 ByteArray.empty ByteArray.empty ++ ⟨Array.replicate len 0⟩).extract 0 len

theorem expand_size (H : Hash) (prk info : ByteArray) (len : Nat) :
    (expand H prk info len).size = len := by
  have h : (⟨Array.replicate len 0⟩ : ByteArray).size = len := Array.size_replicate
  simp only [expand, ByteArray.size_extract, ByteArray.size_append, h]
  omega

/-- Expand-only HKDF as a `KDF`, the raw input keying material used directly as the PRK. -/
def kdfOf (H : Hash) : Cryptlib.Primitives.KDF.KDF where
  expand      := expand H
  expand_size := expand_size H

def hkdfSha256Expand : Cryptlib.Primitives.KDF.KDF := kdfOf Cryptlib.Primitives.Hash.Sha2.Sha256.Scheme

end Cryptlib.Primitives.KDF.HKDF

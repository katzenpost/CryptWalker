/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.MAC.HMAC
import CryptWalker.KDF.KDF
import CryptWalker.Util.Bytes

namespace CryptWalker.KDF.HKDF

open CryptWalker.MAC.HMAC (hmacSha256)
open CryptWalker.Util.Bytes (ofVector)

/-! # HKDF-SHA256, Expand only (RFC 5869 §2.3)

The raw input keying material is used directly as the PRK, no Extract step — the shortcut
`Sphinx.KDF` needs (its own DH/KEM shared secret is already exactly `HashLen` bytes, so there's
nothing to extract down from). For the full two-phase Extract-then-Expand construction, see
`Hash.HKDF`. -/

/-- RFC 5869 §2.3 Expand: iterated HMAC-SHA256 over `(PRK, T(i-1) ‖ info ‖ i)`. `prk` is the raw
input keying material — the Extract-skipping shortcut. -/
def expand (prk info : ByteArray) (len : Nat) : ByteArray :=
  if len = 0 then ByteArray.empty
  else
    let blocks := (len + 31) / 32
    let rec go : Nat → Nat → ByteArray → ByteArray → ByteArray
      | 0, _, _, out => out.extract 0 len
      | fuel + 1, i, prev, out =>
        let t_i := ofVector (hmacSha256 prk (prev ++ info ++ ⟨#[i.toUInt8]⟩))
        go fuel (i + 1) t_i (out ++ t_i)
    go blocks 1 ByteArray.empty ByteArray.empty

private theorem go_size (prk info : ByteArray) (len : Nat) :
    ∀ fuel i prev out, len ≤ 32 * fuel + out.size →
      (expand.go prk info len fuel i prev out).size = len := by
  intro fuel
  induction fuel with
  | zero =>
    intro i prev out hle
    unfold expand.go
    rw [ByteArray.size_extract]
    omega
  | succ fuel ih =>
    intro i prev out hle
    unfold expand.go
    dsimp only
    apply ih
    simp only [ByteArray.size_append, CryptWalker.Util.Bytes.size_ofVector]
    omega

theorem expand_size (ikm info : ByteArray) (len : Nat) :
    (expand ikm info len).size = len := by
  unfold expand
  split
  · simp_all
  · dsimp only
    apply go_size
    omega

/-- HKDF-SHA256-Expand-only, as a `KDF`. -/
def hkdfSha256Expand : CryptWalker.KDF.KDF where
  expand      := expand
  expand_size := expand_size

end CryptWalker.KDF.HKDF

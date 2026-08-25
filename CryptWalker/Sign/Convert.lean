/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Sign
import CryptWalker.NIKE.NIKE

namespace CryptWalker.Sign.Convert

open CryptWalker.Sign.Sign
open CryptWalker.NIKE.NIKE

/-! # Converting signature keys into NIKE keys

## On the name

This is deliberately not called `Elligator`. Elligator is a hash-to-curve / uniform-encoding
construction, and it appears nowhere in hpqc or katzenpost — a search for it returns nothing in
either repository. What actually exists is a one-directional birational map,
`PublicKey.ToECDH` at `hpqc/sign/ed25519/eddsa.go:224-231`, which pushes a compressed Edwards
point through `edwards25519.Point.BytesMontgomery()` into an X25519 public key. There is no
Montgomery-to-Edwards direction, and `ToECDH` is called from nowhere in the tree. So this
structure describes an Ed25519-to-X25519 *key conversion*, and a real instance will be that
birational map.

## Why both directions return `Option`

The map is partial in practice, and more importantly it must be allowed to fail so that
`convert_derive` below stays honest.

## The law does not survive blinding

`hpqc/sign/ed25519/blinded25519.go:23-27` states outright that the blinding scheme does *not*
preserve x25519 validity of the derived secret, because

    clamp(a) * clamp(f)  ≠  clamp(clamp(a) * clamp(f))

Do not add a field asserting that conversion commutes with `Blindable.blindPriv`. It is false.
`convert_derive` is a statement about a scheme's own keys only, and any use of a converted key
must therefore start from a root key rather than a blinded one.
-/

/-- A conversion from a signature scheme's keys into a NIKE's keys. -/
structure KeyConvert (S : Signature) (N : NIKE) where
  toNikePub  : S.PublicKey  → Option N.PublicKey
  toNikePriv : S.PrivateKey → Option N.PrivateKey

  /-- Conversion commutes with key derivation: converting the private key and then deriving
  the NIKE public key agrees with deriving the signature public key and then converting it.
  This is what makes a converted keypair usable — without it the two halves could convert to
  keys that have nothing to do with each other. -/
  convert_derive : ∀ sk nsk npk,
    toNikePriv sk = some nsk → toNikePub (S.pub sk) = some npk →
    N.derivePublicKey nsk = npk

variable {S : Signature} {N : NIKE}

/-- A converted public key whose private counterpart also converts is automatically in the
NIKE's safe subgroup, so it can be fed to the `Safe`-gated `groupAction` with no runtime
check. Follows from `convert_derive` and `NIKE.derive_safe`. -/
theorem converted_pub_safe (C : KeyConvert S N)
    (sk : S.PrivateKey) (nsk : N.PrivateKey) (npk : N.PublicKey)
    (h₁ : C.toNikePriv sk = some nsk) (h₂ : C.toNikePub (S.pub sk) = some npk) :
    N.Safe npk := by
  rw [← C.convert_derive sk nsk npk h₁ h₂]
  exact N.derive_safe nsk

/-- The stub conversion: nothing converts. Vacuously lawful — `convert_derive`'s hypotheses
are unsatisfiable — and the honest default for a signature/NIKE pair with no birational
relationship between their groups. Replace it with the real Edwards-to-Montgomery map once
Ed25519 exists. -/
def stub (S : Signature) (N : NIKE) : KeyConvert S N where
  toNikePub  := fun _ => none
  toNikePriv := fun _ => none
  convert_derive := by
    intro _ _ _ h
    simp at h

end CryptWalker.Sign.Convert

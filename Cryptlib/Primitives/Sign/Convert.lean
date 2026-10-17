/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.Sign.Sign
import Cryptlib.Primitives.NIKE.NIKE

namespace Cryptlib.Primitives.Sign.Convert

open Cryptlib.Primitives.Sign.Sign
open Cryptlib.Primitives.NIKE.NIKE

/-! # Converting signature keys into NIKE keys

Both directions return `Option`, since the conversion may be partial. Conversion does not commute
with `Blindable.blindPriv`, so `convert_derive` covers root keys only.
-/

/-- A conversion from a signature scheme's keys into a NIKE's keys. -/
structure KeyConvert (S : Signature) (N : NIKE) where
  toNikePub  : S.PublicKey  → Option N.PublicKey
  toNikePriv : S.PrivateKey → Option N.PrivateKey

  /-- Converting then deriving agrees with deriving then converting. -/
  convert_derive : ∀ sk nsk npk,
    toNikePriv sk = some nsk → toNikePub (S.pub sk) = some npk →
    N.derivePublicKey nsk = npk

variable {S : Signature} {N : NIKE}

/-- A converted public key whose private key also converts is `Safe`. -/
theorem converted_pub_safe (C : KeyConvert S N)
    (sk : S.PrivateKey) (nsk : N.PrivateKey) (npk : N.PublicKey)
    (h₁ : C.toNikePriv sk = some nsk) (h₂ : C.toNikePub (S.pub sk) = some npk) :
    N.Safe npk := by
  rw [← C.convert_derive sk nsk npk h₁ h₂]
  exact N.derive_safe nsk

/-- The stub conversion: nothing converts. Vacuously lawful. -/
def stub (S : Signature) (N : NIKE) : KeyConvert S N where
  toNikePub  := fun _ => none
  toNikePriv := fun _ => none
  convert_derive := by
    intro _ _ _ h
    simp at h

end Cryptlib.Primitives.Sign.Convert

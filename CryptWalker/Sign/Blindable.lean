/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Sign
import CryptWalker.Util.UniformHit

namespace CryptWalker.Sign.Blindable

set_option linter.dupNamespace false

open CryptWalker.Sign.Sign
open CryptWalker.Util.UniformHit (uniformHit_eq_of_injective)
open OracleComp OracleSpec ENNReal

/-! # Blindable signature schemes

A signature scheme whose keys can be blinded by a scalar, such that a signature made with a
blinded private key verifies under the correspondingly blinded public key. `PrivateKey` is the
scalar itself, so blinding is closed on one key type; seed expansion belongs to key generation.
-/

/-- Blinding laws hold for `Valid` public keys and `Invertible` factors only: a decodable point
with a small-order component breaks `g · (f · pk) = (f g) · pk`, and `f = 0` has no inverse. -/
structure Blindable where
  base : Signature

  /-- Blinding factors. -/
  Scalar : Type

  /-- Public keys on which blinding obeys the laws below. -/
  Valid : base.PublicKey → Prop
  /-- Blinding factors that can be undone. -/
  Invertible : Scalar → Prop
  /-- Keys whose blindings are pairwise distinct. Excludes the identity, which every factor fixes. -/
  Regular : base.PublicKey → Prop

  mul : Scalar → Scalar → Scalar
  /-- Inverse of a blinding factor. -/
  inv : Scalar → Scalar

  /-- Turn KDF output into a blinding factor. -/
  scalarOfBytes : ByteArray → Scalar

  blindPriv : base.PrivateKey → Scalar → base.PrivateKey
  blindPub  : base.PublicKey  → Scalar → base.PublicKey

  /-- Blinding the private key then deriving agrees with deriving then blinding the public key. -/
  blind_hom : ∀ sk f, base.pub (blindPriv sk f) = blindPub (base.pub sk) f

  /-- Every derived public key is valid. -/
  valid_pub : ∀ sk, Valid (base.pub sk)

  /-- Blinding a valid key gives a valid key. -/
  valid_blind : ∀ pk f, Valid pk → Valid (blindPub pk f)

  /-- Blinding twice is blinding by the product. -/
  blind_assoc : ∀ pk, Valid pk → ∀ f g, blindPub (blindPub pk f) g = blindPub pk (mul f g)

  /-- Blinding factors commute. -/
  blind_comm : ∀ f g, mul f g = mul g f

  /-- Unblinding inverts blinding. -/
  blind_inv : ∀ pk, Valid pk → ∀ f, Invertible f → blindPub (blindPub pk f) (inv f) = pk

  /-- Distinct blinding factors give distinct keys, for a regular key. -/
  blind_injective : ∀ pk, Regular pk → Function.Injective (blindPub pk)

variable (B : Blindable)

/-- A signature made with a blinded private key verifies under the blinded public key. -/
theorem verify_blinded (sk : B.base.PrivateKey) (f : B.Scalar)
    (m : ByteArray) (s : B.base.State) :
    B.base.verify (B.blindPub (B.base.pub sk) f) m (B.base.sign (B.blindPriv sk f) m s).1
      = true := by
  rw [← B.blind_hom]
  exact B.base.verify_sign _ _ _

/-- Blinding a private key twice derives the same public key as blinding once by the product. -/
theorem blindPriv_assoc (sk : B.base.PrivateKey) (f g : B.Scalar) :
    B.base.pub (B.blindPriv (B.blindPriv sk f) g) = B.base.pub (B.blindPriv sk (B.mul f g)) := by
  rw [B.blind_hom, B.blind_hom, B.blind_hom, B.blind_assoc _ (B.valid_pub sk)]

/-- Blinding and then unblinding a private key returns to the original public key. -/
theorem blindPriv_inv (sk : B.base.PrivateKey) (f : B.Scalar) (hf : B.Invertible f) :
    B.base.pub (B.blindPriv (B.blindPriv sk f) (B.inv f)) = B.base.pub sk := by
  rw [B.blind_hom, B.blind_hom, B.blind_inv _ (B.valid_pub sk) f hf]

/-- The order in which two blindings are applied is unobservable. -/
theorem blindPub_swap (pk : B.base.PublicKey) (hpk : B.Valid pk) (f g : B.Scalar) :
    B.blindPub (B.blindPub pk f) g = B.blindPub (B.blindPub pk g) f := by
  rw [B.blind_assoc pk hpk, B.blind_assoc pk hpk, B.blind_comm]

/-- For a regular key `pk`, a uniform blinding factor gives each key in the orbit of `pk` with
probability `1/|Scalar|`. -/
theorem blind_unlinkable [Fintype B.Scalar] [SampleableType B.Scalar]
    [DecidableEq B.base.PublicKey] (pk : B.base.PublicKey) (hpk : B.Regular pk)
    {target : B.base.PublicKey} (htarget : target ∈ Set.range (B.blindPub pk)) :
    Pr[= true | ($ᵗ B.Scalar) >>= fun f => pure (decide (B.blindPub pk f = target))] =
      (Fintype.card B.Scalar : ℝ≥0∞)⁻¹ :=
  uniformHit_eq_of_injective (B.blind_injective pk hpk) htarget

/-- The trivial blindable scheme, where every blinding is the identity. -/
instance : Inhabited Blindable := ⟨{
  base   := default
  Scalar := Unit
  Valid  := fun _ => True
  Invertible := fun _ => True
  Regular := fun _ => False

  mul := fun _ _ => ()
  inv := fun _ => ()
  scalarOfBytes := fun _ => ()

  blindPriv := fun sk _ => sk
  blindPub  := fun pk _ => pk

  blind_hom   := fun _ _ => rfl
  valid_pub   := fun _ => trivial
  valid_blind := fun _ _ _ => trivial
  blind_assoc := fun _ _ _ _ => rfl
  blind_comm  := fun _ _ => rfl
  blind_inv   := fun _ _ _ _ => rfl
  blind_injective := fun _ h => h.elim
}⟩

end CryptWalker.Sign.Blindable

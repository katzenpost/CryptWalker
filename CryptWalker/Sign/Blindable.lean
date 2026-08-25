/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Sign

namespace CryptWalker.Sign.Blindable

open CryptWalker.Sign.Sign

/-! # Blindable signature schemes

Models `hpqc/sign/ed25519/blinded25519.go`: a signature scheme whose keys can be blinded by a
scalar, such that a signature made with a blinded private key verifies under the
correspondingly blinded public key. This is what BACAP uses to turn one root keypair into an
unlinkable sequence of per-box keypairs.

## The private key type does not split

In Go there are two private key types. `PrivateKey` holds a *seed* and signs via RFC 8032,
deriving its scalar with SHA-512 on every signature; `BlindedPrivateKey` holds a bare *scalar*
and signs with a vendored algorithm (`blinded25519.go:138-189`). Consequently
`PrivateKey.Blind` changes the type (`blinded25519.go:194`) and blinding is closed only on the
blinded type.

We avoid that split by taking the scheme's `PrivateKey` to *be* the scalar, exactly as the
Echomix paper does — there the root secret is `S_R ∈ Z_ℓ` and the per-box secret is
`S_i^ctx = S_R × K_i^ctx mod ℓ`, with no seed anywhere. Seed expansion,
`clamp(SHA-512(seed))` at `blinded25519.go:196-197`, is then a property of a particular
instance's key generation rather than part of this abstraction. Blinding becomes closed on one
type and a single `sign` suffices.
-/

structure Blindable where
  base : Signature

  /-- Blinding factors. For Ed25519 this is `Z_ℓ`. -/
  Scalar : Type

  /-- Composition of blinding factors. -/
  mul : Scalar → Scalar → Scalar
  /-- Inverse of a blinding factor, for unblinding (`blinded25519.go:256-285`). -/
  inv : Scalar → Scalar

  /-- Turn KDF output into a scalar. For Ed25519 this is the SHA-512/256-then-clamp step at
  `blinded25519.go:214-216`, which is a *second* hash after whatever produced the bytes. -/
  scalarOfBytes : ByteArray → Scalar

  blindPriv : base.PrivateKey → Scalar → base.PrivateKey
  blindPub  : base.PublicKey  → Scalar → base.PublicKey

  /-- The homomorphism: blinding the private key and then deriving agrees with deriving and
  then blinding the public key. In Go the two sides are `(f · a) · G` and `f · (a · G)`
  (`blinded25519.go:237-246` versus `:320`), equal by associativity of scalar
  multiplication. Everything interesting below follows from this one field. -/
  blind_hom : ∀ sk f, base.pub (blindPriv sk f) = blindPub (base.pub sk) f

  /-- Blinding twice is blinding by the product. Tested in Go at
  `blinded25519_test.go:119-129`. -/
  blind_assoc : ∀ pk f g, blindPub (blindPub pk f) g = blindPub pk (mul f g)

  /-- Factors commute, so the order in which blindings are applied does not matter. Also
  tested at `blinded25519_test.go:119-129` (`f12 == f21`, `f123 == f213 == f321`). -/
  blind_comm : ∀ f g, mul f g = mul g f

  /-- Unblinding inverts blinding. Tested at `blinded25519_test.go:224-227`. -/
  blind_inv : ∀ pk f, blindPub (blindPub pk f) (inv f) = pk

variable (B : Blindable)

/-- **A signature made with a blinded private key verifies under the blinded public key.**

This is exactly the equation that `hpqc/bacap/BACAP.spthy:81-82` *assumes* as a rewrite rule:

    verify(sign(m, blindSk(sk, k)), m, blindPk(pk(sk), k)) = true

Here it is derived — from the single `blind_hom` field plus the base scheme's own
`verify_sign` law. Closing that assumption is the main reason to model BACAP in Lean rather
than only in Tamarin. -/
theorem verify_blinded (sk : B.base.PrivateKey) (f : B.Scalar)
    (m : ByteArray) (s : B.base.State) :
    B.base.verify (B.blindPub (B.base.pub sk) f) m (B.base.sign (B.blindPriv sk f) m s).1
      = true := by
  rw [← B.blind_hom]
  exact B.base.verify_sign _ _ _

/-- Blinding a private key twice agrees, observably, with blinding once by the product. The
two private keys need not be equal as terms — only the public keys they derive to, which is
all any verifier can see. -/
theorem blindPriv_assoc (sk : B.base.PrivateKey) (f g : B.Scalar) :
    B.base.pub (B.blindPriv (B.blindPriv sk f) g) = B.base.pub (B.blindPriv sk (B.mul f g)) := by
  rw [B.blind_hom, B.blind_hom, B.blind_hom, B.blind_assoc]

/-- Blinding and then unblinding a private key returns to the original public key. -/
theorem blindPriv_inv (sk : B.base.PrivateKey) (f : B.Scalar) :
    B.base.pub (B.blindPriv (B.blindPriv sk f) (B.inv f)) = B.base.pub sk := by
  rw [B.blind_hom, B.blind_hom, B.blind_inv]

/-- The order in which two blindings are applied is unobservable. -/
theorem blindPub_swap (pk : B.base.PublicKey) (f g : B.Scalar) :
    B.blindPub (B.blindPub pk f) g = B.blindPub (B.blindPub pk g) f := by
  rw [B.blind_assoc, B.blind_assoc, B.blind_comm]

/-- The trivial blindable scheme, over the trivial signature scheme: every blinding is the
identity. Present only to witness inhabitation. -/
instance : Inhabited Blindable := ⟨{
  base   := default
  Scalar := Unit

  mul := fun _ _ => ()
  inv := fun _ => ()
  scalarOfBytes := fun _ => ()

  blindPriv := fun sk _ => sk
  blindPub  := fun pk _ => pk

  blind_hom   := fun _ _ => rfl
  blind_assoc := fun _ _ _ => rfl
  blind_comm  := fun _ _ => rfl
  blind_inv   := fun _ _ => rfl
}⟩

end CryptWalker.Sign.Blindable

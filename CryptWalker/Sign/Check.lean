/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Schemes

namespace CryptWalker.Sign.Check

open CryptWalker.Sign.Sign
open CryptWalker.Sign.Blindable
open CryptWalker.Sign.Convert
open CryptWalker.Sign.Schemes

/-! # Elaboration and axiom audit

The `#print axioms` checks are pinned with `#guard_msgs`, so a change to the trusted surface fails
the build. The generic results use no axioms; the Ed25519 instances assume only
`X25519.p_prime` and `Ed25519Blinded.ell_prime`.
-/

/-- info: 'CryptWalker.Sign.Blindable.verify_blinded' does not depend on any axioms -/
#guard_msgs in
#print axioms CryptWalker.Sign.Blindable.verify_blinded

/-- info: 'CryptWalker.Sign.Blindable.blindPriv_assoc' does not depend on any axioms -/
#guard_msgs in
#print axioms CryptWalker.Sign.Blindable.blindPriv_assoc

/-- info: 'CryptWalker.Sign.Convert.converted_pub_safe' does not depend on any axioms -/
#guard_msgs in
#print axioms CryptWalker.Sign.Convert.converted_pub_safe

/--
info: 'CryptWalker.Sign.Schemes.ed25519Blindable' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 NIKE.X25519.p_prime,
 Ed25519Blinded.ell_prime]
-/
#guard_msgs in
#print axioms CryptWalker.Sign.Schemes.ed25519Blindable

/--
info: 'CryptWalker.Sign.Schemes.ed25519Hybrid' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 NIKE.X25519.p_prime,
 Ed25519Blinded.ell_prime]
-/
#guard_msgs in
#print axioms CryptWalker.Sign.Schemes.ed25519Hybrid

/-! ## Compositions that must elaborate -/

section

variable (sk : ed25519Blindable.base.PrivateKey) (f : ed25519Blindable.Scalar)
         (m : ByteArray) (s : ed25519Blindable.base.State)

/-- A signature made under a blinded key verifies against the blinded public key, at Ed25519. -/
example : ed25519Blindable.base.verify
            (ed25519Blindable.blindPub (ed25519Blindable.base.pub sk) f) m
            (ed25519Blindable.base.sign (ed25519Blindable.blindPriv sk f) m s).1 = true :=
  verify_blinded ed25519Blindable sk f m s

/-- Blinding twice agrees with blinding by the product, observably. -/
example : ed25519Blindable.base.pub
            (ed25519Blindable.blindPriv (ed25519Blindable.blindPriv sk f) f)
          = ed25519Blindable.base.pub
            (ed25519Blindable.blindPriv sk (ed25519Blindable.mul f f)) :=
  blindPriv_assoc ed25519Blindable sk f f

end

/-- The hybrid scheme's correctness law. -/
example (sk : ed25519Hybrid.PrivateKey) (m : ByteArray) (s : ed25519Hybrid.State) :
    ed25519Hybrid.verify (ed25519Hybrid.pub sk) m (ed25519Hybrid.sign sk m s).1 = true :=
  ed25519Hybrid.verify_sign sk m s

/-- A hybrid is itself a `Signature`, so it can be combined again. -/
noncomputable example : Signature :=
  Combiner.combineSign ed25519Hybrid ed25519Signature

/-- The stub key conversion is lawful for any signature scheme and NIKE. -/
example (S : Signature) (N : CryptWalker.NIKE.NIKE.NIKE) : KeyConvert S N := stub S N

end CryptWalker.Sign.Check

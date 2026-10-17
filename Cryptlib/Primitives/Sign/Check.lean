/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.Sign.Schemes

namespace Cryptlib.Primitives.Sign.Check

open Cryptlib.Primitives.Sign.Sign
open Cryptlib.Primitives.Sign.Blindable
open Cryptlib.Primitives.Sign.Convert
open Cryptlib.Primitives.Sign.Schemes

/-! # Elaboration and axiom audit

The `#print axioms` checks are pinned with `#guard_msgs`, so a change to the trusted surface fails
the build. The generic results use no axioms; the Ed25519 instances assume only
`X25519.p_prime` and `Ed25519Blinded.ell_prime`.
-/

/-- info: 'Cryptlib.Primitives.Sign.Blindable.verify_blinded' does not depend on any axioms -/
#guard_msgs in
#print axioms Cryptlib.Primitives.Sign.Blindable.verify_blinded

/-- info: 'Cryptlib.Primitives.Sign.Blindable.blindPriv_assoc' does not depend on any axioms -/
#guard_msgs in
#print axioms Cryptlib.Primitives.Sign.Blindable.blindPriv_assoc

/-- info: 'Cryptlib.Primitives.Sign.Convert.converted_pub_safe' does not depend on any axioms -/
#guard_msgs in
#print axioms Cryptlib.Primitives.Sign.Convert.converted_pub_safe

/--
info: 'Cryptlib.Primitives.Sign.Schemes.ed25519Blindable' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 NIKE.X25519.p_prime,
 Ed25519Blinded.ell_prime]
-/
#guard_msgs in
#print axioms Cryptlib.Primitives.Sign.Schemes.ed25519Blindable

/--
info: 'Cryptlib.Primitives.Sign.Schemes.ed25519Hybrid' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 NIKE.X25519.p_prime,
 Ed25519Blinded.ell_prime]
-/
#guard_msgs in
#print axioms Cryptlib.Primitives.Sign.Schemes.ed25519Hybrid

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
example (S : Signature) (N : Cryptlib.Primitives.NIKE.NIKE.NIKE) : KeyConvert S N := stub S N

end Cryptlib.Primitives.Sign.Check

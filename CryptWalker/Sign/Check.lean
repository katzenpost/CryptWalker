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

Deliberately *not* an executable. Every definition reachable from `Schemes` is `noncomputable`,
so there is nothing to run; what this module does instead is force the compositions to
elaborate and make the trusted surface visible.

The `#print axioms` lines below are the important part, and each is pinned with `#guard_msgs`
so that a change to the trusted surface fails the build rather than scrolling past in it. The
first three must show only standard kernel axioms: they are derived from `Blindable`'s fields
and must not depend on anything Ed25519-specific. The last two enumerate exactly what the
axiomatized instances assume, so the assumptions can be audited and struck off one by one as
real primitives arrive. When an axiom does go, delete it from the expected list here too.
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
info: 'CryptWalker.Sign.Schemes.ed25519Blindable' depends on axioms: [blindPubBytes,
 blindPub_assoc,
 blindPub_hom,
 blindPub_inv,
 invScalar,
 mulScalar,
 mulScalar_comm,
 pubOf,
 scalarFromSeed,
 scalarOfByteArray,
 signWith,
 verifyWith,
 verify_signWith]
-/
#guard_msgs in
#print axioms CryptWalker.Sign.Schemes.ed25519Blindable

/--
info: 'CryptWalker.Sign.Schemes.ed25519Hybrid' depends on axioms: [propext,
 Classical.choice,
 Quot.sound,
 pubOf,
 scalarFromSeed,
 signWith,
 verifyWith,
 verify_signWith]
-/
#guard_msgs in
#print axioms CryptWalker.Sign.Schemes.ed25519Hybrid

/-! ## Compositions that must elaborate -/

section

variable (sk : ed25519Blindable.base.PrivateKey) (f : ed25519Blindable.Scalar)
         (m : ByteArray) (s : ed25519Blindable.base.State)

/-- A signature made under a blinded key verifies against the blinded public key. This is the
statement `BACAP.spthy` assumes as a rewrite rule, instantiated at Ed25519. -/
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

/-- The hybrid scheme's own correctness law, which the combiner derived rather than assumed. -/
example (sk : ed25519Hybrid.PrivateKey) (m : ByteArray) (s : ed25519Hybrid.State) :
    ed25519Hybrid.verify (ed25519Hybrid.pub sk) m (ed25519Hybrid.sign sk m s).1 = true :=
  ed25519Hybrid.verify_sign sk m s

/-- Combining is closed: a hybrid is itself a `Signature`, so it can be combined again. -/
noncomputable example : Signature :=
  Combiner.combineSign ed25519Hybrid ed25519Signature

/-- The stub key conversion is lawful for any signature scheme and NIKE. -/
example (S : Signature) (N : CryptWalker.NIKE.NIKE.NIKE) : KeyConvert S N := stub S N

end CryptWalker.Sign.Check

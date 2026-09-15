/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.nike_sphinx_theorems
import CryptWalker.Sphinx.KEMSphinx
import CryptWalker.NIKE.Schemes
import CryptWalker.KEM.Schemes

namespace CryptWalker.Sphinx.Schemes

open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.NIKESphinx (NIKESphinxScheme nikeSphinxScheme)
open CryptWalker.Sphinx.KEMSphinx (KEMSphinxScheme kemSphinxScheme)

/-! # The Sphinx scheme registry

`NIKESphinx.nikeSphinxScheme`/`KEMSphinx.kemSphinxScheme` already build a concrete Sphinx scheme
for any name `CryptWalker.NIKE.byName`/`CryptWalker.KEM.byName` resolves — this file is the one
place that lists what those names currently are, the way `NIKE.Schemes`/`KEM.Schemes` list the
registered NIKEs/KEMs themselves, and the one place a caller who doesn't already know whether a
`Geometry` is NIKE- or KEM-flavored can get a scheme without picking which dispatcher to call.

Right now that list has exactly four entries, because it's built entirely from two registries
(`NIKE.Schemes.registry`, `KEM.Schemes.registry`) that each currently carry the same two X25519
implementations — the group formulation and the Montgomery ladder, agreeing byte-for-byte
(`CryptWalker.NIKE.test`'s `testX25519GroupAgreesWithLadder`) but genuinely different `NIKE`
values:

* NIKE-Sphinx over `"x25519"` (the group NIKE)
* NIKE-Sphinx over `"x25519-ladder"` (the ladder NIKE)
* KEM-Sphinx over `"x25519"` (the group NIKE, wrapped by `hpqc/kem/adapter`)
* KEM-Sphinx over `"x25519-ladder"` (the ladder NIKE, wrapped the same way)

Registering a fifth NIKE or KEM anywhere lengthens this list automatically — nothing here names
a scheme directly, so there is nothing to update.

A Sphinx *scheme* needs a `Geometry` (the header/payload byte layout for a given hop count and
message size), not just a crypto scheme, so this registry is a `List` of *names*, not of
ready-made scheme values: build a `Geometry` naming one of them (`Geometry.ofNIKE`/`ofKEM`) and
pass it to `sphinxScheme` below, or to `nikeSphinxScheme`/`kemSphinxScheme` directly if the kind
is already known. -/

/-- Every Sphinx scheme name currently constructible, NIKE-backed and KEM-backed together. -/
def schemeNames : List String :=
  (CryptWalker.NIKE.registry.map (·.hpqcName)) ++ (CryptWalker.KEM.registry.map (·.hpqcName))

/-- Build the Sphinx scheme a `Geometry` names: `NIKESphinxScheme` for a NIKE geometry
(`Geometry.scheme = .inl _`), `KEMSphinxScheme` for a KEM one (`.inr _`) — whichever of
`nikeSphinxScheme`/`kemSphinxScheme` actually applies, so a caller holding a `Geometry` of
unknown kind doesn't have to guess which one to call.

`noncomputable`, like `nikeSphinxScheme` itself: resolving a NIKE *by name at runtime* needs a
`Fintype`/`SampleableType` instance for its `PrivateKey` that only classical choice can supply
(see `NIKESphinx.nikeSphinxSchemeOf`'s doc comment). Executable code that only needs
`wrap`/`unwrap`/`newSURB`/`newPacketFromSURB` for a *statically known* NIKE should go through
`NIKESphinx.nikeSphinxCore` instead, as the self-tests and vector generators do. -/
noncomputable def sphinxScheme (geom : Geometry) : Except String (NIKESphinxScheme ⊕ KEMSphinxScheme) :=
  match geom.scheme with
  | .inl _ => (nikeSphinxScheme geom).map Sum.inl
  | .inr _ => (kemSphinxScheme geom).map Sum.inr

end CryptWalker.Sphinx.Schemes

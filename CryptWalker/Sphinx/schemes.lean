/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.geometry
import CryptWalker.Sphinx.nike_sphinx_theorems
import CryptWalker.Sphinx.kem_sphinx_theorems
import CryptWalker.NIKE.Schemes
import CryptWalker.KEM.Schemes

namespace CryptWalker.Sphinx.Schemes

open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.NIKESphinx (NIKESphinxScheme nikeSphinxScheme)
open CryptWalker.Sphinx.KEMSphinx (KEMSphinxScheme kemSphinxScheme)

/-! # The Sphinx scheme registry

`nikeSphinxScheme`/`kemSphinxScheme` already build a concrete Sphinx scheme for any name
`CryptWalker.NIKE.byName`/`CryptWalker.KEM.byName` resolves — this file lists what those names
currently are (built from `NIKE.Schemes.registry`/`KEM.Schemes.registry`, so registering a new
NIKE or KEM anywhere lengthens it automatically), and lets a caller holding a `Geometry` of
unknown kind get a scheme without picking which dispatcher to call.

A Sphinx *scheme* needs a `Geometry`, not just a crypto scheme, so this registry is a `List` of
names: build a `Geometry` naming one (`Geometry.ofNIKE`/`ofKEM`) and pass it to `sphinxScheme`
below, or to `nikeSphinxScheme`/`kemSphinxScheme` directly if the kind is already known. -/

/-- Every Sphinx scheme name currently constructible, NIKE-backed and KEM-backed together. -/
def schemeNames : List String :=
  (CryptWalker.NIKE.registry.map (·.hpqcName)) ++ (CryptWalker.KEM.registry.map (·.hpqcName))

/-- Build the Sphinx scheme a `Geometry` names: `NIKESphinxScheme` for `.inl _`, `KEMSphinxScheme`
for `.inr _`. `noncomputable`, like `nikeSphinxScheme` itself, since resolving a NIKE by name at
runtime needs classical choice. Code that already knows which NIKE it wants should go through
`nikeSphinxCore` instead, as the self-tests and vector generators do. -/
noncomputable def sphinxScheme (geom : Geometry) : Except String (NIKESphinxScheme ⊕ KEMSphinxScheme) :=
  match geom.scheme with
  | .inl _ => (nikeSphinxScheme geom).map Sum.inl
  | .inr _ => (kemSphinxScheme geom).map Sum.inr

end CryptWalker.Sphinx.Schemes

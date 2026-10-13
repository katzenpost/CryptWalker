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

/-! # Sphinx scheme registry -/

/-- Every Sphinx scheme name currently constructible, NIKE-backed and KEM-backed together. -/
def schemeNames : List String :=
  (CryptWalker.NIKE.registry.map (·.hpqcName)) ++ (CryptWalker.KEM.registry.map (·.name))

/-- The Sphinx scheme a `Geometry` names. -/
noncomputable def sphinxScheme (geom : Geometry) : Except String (NIKESphinxScheme ⊕ KEMSphinxScheme) :=
  match geom.scheme with
  | .inl _ => (nikeSphinxScheme geom).map Sum.inl
  | .inr _ => (kemSphinxScheme geom).map Sum.inr

end CryptWalker.Sphinx.Schemes

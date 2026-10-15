/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Protocols.Sphinx.geometry
import CryptWalker.Protocols.Sphinx.nike_sphinx_theorems
import CryptWalker.Protocols.Sphinx.kem_sphinx_theorems
import CryptWalker.NIKE.Schemes
import CryptWalker.KEM.Schemes

namespace CryptWalker.Protocols.Sphinx.Schemes

open CryptWalker.Protocols.Sphinx.Geometry (Geometry)
open CryptWalker.Protocols.Sphinx.NIKESphinx (NIKESphinxScheme nikeSphinxScheme)
open CryptWalker.Protocols.Sphinx.KEMSphinx (KEMSphinxScheme kemSphinxScheme)

/-! # Sphinx scheme registry -/

/-- Every Sphinx scheme name currently constructible, NIKE-backed and KEM-backed together. -/
def schemeNames : List String :=
  (CryptWalker.NIKE.registry.map (·.hpqcName)) ++ (CryptWalker.KEM.registry.map (·.name))

/-- The Sphinx scheme a `Geometry` names. -/
noncomputable def sphinxScheme (geom : Geometry) : Except String (NIKESphinxScheme ⊕ KEMSphinxScheme) :=
  if geom.nikeName.isEmpty then (kemSphinxScheme geom).map Sum.inr
  else (nikeSphinxScheme geom).map Sum.inl

end CryptWalker.Protocols.Sphinx.Schemes

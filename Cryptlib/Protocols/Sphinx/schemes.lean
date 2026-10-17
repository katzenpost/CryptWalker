/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Protocols.Sphinx.geometry
import Cryptlib.Protocols.Sphinx.nike_sphinx_theorems
import Cryptlib.Protocols.Sphinx.kem_sphinx_theorems
import Cryptlib.Primitives.NIKE.Schemes
import Cryptlib.Primitives.KEM.Schemes

namespace Cryptlib.Protocols.Sphinx.Schemes

open Cryptlib.Protocols.Sphinx.Geometry (Geometry)
open Cryptlib.Protocols.Sphinx.NIKESphinx (NIKESphinxScheme nikeSphinxScheme)
open Cryptlib.Protocols.Sphinx.KEMSphinx (KEMSphinxScheme kemSphinxScheme)

/-! # Sphinx scheme registry -/

/-- Every Sphinx scheme name currently constructible, NIKE-backed and KEM-backed together. -/
def schemeNames : List String :=
  (Cryptlib.Primitives.NIKE.registry.map (·.hpqcName)) ++ (Cryptlib.Primitives.KEM.registry.map (·.name))

/-- The Sphinx scheme a `Geometry` names. -/
noncomputable def sphinxScheme (geom : Geometry) : Except String (NIKESphinxScheme ⊕ KEMSphinxScheme) :=
  if geom.nikeName.isEmpty then (kemSphinxScheme geom).map Sum.inr
  else (nikeSphinxScheme geom).map Sum.inl

end Cryptlib.Protocols.Sphinx.Schemes

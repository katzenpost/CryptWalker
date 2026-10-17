/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.NIKE.Schemes
import Cryptlib.Primitives.KEM.Schemes

namespace Cryptlib.Protocols.Sphinx.BenchRegistry

open Cryptlib.Primitives.NIKE.NIKE (NIKE)
open Cryptlib.Primitives.KEM.KEM (KEM)

/-! # Sphinx benchmark cases

Every registered NIKE and KEM at several payload sizes and hop counts. -/

/-- The scheme a bench case runs, with its registry name. -/
inductive SchemeKind where
  | nike (name : String) (nike : NIKE)
  | kem (name : String) (kem : KEM)

/-- One benchmark configuration: a forward packet, no SURB. -/
structure BenchCase where
  kind : SchemeKind
  payloadSize : Nat
  nrHops : Nat := 5

/-- A display label: scheme name, payload size, hop count. -/
def BenchCase.name (c : BenchCase) : String :=
  let schemeName := match c.kind with
    | .nike n _ => n
    | .kem n _ => n
  s!"{schemeName} ({c.payloadSize}B, {c.nrHops} hops)"

/-- Every registered NIKE and KEM, at three payload sizes and 5 hops. -/
def sphinxBenchCases : List BenchCase :=
  let payloadSizes := [1000, 2000, 10000]
  let nikeCases := Cryptlib.Primitives.NIKE.registry.flatMap fun e =>
    payloadSizes.map fun sz => { kind := .nike e.hpqcName e.scheme, payloadSize := sz }
  let kemCases := Cryptlib.Primitives.KEM.registry.flatMap fun e =>
    payloadSizes.map fun sz => { kind := .kem e.name e.scheme, payloadSize := sz }
  nikeCases ++ kemCases

end Cryptlib.Protocols.Sphinx.BenchRegistry

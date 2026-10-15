/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.NIKE.Schemes
import CryptWalker.KEM.Schemes

namespace CryptWalker.Protocols.Sphinx.BenchRegistry

open CryptWalker.NIKE.NIKE (NIKE)
open CryptWalker.KEM.KEM (KEM)

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
  let nikeCases := CryptWalker.NIKE.registry.flatMap fun e =>
    payloadSizes.map fun sz => { kind := .nike e.hpqcName e.scheme, payloadSize := sz }
  let kemCases := CryptWalker.KEM.registry.flatMap fun e =>
    payloadSizes.map fun sz => { kind := .kem e.name e.scheme, payloadSize := sz }
  nikeCases ++ kemCases

end CryptWalker.Protocols.Sphinx.BenchRegistry

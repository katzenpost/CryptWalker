/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.NIKE.Schemes
import CryptWalker.KEM.Schemes

namespace CryptWalker.Sphinx.BenchRegistry

open CryptWalker.NIKE.NIKE (NIKE)
open CryptWalker.KEM.KEM (KEM)

/-! # The Sphinx benchmark-case registry

Distinct from `Sphinx.Schemes` (which registry name resolves to which crypto scheme) — this is
which scheme × payload size × hop count `benchmark.lean` actually times, mirroring the *shape* of
katzenpost's own `benchmarks []struct{...}` table in `sphinx_benchmark_test.go`, not its content
(that table spans ~19 schemes across NIKE/KEM/hybrid/PQ; this project only ever ported X25519, so
every entry here is one of `NIKE.registry`/`KEM.registry`'s two entries each). Built directly from
those two registries rather than hardcoding scheme values a second time, so a future NIKE/KEM
addition lengthens this automatically — the same principle `Sphinx.Schemes.schemeNames` already
follows. -/

/-- Which family of Sphinx a bench case exercises, carrying both the concrete scheme value (to
run) and its registry name (to build a `Geometry` against `Geometry.ofNIKE`/`ofKEM`). -/
inductive SchemeKind where
  | nike (name : String) (nike : NIKE)
  | kem (name : String) (kem : KEM)

/-- One benchmark configuration. `withSURB` isn't a field — every case here is a plain forward
packet, matching katzenpost's own benchmark table (its `isSURB` knob exists only for
`bench_utils_test.go`'s path-vector shape, never set to `true` in `sphinx_benchmark_test.go`'s
actual cases). -/
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

/-- Every Sphinx bench case this project runs: every `NIKE.registry` and `KEM.registry` scheme,
each at 3 payload sizes, all at 5 hops. The
2000-byte cases match katzenpost's own `sphinx_benchmark_test.go` table exactly (same payload
size, same hop count), so they're directly comparable to its published numbers. -/
def sphinxBenchCases : List BenchCase :=
  let payloadSizes := [1000, 2000, 10000]
  let nikeCases := CryptWalker.NIKE.registry.flatMap fun e =>
    payloadSizes.map fun sz => { kind := .nike e.hpqcName e.scheme, payloadSize := sz }
  let kemCases := CryptWalker.KEM.registry.flatMap fun e =>
    payloadSizes.map fun sz => { kind := .kem e.hpqcName e.scheme, payloadSize := sz }
  nikeCases ++ kemCases

end CryptWalker.Sphinx.BenchRegistry

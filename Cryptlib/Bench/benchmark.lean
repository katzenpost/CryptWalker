/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Bench.NIKE
import Cryptlib.Bench.KEM
import Cryptlib.Bench.Sphinx
import Cryptlib.Bench.MLKEMSteps
import Cryptlib.Bench.Field25519
import Cryptlib.Bench.Cipher
import Cryptlib.Bench.KDF

/-! # Benchmark driver for all registered schemes and suites -/

def main (args : List String) : IO UInt32 := do
  for e in Cryptlib.Primitives.NIKE.registry do
    (← Cryptlib.Bench.NIKE.benches e.hpqcName e.scheme).forM LeanBench.register
  for e in Cryptlib.Primitives.KEM.registry do
    (← Cryptlib.Bench.KEM.benches e.name e.scheme).forM LeanBench.register
  (← Cryptlib.Bench.Sphinx.benches).forM LeanBench.register
  (← Cryptlib.Bench.MLKEMSteps.benches).forM LeanBench.register
  (← Cryptlib.Bench.Field25519.benches).forM LeanBench.register
  (← Cryptlib.Bench.Cipher.benches).forM LeanBench.register
  (← Cryptlib.Bench.KDF.benches).forM LeanBench.register
  LeanBench.runMain args

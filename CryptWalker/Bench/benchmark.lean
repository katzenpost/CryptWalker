/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Bench.NIKE
import CryptWalker.Bench.KEM
import CryptWalker.Bench.Sphinx

/-! # The benchmark driver: every registered NIKE, KEM and Sphinx scheme, via LeanBench -/

def main (args : List String) : IO UInt32 := do
  for e in CryptWalker.NIKE.registry do
    (← CryptWalker.Bench.NIKE.benches e.hpqcName e.scheme).forM LeanBench.register
  for e in CryptWalker.KEM.registry do
    (← CryptWalker.Bench.KEM.benches e.hpqcName e.scheme).forM LeanBench.register
  (← CryptWalker.Bench.Sphinx.benches).forM LeanBench.register
  LeanBench.runMain args

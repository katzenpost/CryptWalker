/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.KDF.Argon2
import LeanBench

/-! # Argon2id benchmarks at growing memory sizes

Inputs are read from refs so the compiler cannot hoist the work out of the timed action. -/

namespace Cryptlib.Bench.KDF

open Cryptlib.Primitives.KDF.Argon2

private def cfg : LeanBench.BenchConfig := { suite := some "kdf", samples := 3, warmup := 0 }

def sizes : List (Nat × String) := [(1024, "1MiB"), (16384, "16MiB"), (65536, "64MiB")]

def benches : IO (Array LeanBench.Bench) := do
  let pw ← IO.mkRef "correct horse battery staple".toUTF8
  let salt ← IO.mkRef (ByteArray.mk (Array.replicate 16 7))
  let out ← IO.mkRef ByteArray.empty
  let mut bs := #[]
  for (m, label) in sizes do
    bs := bs.push { name := s!"argon2id {label} t=3", config := cfg,
                    action := do
                      out.set ((hash { memoryKiB := m, passes := 3 } (← pw.get) (← salt.get)).toOption.getD .empty) }
  pure bs

end Cryptlib.Bench.KDF

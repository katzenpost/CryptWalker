/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.NIKE.X25519_montgomery_ladder
import LeanBench

/-! # Field arithmetic modulo `2^255 - 19` and the two X25519 ladders

Inputs are read from refs so the compiler cannot hoist the work out of the timed action. -/

namespace Cryptlib.Bench.Field25519

open Cryptlib.Primitives.NIKE.Field25519 (Fe)
open Cryptlib.Primitives.NIKE.X25519_montgomery_ladder (curve25519 curve25519_fe basepointBytes)

private def cfg : LeanBench.BenchConfig := { suite := some "field25519", samples := 100, warmup := 2 }

def benches : IO (Array LeanBench.Bench) := do
  let a ← IO.mkRef (Fe.ofNat (2 ^ 254 + 12345))
  let b ← IO.mkRef (Fe.ofNat (2 ^ 200 + 6789))
  let fe ← IO.mkRef Fe.zero
  let scalar ← IO.mkRef (Vector.replicate 32 (7 : UInt8))
  let base ← IO.mkRef basepointBytes
  let out ← IO.mkRef (Vector.replicate 32 (0 : UInt8))
  pure #[
    { name := "fe mul", config := cfg, action := do fe.set ((← a.get).mul (← b.get)) },
    { name := "fe sq", config := cfg, action := do fe.set (← a.get).sq },
    { name := "fe invert", config := cfg, action := do fe.set (← a.get).invert },
    { name := "x25519 ladder (Fe limbs)", config := cfg,
      action := do out.set (curve25519_fe (← scalar.get) (← base.get)) },
    { name := "x25519 ladder (ZMod)", config := cfg,
      action := do out.set (curve25519 (← scalar.get) (← base.get)) }]

end Cryptlib.Bench.Field25519

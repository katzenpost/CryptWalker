/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.NIKE.Schemes
import LeanBench

/-! # NIKE benchmarks, generic over any `NIKE`

A fresh private key is drawn before each sample, outside the timed region. -/

namespace CryptWalker.Bench.NIKE

open CryptWalker.NIKE.NIKE (NIKE)
open CryptWalker.Util.Bytes (ofVector)

private def randomSeed : IO (Vector UInt8 32) := do
  let bs ← IO.getRandomBytes 32
  pure (Vector.ofFn fun i : Fin 32 => bs[i.val]!)

private def cfg : LeanBench.BenchConfig := { suite := some "nike", samples := 100, warmup := 2 }

def benches (name : String) (nike : NIKE) : IO (Array LeanBench.Bench) := do
  let sk ← IO.mkRef (nike.privateKeyFromSeed (← randomSeed))
  let peer ← IO.mkRef (nike.privateKeyFromSeed (← randomSeed))
  let out ← IO.mkRef ByteArray.empty
  let fresh := some do sk.set (nike.privateKeyFromSeed (← randomSeed))
  pure #[
    { name := s!"nike {name} derivePublicKey", config := cfg, beforeEach? := fresh
      action := do out.set (ofVector (nike.encodePublicKey (nike.derivePublicKey (← sk.get)))) },
    { name := s!"nike {name} groupAction", config := cfg, beforeEach? := fresh
      action := do
        let p ← peer.get
        let ss := nike.groupAction (← sk.get) ⟨nike.derivePublicKey p, nike.derive_safe p⟩
        out.set (ofVector (nike.encodeSharedSecret ss)) }]

end CryptWalker.Bench.NIKE

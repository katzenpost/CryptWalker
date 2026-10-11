/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Cipher.ChaChaPoly
import LeanBench

/-! # ChaCha20 and Poly1305 benchmarks at growing message sizes

Inputs are read from refs so the compiler cannot hoist the work out of the timed action. -/

namespace CryptWalker.Bench.Cipher

open CryptWalker.Cipher.ChaChaPoly (chacha20 poly1305)
open CryptWalker.Util.Bytes (ofVector)

private def cfg : LeanBench.BenchConfig := { suite := some "cipher", samples := 10, warmup := 1 }

def sizes : List (Nat × String) := [(1024, "1KiB"), (4096, "4KiB"), (16384, "16KiB"), (65536, "64KiB")]

def benches : IO (Array LeanBench.Bench) := do
  let key ← IO.mkRef (Vector.replicate 32 (1 : UInt8))
  let nonce ← IO.mkRef (Vector.replicate 12 (0 : UInt8))
  let out ← IO.mkRef ByteArray.empty
  let mut bs := #[]
  for (size, label) in sizes do
    let msg ← IO.mkRef (ByteArray.mk (Array.ofFn fun (i : Fin size) => (i.val * 7 % 251).toUInt8))
    bs := bs.push { name := s!"chacha20 {label}", config := cfg,
                    action := do out.set (chacha20 (← key.get) (← nonce.get) (← msg.get)) }
    bs := bs.push { name := s!"poly1305 {label}", config := cfg,
                    action := do out.set (ofVector (poly1305 (← key.get) (← msg.get))) }
  pure bs

end CryptWalker.Bench.Cipher

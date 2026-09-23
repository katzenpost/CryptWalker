/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.KEM.Schemes
import LeanBench

/-! # KEM benchmarks, generic over any `KEM`

Each sample runs from a freshly seeded state; `decap` gets a fresh ciphertext per sample. Keys and
ciphertexts are prepared outside the timed region. -/

namespace CryptWalker.Bench.KEM

open CryptWalker.KEM.KEM (KEM)
open CryptWalker.Util.Bytes (ofVector)

private def randomSeed : IO (Vector UInt8 32) := do
  let bs ← IO.getRandomBytes 32
  pure (Vector.ofFn fun i : Fin 32 => bs[i.val]!)

private def cfg : LeanBench.BenchConfig := { suite := some "kem", samples := 20, warmup := 2 }

def benches (name : String) (kem : KEM) : IO (Array LeanBench.Bench) := do
  let fail {α} (op : String) : IO α := throw (IO.userError s!"kem {name}: {op} failed")
  let st ← IO.mkRef (kem.stateFromSeed (← randomSeed))
  let keys ← IO.mkRef (none : Option (kem.PublicKey × kem.PrivateKey))
  let ct ← IO.mkRef (none : Option kem.Ciphertext)
  let out ← IO.mkRef ByteArray.empty
  let fresh : IO Unit := do st.set (kem.stateFromSeed (← randomSeed))
  let getKeys : IO (kem.PublicKey × kem.PrivateKey) := do
    let some k ← keys.get | fail "keys"
    pure k
  let setup := some do
    match kem.generate (kem.stateFromSeed (← randomSeed)) with
    | .ok ⟨pk, sk, _⟩ _ => keys.set (some (pk, sk))
    | .error _ _ => fail "generate"
  pure #[
    { name := s!"kem {name} generate", config := cfg, beforeEach? := some fresh
      action := do
        match kem.generate (← st.get) with
        | .ok ⟨pk, _, _⟩ _ => out.set (ofVector (kem.encodePublicKey pk))
        | .error _ _ => fail "generate" },
    { name := s!"kem {name} encap", config := cfg, setup? := setup, beforeEach? := some fresh
      action := do
        match kem.encap (← getKeys).1 (← st.get) with
        | .ok (c, _) _ => out.set (ofVector (kem.encodeCiphertext c))
        | .error _ _ => fail "encap" },
    { name := s!"kem {name} decap", config := cfg, setup? := setup
      beforeEach? := some do
        fresh
        match kem.encap (← getKeys).1 (← st.get) with
        | .ok (c, _) _ => ct.set (some c)
        | .error _ _ => fail "encap"
      action := do
        let some c ← ct.get | fail "ciphertext"
        match kem.decap (← getKeys).2 c (← st.get) with
        | .ok k _ => out.set (ofVector (kem.encodePlaintext k))
        | .error _ _ => fail "decap" }]

end CryptWalker.Bench.KEM

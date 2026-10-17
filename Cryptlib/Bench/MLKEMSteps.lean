/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.KEM.MLKEM.MLKEM
import LeanBench

/-! # ML-KEM-768 encapsulation, one step at a time

Each bench is one step of `FIPS203.encaps`. Inputs are computed once from a real key pair and read
from a ref so the compiler cannot hoist the work out of the timed action. -/

namespace Cryptlib.Bench.MLKEMSteps

open MLKEM
open Cryptlib.Primitives.KEM.FIPS203
open Cryptlib.Util.Bytes (ofVector)

private def cfg : LeanBench.BenchConfig := { suite := some "mlkem-steps", samples := 10, warmup := 1 }

private def ps : ParameterSet := .MLKEM768

/-- A bench that applies `f` to the value in `input`. -/
private def step {α β} (name : String) (input : α) (f : α → β) : IO LeanBench.Bench := do
  let inp ← IO.mkRef input
  let out ← IO.mkRef (none : Option β)
  return { name := s!"mlkem768 {name}", config := cfg, action := do out.set (some (f (← inp.get))) }

def benches : IO (Array LeanBench.Bench) := do
  let enc := encoding ps
  let prims := primitives ps
  let d : Seed32 := Vector.replicate 32 1
  let z : Seed32 := Vector.replicate 32 2
  let m : Message := Vector.replicate 32 3
  let (ek, _) := keygen ps d z
  let ekHash := prims.hEncapsulationKey ek.tHatEncoded ek.rho
  let (_, coins) := prims.gEncaps m ekHash
  let tHat := enc.byteDecode12Vec ek.tHatEncoded
  let aHat := prims.publicMatrix ek.rho
  let y := prims.sampleVecEta1 coins 0
  let yHat := ring.nttVec y
  let e1 := prims.sampleVecEta2 coins (params ps).k
  let u := ring.invNTTVec (ring.matTransposeVecMul aHat yHat) + e1
  let v := ring.invNTT (ring.dot tHat yHat)
  return #[
    ← step "encaps (whole)" (ek, m) fun (ek, m) => encaps ps ek m,
    ← step "KPKE.encrypt (whole)" (ek, m, coins) fun (ek, m, r) => KPKE.encrypt ring enc prims ek m r,
    ← step "H(ek)" ek fun ek => prims.hEncapsulationKey ek.tHatEncoded ek.rho,
    ← step "G(m, H(ek))" (m, ekHash) fun (m, h) => prims.gEncaps m h,
    ← step "byteDecode12Vec t̂" ek fun ek => enc.byteDecode12Vec ek.tHatEncoded,
    ← step "publicMatrix (9 sampleNTT)" ek fun ek => prims.publicMatrix ek.rho,
    ← step "sampleNTT (one)" ek fun ek => concreteSampleNTT ek.rho 0 0,
    ← step "sampleVecEta1" coins fun r => prims.sampleVecEta1 r 0,
    ← step "sampleVecEta2" coins fun r => prims.sampleVecEta2 r (params ps).k,
    ← step "prfEta2 (one)" coins fun r => prims.prfEta2 r (2 * (params ps).k),
    ← step "nttVec" y fun y => ring.nttVec y,
    ← step "matTransposeVecMul" (aHat, yHat) fun (a, y) => ring.matTransposeVecMul a y,
    ← step "invNTTVec" (aHat, yHat) fun (a, y) => ring.invNTTVec (ring.matTransposeVecMul a y),
    ← step "dot" (tHat, yHat) fun (t, y) => ring.dot t y,
    ← step "invNTT (one)" (tHat, yHat) fun (t, y) => ring.invNTT (ring.dot t y),
    ← step "decompress1 ∘ byteDecode1" m fun m => enc.decompress1 (enc.byteDecode1 m),
    ← step "compressDU" u fun u => enc.compressDU u,
    ← step "byteEncodeDUVec ∘ compressDU" u fun u => enc.byteEncodeDUVec (enc.compressDU u),
    ← step "compressDV" v fun v => enc.compressDV v,
    ← step "byteEncodeDV ∘ compressDV" v fun v => enc.byteEncodeDV (enc.compressDV v)]

end Cryptlib.Bench.MLKEMSteps

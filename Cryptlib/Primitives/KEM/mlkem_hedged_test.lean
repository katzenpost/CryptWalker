/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import Cryptlib.Primitives.KEM.MLKEMHedged.MLKEMHedged512
import Cryptlib.Primitives.KEM.MLKEMHedged.MLKEMHedged768
import Cryptlib.Primitives.KEM.MLKEMHedged.MLKEMHedged1024
import Cryptlib.Util.newhex

/-! # Hedged ML-KEM: known-answer tests shared with hpqc

`testdata/mlkem768_hedged.json` comes from hpqc's Go implementation, and
`testdata/lean_mlkem{512,768,1024}_hedged_vectors.json` from `gen_mlkem_hedged_vectors.lean`; hpqc's
Rust implementation checks all of them too. These vectors start from the unhashed `m`, so they also
cover the pre-hash. -/

open Lean
open MLKEM
open Cryptlib.Primitives.KEM.FIPS203 (hashH uBytes vBytes)
open Cryptlib.Primitives.KEM.MLKEMHedged
open Cryptlib.Util.newhex
open Cryptlib.Util.Bytes (ofVector toVecN)

def field (j : Json) (k : String) : Except String ByteArray := do
  let s ← (← j.getObjVal? k).getStr?
  match hexStringToByteArray s with
  | some b => pure b
  | none   => throw s!"field {k}: not valid hex: {s}"

def hexOfB (b : ByteArray) : String := byteArrayToHex b

def check (label : String) (want got : ByteArray) : IO Bool := do
  if hexOfB want == hexOfB got then
    IO.println s!"    ok   {label}"
    pure true
  else
    IO.println s!"    FAIL {label}"
    IO.println s!"           want {hexOfB want}"
    IO.println s!"           got  {hexOfB got}"
    pure false

def runVec (ps : ParameterSet) (j : Json) : IO Bool := do
  match (do
    let name ← (← j.getObjVal? "name").getStr?
    pure (name, ← field j "d_hex", ← field j "z_hex", ← field j "m_hex", ← field j "m_hash_hex",
      ← field j "encapsulation_key_hex", ← field j "ciphertext_hex", ← field j "shared_secret_hex")
      : Except String _) with
  | .error e => do IO.eprintln e; pure false
  | .ok (name, d, z, m, wantMh, wantEk, wantCt, wantSs) =>
    IO.println s!"  {name}"
    let K := kemSeed ps
    let sk := (toVecN 32 d, toVecN 32 z)
    let pk := K.derivePublicKey sk
    let mv := toVecN 32 m
    let mut ok ← check "encapsulation key" wantEk (ofVector (K.encodePublicKey pk))
    ok := (← check "H(m)" wantMh (ofVector (hashH (ofVector mv)))) && ok
    let (ss, ct) := encapsHedged ps (show Cryptlib.Primitives.KEM.FIPS203.PublicKey ps from pk).1 mv
    let ctBytes := uBytes ps ct.uEncoded ++ vBytes ps ct.vEncoded
    ok := (← check "ciphertext" wantCt ctBytes) && ok
    ok := (← check "encap shared secret" wantSs (ofVector ss)) && ok
    match K.decodeCiphertext (toVecN _ wantCt) with
    | none => IO.println "    FAIL ciphertext decode"; pure false
    | some c =>
      match K.decap sk c K.stateI.default with
      | .ok k _ => pure ((← check "decap shared secret" wantSs (ofVector (K.encodePlaintext k))) && ok)
      | .error _ _ => IO.println "    FAIL decap"; pure false

def runFile (ps : ParameterSet) (size path : String) : IO (Option Nat) := do
  let raw ← IO.FS.readFile path
  match (do
    let j ← Json.parse raw
    let prim ← (← j.getObjVal? "primitive").getStr?
    if prim ≠ s!"mlkem{size}_hedged" then throw s!"unexpected primitive: {prim}"
    (← j.getObjVal? "vectors").getArr? : Except String _) with
  | .error e => IO.eprintln s!"failed to parse {path}: {e}"; pure none
  | .ok vs =>
    IO.println s!"Hedged ML-KEM-{size} vectors ({vs.size} from {path})"
    let mut ok := !vs.isEmpty
    for v in vs do
      ok := (← runVec ps v) && ok
    IO.println ""
    pure (if ok then some vs.size else none)

def main : IO UInt32 := do
  let files := [
    (ParameterSet.MLKEM768, "768", "testdata/mlkem768_hedged.json"),
    (.MLKEM512, "512", "testdata/lean_mlkem512_hedged_vectors.json"),
    (.MLKEM768, "768", "testdata/lean_mlkem768_hedged_vectors.json"),
    (.MLKEM1024, "1024", "testdata/lean_mlkem1024_hedged_vectors.json")]
  let mut total := 0
  for (ps, size, path) in files do
    match ← runFile ps size path with
    | some n => total := total + n
    | none => IO.eprintln s!"FAILED: {path}"; return 1
  IO.println s!"all checks passed ({total} vectors)"
  pure 0

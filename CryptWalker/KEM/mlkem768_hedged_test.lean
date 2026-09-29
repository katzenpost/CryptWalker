/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.KEM.MLKEMHedged.MLKEMHedged768
import CryptWalker.Util.newhex

/-! # Hedged ML-KEM-768: known-answer tests, against `hpqc`

Checks `kemMLKEMHedged768Seed` and `encaps768Hedged` against vectors vendored from hpqc
(`testdata/mlkem768_hedged.json`, hpqc's `"MLKEMHedged768"`). Unlike the NIST ACVP suite
(`MLKEMHedged/mlkemhedged768_test.lean`), these vectors start from the unhashed `m`, so they cover
the pre-hash too: for each vector, keygen from `d`,`z`, then `H(m)`, then hedged encapsulation of `m`,
then decapsulation back to the shared secret. -/

open Lean
open MLKEM
open CryptWalker.KEM.MLKEM768 (hashH uBytes vBytes)
open CryptWalker.KEM.MLKEMHedged
open CryptWalker.Util.newhex
open CryptWalker.Util.Bytes (ofVector toVecN)

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

def runVec (j : Json) : IO Bool := do
  match (do
    let name ← (← j.getObjVal? "name").getStr?
    pure (name, ← field j "d_hex", ← field j "z_hex", ← field j "m_hex", ← field j "m_hash_hex",
      ← field j "encapsulation_key_hex", ← field j "ciphertext_hex", ← field j "shared_secret_hex")
      : Except String _) with
  | .error e => do IO.eprintln e; pure false
  | .ok (name, d, z, m, wantMh, wantEk, wantCt, wantSs) =>
    IO.println s!"  {name}"
    let K := kemMLKEMHedged768Seed
    let sk := (toVecN 32 d, toVecN 32 z)
    let pk := K.derivePublicKey sk
    let mv := toVecN 32 m
    let mut ok ← check "encapsulation key" wantEk (ofVector (K.encodePublicKey pk))
    ok := (← check "H(m)" wantMh (ofVector (hashH (ofVector mv)))) && ok
    let (ss, ct) := encaps768Hedged (show CryptWalker.KEM.MLKEM768.PublicKey from pk).1 mv
    let ctBytes := uBytes ct.uEncoded ++ vBytes ct.vEncoded
    ok := (← check "ciphertext" wantCt ctBytes) && ok
    ok := (← check "encap shared secret" wantSs (ofVector ss)) && ok
    match K.decodeCiphertext (toVecN _ wantCt) with
    | none => IO.println "    FAIL ciphertext decode"; pure false
    | some c =>
      match K.decap sk c K.stateI.default with
      | .ok k _ => pure ((← check "decap shared secret" wantSs (ofVector (K.encodePlaintext k))) && ok)
      | .error _ _ => IO.println "    FAIL decap"; pure false

def main : IO UInt32 := do
  let path := "testdata/mlkem768_hedged.json"
  let raw ← IO.FS.readFile path
  match (do
    let j ← Json.parse raw
    let prim ← (← j.getObjVal? "primitive").getStr?
    if prim ≠ "mlkem768_hedged" then throw s!"unexpected primitive: {prim}"
    (← j.getObjVal? "vectors").getArr? : Except String _) with
  | .error e => IO.eprintln s!"failed to parse {path}: {e}"; pure 1
  | .ok vs =>
    IO.println s!"Hedged ML-KEM-768 vectors ({vs.size} from hpqc)"
    let mut ok := true
    for v in vs do
      ok := (← runVec v) && ok
    IO.println ""
    if vs.isEmpty then
      IO.eprintln "no vectors -- nothing was verified"
      return 1
    if !ok then
      IO.eprintln "FAILED"
      return 1
    IO.println s!"all checks passed ({vs.size} vectors)"
    pure 0

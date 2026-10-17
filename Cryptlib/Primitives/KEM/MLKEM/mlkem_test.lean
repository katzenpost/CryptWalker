/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import Cryptlib.Primitives.KEM.MLKEM.MLKEM
import Cryptlib.Util.newhex

/-! # ML-KEM known-answer tests: NIST ACVP vectors for ML-KEM-512, -768 and -1024

Vectors in `testdata/mlkem<N>_{keygen,encapdecap,keycheck}.json`, extracted by
`scripts/extract_acvp_mlkem.py`. -/

open Lean
open MLKEM
open Cryptlib.Primitives.KEM.FIPS203
open Cryptlib.Util.newhex
open Cryptlib.Util.Bytes (ofVector toVecN)

def field (j : Json) (k : String) : Except String ByteArray := do
  let s ← (← j.getObjVal? k).getStr?
  match hexStringToByteArray s with
  | some b => pure b
  | none   => throw s!"field {k}: not valid hex: {s}"

def hexOfB (b : ByteArray) : String := byteArrayToHex b

def loadPrimitive (path prim : String) : IO (Except String (Array Json)) := do
  let raw ← IO.FS.readFile path
  match Json.parse raw with
  | .error e => pure (.error s!"failed to parse {path}: {e}")
  | .ok j =>
    match j.getObjVal? "primitive" >>= Json.getStr? with
    | .error e => pure (.error e)
    | .ok p =>
      if p ≠ prim then pure (.error s!"unexpected primitive in {path}: {p}")
      else match j.getObjVal? "vectors" >>= Json.getArr? with
        | .error e => pure (.error e)
        | .ok arr  => pure (.ok arr)

def n : ParameterSet → Nat
  | .MLKEM512 => 512
  | .MLKEM768 => 768
  | .MLKEM1024 => 1024

/-! ## Raw encode/decode (no wire-type wrapper, no well-formedness proof) -/

section

variable (ps : ParameterSet)

def encodeEKRaw (ek : EncapsulationKey (params ps) (encoding ps)) : ByteArray :=
  (tBytes ps) ek.tHatEncoded ++ ofVector ek.rho

def decodeEKRaw (b : ByteArray) : EncapsulationKey (params ps) (encoding ps) :=
  let a := b.extract 0 (384 * (params ps).k)
  let rest := b.extract (384 * (params ps).k) b.size
  { tHatEncoded := (bytesT ps) a, rho := toVecN 32 rest }

def encodeDKRaw (dk : DecapsulationKey (params ps) (encoding ps)) : ByteArray :=
  (tBytes ps) dk.dkPKE.sHatEncoded ++ ((tBytes ps) dk.ekPKE.tHatEncoded ++ (ofVector dk.ekPKE.rho ++
    (ofVector dk.ekHash ++ ofVector dk.z)))

def decodeDKRaw (b : ByteArray) : DecapsulationKey (params ps) (encoding ps) :=
  let sHatEncoded := b.extract 0 (384 * (params ps).k)
  let b1 := b.extract (384 * (params ps).k) b.size
  let tHatEncoded := b1.extract 0 (384 * (params ps).k)
  let b2 := b1.extract (384 * (params ps).k) b1.size
  let rho := toVecN 32 (b2.extract 0 32)
  let b3 := b2.extract 32 b2.size
  let ekHash := toVecN 32 (b3.extract 0 32)
  let b4 := b3.extract 32 b3.size
  let z := toVecN 32 (b4.extract 0 32)
  { dkPKE := { sHatEncoded := (bytesT ps) sHatEncoded }
    ekPKE := { tHatEncoded := (bytesT ps) tHatEncoded, rho }, ekHash, z }

def encodeCTRaw (c : Ciphertext (params ps) (encoding ps)) : ByteArray :=
  (uBytes ps) c.uEncoded ++ (vBytes ps) c.vEncoded

def decodeCTRaw (b : ByteArray) : Ciphertext (params ps) (encoding ps) :=
  let u := b.extract 0 (32 * (params ps).du * (params ps).k)
  let rest := b.extract (32 * (params ps).du * (params ps).k) b.size
  { uEncoded := (bytesU ps) u, vEncoded := (bytesV ps) rest }

/-! ## KeyGen: `d, z -> ek, dk` -/

def runKeyGen : IO Bool := do
  match ← loadPrimitive s!"testdata/mlkem{n ps}_keygen.json" s!"mlkem{n ps}_keygen" with
  | .error e => do IO.eprintln e; pure false
  | .ok arr => do
    IO.println s!"ML-KEM-{n ps} KeyGen (NIST ACVP, {arr.size} vectors)"
    let mut ok := true
    for j in arr do
      match (do
        let name ← (← j.getObjVal? "name").getStr?
        let d ← field j "d_hex"
        let z ← field j "z_hex"
        let wantEk ← field j "ek_hex"
        let wantDk ← field j "dk_hex"
        pure (name, d, z, wantEk, wantDk) : Except String _) with
      | .error e => do IO.eprintln e; ok := false
      | .ok (name, d, z, wantEk, wantDk) =>
        if d.size ≠ 32 ∨ z.size ≠ 32 then
          ok := false
          IO.println s!"  FAIL  {name}  (d/z not 32 bytes)"
        else
          let (ek, dk) := (keygen ps) (toVecN 32 d) (toVecN 32 z)
          let gotEk := hexOfB ((encodeEKRaw ps) ek)
          let gotDk := hexOfB ((encodeDKRaw ps) dk)
          if gotEk == hexOfB wantEk ∧ gotDk == hexOfB wantDk then
            IO.println s!"  ok    {name}"
          else
            ok := false
            IO.println s!"  FAIL  {name}"
            if gotEk ≠ hexOfB wantEk then
              IO.println s!"          ek want {hexOfB wantEk}"
              IO.println s!"          ek got  {gotEk}"
            if gotDk ≠ hexOfB wantDk then
              IO.println s!"          dk want {hexOfB wantDk}"
              IO.println s!"          dk got  {gotDk}"
    pure ok

/-! ## Encapsulate/Decapsulate: `ek, m -> c, k` (AFT) and `dk, c -> k` (VAL) -/

def runEncapDecap : IO Bool := do
  match ← loadPrimitive s!"testdata/mlkem{n ps}_encapdecap.json" s!"mlkem{n ps}_encapdecap" with
  | .error e => do IO.eprintln e; pure false
  | .ok arr => do
    IO.println s!"ML-KEM-{n ps} Encaps/Decaps (NIST ACVP, {arr.size} vectors)"
    let mut ok := true
    for j in arr do
      match (do
        let name ← (← j.getObjVal? "name").getStr?
        let mode ← (← j.getObjVal? "mode").getStr?
        pure (name, mode) : Except String _) with
      | .error e => do IO.eprintln e; ok := false
      | .ok (name, "encap") =>
        match (do
          let ek ← field j "ek_hex"
          let m ← field j "m_hex"
          let wantC ← field j "c_hex"
          let wantK ← field j "k_hex"
          pure (ek, m, wantC, wantK) : Except String _) with
        | .error e => do IO.eprintln e; ok := false
        | .ok (ek, m, wantC, wantK) =>
          if ek.size ≠ (params ps).publicKeyBytes ∨ m.size ≠ 32 then
            ok := false
            IO.println s!"  FAIL  {name}  (ek/m wrong length)"
          else
            let (k, c) := (encaps ps) ((decodeEKRaw ps) ek) (toVecN 32 m)
            let gotC := hexOfB ((encodeCTRaw ps) c)
            let gotK := hexOfB (ofVector k)
            if gotC == hexOfB wantC ∧ gotK == hexOfB wantK then
              IO.println s!"  ok    {name}"
            else
              ok := false
              IO.println s!"  FAIL  {name}"
              if gotC ≠ hexOfB wantC then
                IO.println s!"          c want {hexOfB wantC}"
                IO.println s!"          c got  {gotC}"
              if gotK ≠ hexOfB wantK then
                IO.println s!"          k want {hexOfB wantK}"
                IO.println s!"          k got  {gotK}"
      | .ok (name, "decap") =>
        match (do
          let dk ← field j "dk_hex"
          let c ← field j "c_hex"
          let wantK ← field j "k_hex"
          pure (dk, c, wantK) : Except String _) with
        | .error e => do IO.eprintln e; ok := false
        | .ok (dk, c, wantK) =>
          if dk.size ≠ (params ps).secretKeyBytes ∨ c.size ≠ (params ps).ciphertextBytes then
            ok := false
            IO.println s!"  FAIL  {name}  (dk/c wrong length)"
          else
            let k := (decaps ps) ((decodeDKRaw ps) dk) ((decodeCTRaw ps) c)
            let gotK := hexOfB (ofVector k)
            if gotK == hexOfB wantK then
              IO.println s!"  ok    {name}"
            else
              ok := false
              IO.println s!"  FAIL  {name}"
              IO.println s!"          k want {hexOfB wantK}"
              IO.println s!"          k got  {gotK}"
      | .ok (name, mode) => do
        IO.eprintln s!"{name}: unknown mode {mode}"; ok := false
    pure ok

/-! ## Input-validation checks: `(checkDecapsulationKey ps)`/`(checkEncapsulationKey ps)` (VAL) -/

def runKeyCheck : IO Bool := do
  match ← loadPrimitive s!"testdata/mlkem{n ps}_keycheck.json" s!"mlkem{n ps}_keycheck" with
  | .error e => do IO.eprintln e; pure false
  | .ok arr => do
    IO.println s!"ML-KEM-{n ps} key checks (NIST ACVP, {arr.size} vectors)"
    let mut ok := true
    for j in arr do
      match (do
        let name ← (← j.getObjVal? "name").getStr?
        let mode ← (← j.getObjVal? "mode").getStr?
        let wantPass ← (← j.getObjVal? "want_pass").getBool?
        pure (name, mode, wantPass) : Except String _) with
      | .error e => do IO.eprintln e; ok := false
      | .ok (name, "checkDK", wantPass) =>
        match field j "dk_hex" with
        | .error e => do IO.eprintln e; ok := false
        | .ok dk =>
          if dk.size ≠ (params ps).secretKeyBytes then
            ok := false
            IO.println s!"  FAIL  {name}  (dk wrong length)"
          else
            let gotPass := checkDecapsulationKey ps ((decodeDKRaw ps) dk)
            if gotPass == wantPass then
              IO.println s!"  ok    {name}"
            else
              ok := false
              IO.println s!"  FAIL  {name}  want pass={wantPass} got pass={gotPass}"
      | .ok (name, "checkEK", wantPass) =>
        match field j "ek_hex" with
        | .error e => do IO.eprintln e; ok := false
        | .ok ek =>
          if ek.size ≠ (params ps).publicKeyBytes then
            ok := false
            IO.println s!"  FAIL  {name}  (ek wrong length)"
          else
            let gotPass := checkEncapsulationKey ps ((decodeEKRaw ps) ek)
            if gotPass == wantPass then
              IO.println s!"  ok    {name}"
            else
              ok := false
              IO.println s!"  FAIL  {name}  want pass={wantPass} got pass={gotPass}"
      | .ok (name, mode, _) => do
        IO.eprintln s!"{name}: unknown mode {mode}"; ok := false
    pure ok

end

def main : IO UInt32 := do
  let mut ok := true
  for ps in [ParameterSet.MLKEM512, .MLKEM768, .MLKEM1024] do
    let okKeyGen ← runKeyGen ps
    let okEncapDecap ← runEncapDecap ps
    let okKeyCheck ← runKeyCheck ps
    ok := ok && okKeyGen && okEncapDecap && okKeyCheck
  if ok then
    IO.println "ML-KEM KAT: all NIST ACVP vectors passed"
    pure 0
  else
    IO.eprintln "ML-KEM KAT: FAILED"
    pure 1

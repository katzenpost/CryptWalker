/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.KEM.MLKEMHedged.MLKEMHedged
import CryptWalker.Util.newhex

/-!
# Hedged ML-KEM: NIST ACVP known-answer tests, for ML-KEM-512, -768 and -1024

Runs each parameter set's NIST ACVP vectors through the hedged instances `kem ps` and `kemSeed ps`:
their decoders, encoders, `derivePublicKey` and `decap`. Hedging changes only which message
encapsulation encrypts, so every ACVP group applies except one step: ACVP gives
`Encaps_internal`'s input `m` directly, which for the hedged scheme is the already-hashed message.
`encapsHedged_eq_encaps_hashH` proves hedged encapsulation is `FIPS203.encaps` after `H`, so these
vectors check everything but `H(m)` itself. The pre-hash is covered by the hpqc cross-check vectors
(`KEM/mlkem768_hedged_test.lean`) and, for every size, by an encapsulate/decapsulate round trip.
-/

open Lean
open MLKEM
open CryptWalker.KEM.FIPS203 (encaps expandSeed checkEncapsulationKey checkDecapsulationKey
  uBytes vBytes stateFromSeed)
open CryptWalker.KEM.MLKEMHedged
open CryptWalker.Util.newhex
open CryptWalker.Util.Bytes (ofVector toVecN)

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

def report (name : String) (checks : List (String × ByteArray × ByteArray)) : IO Bool := do
  let bad := checks.filter fun (_, want, got) => hexOfB want ≠ hexOfB got
  if bad.isEmpty then
    IO.println s!"  ok    {name}"
    pure true
  else
    IO.println s!"  FAIL  {name}"
    for (label, want, got) in bad do
      IO.println s!"          {label} want {hexOfB want}"
      IO.println s!"          {label} got  {hexOfB got}"
    pure false

def n : ParameterSet → Nat
  | .MLKEM512 => 512
  | .MLKEM768 => 768
  | .MLKEM1024 => 1024

section

variable (ps : ParameterSet)

/-! ## KeyGen: `d, z -> ek, dk` -/

def runKeyGen : IO Bool := do
  match ← loadPrimitive s!"testdata/mlkem{n ps}_keygen.json" s!"mlkem{n ps}_keygen" with
  | .error e => do IO.eprintln e; pure false
  | .ok arr => do
    IO.println s!"Hedged ML-KEM-{n ps} KeyGen (NIST ACVP, {arr.size} vectors)"
    let mut ok := true
    for j in arr do
      match (do
        let name ← (← j.getObjVal? "name").getStr?
        pure (name, ← field j "d_hex", ← field j "z_hex", ← field j "ek_hex", ← field j "dk_hex")
          : Except String _) with
      | .error e => do IO.eprintln e; ok := false
      | .ok (name, d, z, wantEk, wantDk) =>
        let sk := (toVecN 32 d, toVecN 32 z)
        let ek := ofVector ((kemSeed ps).encodePublicKey
          ((kemSeed ps).derivePublicKey sk))
        let dk := ofVector ((kem ps).encodePrivateKey (expandSeed ps sk))
        ok := (← report name [("ek", wantEk, ek), ("dk", wantDk, dk)]) && ok
    pure ok

/-! ## Encaps (`AFT`, via the proven core) and Decaps (`VAL`, via the hedged `decap`) -/

def runEncapDecap : IO Bool := do
  match ← loadPrimitive s!"testdata/mlkem{n ps}_encapdecap.json" s!"mlkem{n ps}_encapdecap" with
  | .error e => do IO.eprintln e; pure false
  | .ok arr => do
    IO.println s!"Hedged ML-KEM-{n ps} Encaps core / Decaps (NIST ACVP, {arr.size} vectors)"
    let mut ok := true
    for j in arr do
      match (do
        let name ← (← j.getObjVal? "name").getStr?
        let mode ← (← j.getObjVal? "mode").getStr?
        pure (name, mode) : Except String _) with
      | .error e => do IO.eprintln e; ok := false
      | .ok (name, "encap") =>
        match (do pure (← field j "ek_hex", ← field j "m_hex", ← field j "c_hex", ← field j "k_hex")
            : Except String _) with
        | .error e => do IO.eprintln e; ok := false
        | .ok (ek, m, wantC, wantK) =>
          match (kem ps).decodePublicKey (toVecN _ ek) with
          | none => do IO.println s!"  FAIL  {name}  (ek decode)"; ok := false
          | some pk =>
            let (k, c) := encaps ps (show CryptWalker.KEM.FIPS203.PublicKey ps from pk).1 (toVecN 32 m)
            ok := (← report name [("c", wantC, uBytes ps c.uEncoded ++ vBytes ps c.vEncoded),
              ("k", wantK, ofVector k)]) && ok
      | .ok (name, "decap") =>
        match (do pure (← field j "dk_hex", ← field j "c_hex", ← field j "k_hex")
            : Except String _) with
        | .error e => do IO.eprintln e; ok := false
        | .ok (dk, c, wantK) =>
          match (kem ps).decodePrivateKey (toVecN _ dk),
              (kem ps).decodeCiphertext (toVecN _ c) with
          | some sk, some ct =>
            match (kem ps).decap sk ct (kem ps).stateI.default with
            | .ok k _ =>
              ok := (← report name [("k", wantK, ofVector ((kem ps).encodePlaintext k))]) && ok
            | .error _ _ => do IO.println s!"  FAIL  {name}  (decap error)"; ok := false
          | _, _ => do IO.println s!"  FAIL  {name}  (dk/c decode)"; ok := false
      | .ok (name, mode) => do
        IO.eprintln s!"{name}: unknown mode {mode}"; ok := false
    pure ok

/-! ## Input-validation checks on keys decoded by the hedged instance -/

def runKeyCheck : IO Bool := do
  match ← loadPrimitive s!"testdata/mlkem{n ps}_keycheck.json" s!"mlkem{n ps}_keycheck" with
  | .error e => do IO.eprintln e; pure false
  | .ok arr => do
    IO.println s!"Hedged ML-KEM-{n ps} key checks (NIST ACVP, {arr.size} vectors)"
    let mut ok := true
    for j in arr do
      match (do
        let name ← (← j.getObjVal? "name").getStr?
        let mode ← (← j.getObjVal? "mode").getStr?
        let wantPass ← (← j.getObjVal? "want_pass").getBool?
        pure (name, mode, wantPass) : Except String _) with
      | .error e => do IO.eprintln e; ok := false
      | .ok (name, mode, wantPass) =>
        let gotPass : Option Bool :=
          match mode with
          | "checkEK" => (field j "ek_hex").toOption.bind fun b =>
              ((kem ps).decodePublicKey (toVecN _ b)).map fun pk =>
                checkEncapsulationKey ps (show CryptWalker.KEM.FIPS203.PublicKey ps from pk).1
          | "checkDK" => (field j "dk_hex").toOption.bind fun b =>
              ((kem ps).decodePrivateKey (toVecN _ b)).map fun sk =>
                checkDecapsulationKey ps (show CryptWalker.KEM.FIPS203.PrivateKey ps from sk).1
          | _ => none
        match gotPass with
        | some p =>
          if p == wantPass then IO.println s!"  ok    {name}"
          else
            ok := false
            IO.println s!"  FAIL  {name}  want pass={wantPass} got pass={p}"
        | none => do IO.println s!"  FAIL  {name}  (mode {mode} or decode)"; ok := false
    pure ok

/-! ## Round trip, through the pre-hash -/

def runRoundTrip : IO Bool := do
  let K := kemSeed ps
  let mut ok := true
  for i in [0:8] do
    let seed : Vector UInt8 32 := Vector.ofFn fun j => UInt8.ofNat (i * 32 + j.val)
    match K.generate (K.stateFromSeed seed) with
    | .error _ _ => ok := false
    | .ok ⟨pk, sk, _⟩ s =>
      match K.encap pk s with
      | .error _ _ => ok := false
      | .ok (c, k) _ =>
        match K.decap sk c (K.stateFromSeed seed) with
        | .ok k' _ => ok := ok && (k' == k)
        | .error _ _ => ok := false
  IO.println s!"Hedged ML-KEM-{n ps} round trip: {if ok then "ok" else "FAIL"}"
  pure ok

end

def main : IO UInt32 := do
  let mut ok := true
  for ps in [ParameterSet.MLKEM512, .MLKEM768, .MLKEM1024] do
    let okKeyGen ← runKeyGen ps
    let okEncapDecap ← runEncapDecap ps
    let okKeyCheck ← runKeyCheck ps
    let okRoundTrip ← runRoundTrip ps
    ok := ok && okKeyGen && okEncapDecap && okKeyCheck && okRoundTrip
  if ok then
    IO.println "Hedged ML-KEM KAT: all NIST ACVP vectors passed"
    pure 0
  else
    IO.eprintln "Hedged ML-KEM KAT: FAILED"
    pure 1

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.KEM.MLKEMHedged.MLKEMHedged768
import CryptWalker.Util.newhex

/-!
# Hedged ML-KEM-768: NIST ACVP known-answer tests

Runs the NIST ACVP ML-KEM-768 vectors that `KEM/MLKEM/mlkem768_test.lean` checks against raw
`keygen768`/`encaps768`/`decaps768` through the registered hedged instances `kemMLKEMHedged768`
and `kemMLKEMHedged768Seed` instead: their decoders, encoders, `derivePublicKey` and `decap`.

Hedging changes only which message encapsulation encrypts, so every ACVP group applies to the
hedged scheme except one step:

* keygen (`d, z -> ek, dk`): `kemMLKEMHedged768Seed.derivePublicKey (d, z)` must encode to `ek`,
  and the expanded key `expandSeed (d, z)` must encode to `dk` under `kemMLKEMHedged768`;
* decap (`dk, c -> k`, `VAL`, including implicit rejection): `kemMLKEMHedged768.decap`;
* key checks: `checkEncapsulationKey`/`checkDecapsulationKey` on keys decoded by the hedged
  instance;
* encap (`ek, m -> c, k`): ACVP gives `Encaps_internal`'s input `m` directly, which for the hedged
  scheme is the already-hashed message. `encaps768Hedged_eq_encaps768_hashH` proves hedged
  encapsulation is `encaps768` after `H`, so these vectors check everything but `H(m)` itself.
  The pre-hash is covered by the hpqc cross-check vectors (`KEM/mlkem768_hedged_test.lean`).
-/

open Lean
open MLKEM
open CryptWalker.KEM.MLKEM768 (params encoding encaps768 expandSeed checkEncapsulationKey
  checkDecapsulationKey uBytes vBytes)
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

/-! ## KeyGen: `d, z -> ek, dk` -/

def runKeyGen : IO Bool := do
  match ← loadPrimitive "testdata/mlkem768_keygen.json" "mlkem768_keygen" with
  | .error e => do IO.eprintln e; pure false
  | .ok arr => do
    IO.println s!"Hedged ML-KEM-768 KeyGen (NIST ACVP, {arr.size} vectors)"
    let mut ok := true
    for j in arr do
      match (do
        let name ← (← j.getObjVal? "name").getStr?
        pure (name, ← field j "d_hex", ← field j "z_hex", ← field j "ek_hex", ← field j "dk_hex")
          : Except String _) with
      | .error e => do IO.eprintln e; ok := false
      | .ok (name, d, z, wantEk, wantDk) =>
        let sk := (toVecN 32 d, toVecN 32 z)
        let ek := ofVector (kemMLKEMHedged768Seed.encodePublicKey
          (kemMLKEMHedged768Seed.derivePublicKey sk))
        let dk := ofVector (kemMLKEMHedged768.encodePrivateKey (expandSeed sk))
        ok := (← report name [("ek", wantEk, ek), ("dk", wantDk, dk)]) && ok
    pure ok

/-! ## Encaps (`AFT`, via the proven core) and Decaps (`VAL`, via the hedged `decap`) -/

def runEncapDecap : IO Bool := do
  match ← loadPrimitive "testdata/mlkem768_encapdecap.json" "mlkem768_encapdecap" with
  | .error e => do IO.eprintln e; pure false
  | .ok arr => do
    IO.println s!"Hedged ML-KEM-768 Encaps core / Decaps (NIST ACVP, {arr.size} vectors)"
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
          match kemMLKEMHedged768.decodePublicKey (toVecN _ ek) with
          | none => do IO.println s!"  FAIL  {name}  (ek decode)"; ok := false
          | some pk =>
            let (k, c) := encaps768 (show CryptWalker.KEM.MLKEM768.PublicKey from pk).1 (toVecN 32 m)
            ok := (← report name [("c", wantC, uBytes c.uEncoded ++ vBytes c.vEncoded),
              ("k", wantK, ofVector k)]) && ok
      | .ok (name, "decap") =>
        match (do pure (← field j "dk_hex", ← field j "c_hex", ← field j "k_hex")
            : Except String _) with
        | .error e => do IO.eprintln e; ok := false
        | .ok (dk, c, wantK) =>
          match kemMLKEMHedged768.decodePrivateKey (toVecN _ dk),
              kemMLKEMHedged768.decodeCiphertext (toVecN _ c) with
          | some sk, some ct =>
            match kemMLKEMHedged768.decap sk ct kemMLKEMHedged768.stateI.default with
            | .ok k _ =>
              ok := (← report name [("k", wantK, ofVector (kemMLKEMHedged768.encodePlaintext k))]) && ok
            | .error _ _ => do IO.println s!"  FAIL  {name}  (decap error)"; ok := false
          | _, _ => do IO.println s!"  FAIL  {name}  (dk/c decode)"; ok := false
      | .ok (name, mode) => do
        IO.eprintln s!"{name}: unknown mode {mode}"; ok := false
    pure ok

/-! ## Input-validation checks on keys decoded by the hedged instance -/

def runKeyCheck : IO Bool := do
  match ← loadPrimitive "testdata/mlkem768_keycheck.json" "mlkem768_keycheck" with
  | .error e => do IO.eprintln e; pure false
  | .ok arr => do
    IO.println s!"Hedged ML-KEM-768 key checks (NIST ACVP, {arr.size} vectors)"
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
              (kemMLKEMHedged768.decodePublicKey (toVecN _ b)).map fun pk =>
                checkEncapsulationKey (show CryptWalker.KEM.MLKEM768.PublicKey from pk).1
          | "checkDK" => (field j "dk_hex").toOption.bind fun b =>
              (kemMLKEMHedged768.decodePrivateKey (toVecN _ b)).map fun sk =>
                checkDecapsulationKey (show CryptWalker.KEM.MLKEM768.PrivateKey from sk).1
          | _ => none
        match gotPass with
        | some p =>
          if p == wantPass then IO.println s!"  ok    {name}"
          else
            ok := false
            IO.println s!"  FAIL  {name}  want pass={wantPass} got pass={p}"
        | none => do IO.println s!"  FAIL  {name}  (mode {mode} or decode)"; ok := false
    pure ok

def main : IO UInt32 := do
  let okKeyGen ← runKeyGen
  let okEncapDecap ← runEncapDecap
  let okKeyCheck ← runKeyCheck
  if okKeyGen ∧ okEncapDecap ∧ okKeyCheck then
    IO.println "Hedged ML-KEM-768 KAT: all NIST ACVP vectors passed"
    pure 0
  else
    IO.eprintln "Hedged ML-KEM-768 KAT: FAILED"
    pure 1

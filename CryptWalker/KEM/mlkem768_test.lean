/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.KEM.MLKEM768
import CryptWalker.Util.newhex

/-!
# ML-KEM-768 known-answer tests: NIST ACVP vectors

Checks `keygen768`/`encaps768`/`decaps768` (`CryptWalker/KEM/MLKEM768.lean`) against the official
NIST ACVP-Server ML-KEM-768 test vectors (`gen-val/json-files/ML-KEM-{keyGen,encapDecap}-FIPS203/
internalProjection.json`, vendored into `testdata/mlkem768_{keygen,encapdecap}.json` — see those
files' `"generator"` field for the exact source), following the same
`field`/`loadPrimitive`/hex-helper convention as `Sphinx/crypto_test.lean`.

This complements, rather than replaces, `Sphinx/kem_selftest.lean`'s `"mlkem768-kem"` round: that
checks *internal* consistency (decap undoes encap for a self-generated keypair); this checks
*compliance* against an external, authoritative reference. The `mlkem768_encapdecap.json`
decapsulation vectors are NIST's `VAL` group (not `AFT` — ACVP puts all decapsulation testing
there), and include "modified ciphertext" cases exercising `decaps768`'s implicit-rejection path
(`jReject`) — a malformed ciphertext still decapsulates to a specific, deterministic pseudorandom
key rather than erroring, and that key is exactly what NIST's vector checks.

Also checks `checkEncapsulationKey`/`checkDecapsulationKey` (FIPS 203 §7.2/§7.3's input-validation
checks, also `MLKEM768.lean`) against NIST's `decapsulationKeyCheck`/`encapsulationKeyCheck` `VAL`
groups, vendored into `testdata/mlkem768_keycheck.json` — the modulus check ("noisy linear system
values too large" cases must fail) and the hash check ("modified H" cases must fail) both need to
correctly *reject* a malformed key, not just accept a well-formed one.

Local encode/decode helpers on the *raw* `EncapsulationKey`/`DecapsulationKey`/`Ciphertext`
structures (not `MLKEM768Encoding.lean`'s `PublicKey`/`PrivateKey`/`CT` wrapper subtypes) — a KAT
test only needs raw computation and a byte comparison, not the formal wire-type well-formedness
machinery, and `MLKEM768Encoding.lean`'s own `decode*Val`/`encode*` are `private`. -/

open Lean
open MLKEM
open CryptWalker.KEM.MLKEM768
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

/-! ## Raw encode/decode (no wire-type wrapper, no well-formedness proof) -/

def encodeEKRaw (ek : EncapsulationKey params encoding) : ByteArray :=
  tBytes ek.tHatEncoded ++ ofVector ek.rho

def decodeEKRaw (b : ByteArray) : EncapsulationKey params encoding :=
  let a := b.extract 0 (384 * params.k)
  let rest := b.extract (384 * params.k) b.size
  { tHatEncoded := bytesT a, rho := toVecN 32 rest }

def encodeDKRaw (dk : DecapsulationKey params encoding) : ByteArray :=
  tBytes dk.dkPKE.sHatEncoded ++ (tBytes dk.ekPKE.tHatEncoded ++ (ofVector dk.ekPKE.rho ++
    (ofVector dk.ekHash ++ ofVector dk.z)))

def decodeDKRaw (b : ByteArray) : DecapsulationKey params encoding :=
  let sHatEncoded := b.extract 0 (384 * params.k)
  let b1 := b.extract (384 * params.k) b.size
  let tHatEncoded := b1.extract 0 (384 * params.k)
  let b2 := b1.extract (384 * params.k) b1.size
  let rho := toVecN 32 (b2.extract 0 32)
  let b3 := b2.extract 32 b2.size
  let ekHash := toVecN 32 (b3.extract 0 32)
  let b4 := b3.extract 32 b3.size
  let z := toVecN 32 (b4.extract 0 32)
  { dkPKE := { sHatEncoded := bytesT sHatEncoded }
    ekPKE := { tHatEncoded := bytesT tHatEncoded, rho }, ekHash, z }

def encodeCTRaw (c : Ciphertext params encoding) : ByteArray :=
  uBytes c.uEncoded ++ vBytes c.vEncoded

def decodeCTRaw (b : ByteArray) : Ciphertext params encoding :=
  let u := b.extract 0 (32 * params.du * params.k)
  let rest := b.extract (32 * params.du * params.k) b.size
  { uEncoded := bytesU u, vEncoded := bytesV rest }

/-! ## KeyGen: `d, z -> ek, dk` -/

def runKeyGen : IO Bool := do
  match ← loadPrimitive "testdata/mlkem768_keygen.json" "mlkem768_keygen" with
  | .error e => do IO.eprintln e; pure false
  | .ok arr => do
    IO.println s!"ML-KEM-768 KeyGen (NIST ACVP, {arr.size} vectors)"
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
          let (ek, dk) := keygen768 (toVecN 32 d) (toVecN 32 z)
          let gotEk := hexOfB (encodeEKRaw ek)
          let gotDk := hexOfB (encodeDKRaw dk)
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
  match ← loadPrimitive "testdata/mlkem768_encapdecap.json" "mlkem768_encapdecap" with
  | .error e => do IO.eprintln e; pure false
  | .ok arr => do
    IO.println s!"ML-KEM-768 Encaps/Decaps (NIST ACVP, {arr.size} vectors)"
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
          if ek.size ≠ params.publicKeyBytes ∨ m.size ≠ 32 then
            ok := false
            IO.println s!"  FAIL  {name}  (ek/m wrong length)"
          else
            let (k, c) := encaps768 (decodeEKRaw ek) (toVecN 32 m)
            let gotC := hexOfB (encodeCTRaw c)
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
          if dk.size ≠ params.secretKeyBytes ∨ c.size ≠ params.ciphertextBytes then
            ok := false
            IO.println s!"  FAIL  {name}  (dk/c wrong length)"
          else
            let k := decaps768 (decodeDKRaw dk) (decodeCTRaw c)
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

/-! ## Input-validation checks: `checkDecapsulationKey`/`checkEncapsulationKey` (VAL) -/

def runKeyCheck : IO Bool := do
  match ← loadPrimitive "testdata/mlkem768_keycheck.json" "mlkem768_keycheck" with
  | .error e => do IO.eprintln e; pure false
  | .ok arr => do
    IO.println s!"ML-KEM-768 key checks (NIST ACVP, {arr.size} vectors)"
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
          if dk.size ≠ params.secretKeyBytes then
            ok := false
            IO.println s!"  FAIL  {name}  (dk wrong length)"
          else
            let gotPass := checkDecapsulationKey (decodeDKRaw dk)
            if gotPass == wantPass then
              IO.println s!"  ok    {name}"
            else
              ok := false
              IO.println s!"  FAIL  {name}  want pass={wantPass} got pass={gotPass}"
      | .ok (name, "checkEK", wantPass) =>
        match field j "ek_hex" with
        | .error e => do IO.eprintln e; ok := false
        | .ok ek =>
          if ek.size ≠ params.publicKeyBytes then
            ok := false
            IO.println s!"  FAIL  {name}  (ek wrong length)"
          else
            let gotPass := checkEncapsulationKey (decodeEKRaw ek)
            if gotPass == wantPass then
              IO.println s!"  ok    {name}"
            else
              ok := false
              IO.println s!"  FAIL  {name}  want pass={wantPass} got pass={gotPass}"
      | .ok (name, mode, _) => do
        IO.eprintln s!"{name}: unknown mode {mode}"; ok := false
    pure ok

def main : IO UInt32 := do
  let okKeyGen ← runKeyGen
  let okEncapDecap ← runEncapDecap
  let okKeyCheck ← runKeyCheck
  if okKeyGen ∧ okEncapDecap ∧ okKeyCheck then
    IO.println "ML-KEM-768 KAT: all NIST ACVP vectors passed"
    pure 0
  else
    IO.eprintln "ML-KEM-768 KAT: FAILED"
    pure 1

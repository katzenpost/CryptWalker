/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import Cryptlib.Primitives.KEM.Schemes
import Cryptlib.Util.newhex

/-! # X25519 + ML-KEM-768 combiner: known-answer tests

Vectors from `testdata/mlkem768_x25519_combiner.json` check each component and the combined
ciphertext and shared secret. Each vector's `prf` field selects `kemX25519Blake2b` or
`kemX25519`. -/

open Lean
open Cryptlib.Util.newhex
open Cryptlib.Primitives.KEM
open Cryptlib.Primitives.KEM.KEM
open MLKEM
open Cryptlib.Primitives.KEM.MLKEM768 (keygen768 encaps768 params encoding tBytes uBytes vBytes)
open Cryptlib.Util.Bytes (ofVector toVecN)

def field (j : Json) (k : String) : Except String ByteArray := do
  let s ← (← j.getObjVal? k).getStr?
  match hexStringToByteArray s with
  | some b => pure b
  | none   => throw s!"field {k}: not valid hex: {s}"

def hexOfB (b : ByteArray) : String := byteArrayToHex b

def encodeEKRaw (ek : EncapsulationKey params encoding) : ByteArray :=
  tBytes ek.tHatEncoded ++ ofVector ek.rho

def encodeCTRaw (c : Ciphertext params encoding) : ByteArray :=
  uBytes c.uEncoded ++ vBytes c.vEncoded

structure Vec where
  name             : String
  prf              : String
  x25519StaticPriv : ByteArray
  x25519StaticPub  : ByteArray
  x25519EphPriv    : ByteArray
  x25519Ct         : ByteArray
  x25519Ss         : ByteArray
  mlkemD           : ByteArray
  mlkemZ           : ByteArray
  mlkemM           : ByteArray
  mlkemEk          : ByteArray
  mlkemCt          : ByteArray
  mlkemSs          : ByteArray
  combinedCt       : ByteArray
  combinedSs       : ByteArray

def parseVec (j : Json) : Except String Vec := do
  pure {
    name             := ← (← j.getObjVal? "name").getStr?
    prf              := ← (← j.getObjVal? "prf").getStr?
    x25519StaticPriv := ← field j "x25519_static_private_key_hex"
    x25519StaticPub  := ← field j "x25519_static_public_key_hex"
    x25519EphPriv    := ← field j "x25519_ephemeral_private_key_hex"
    x25519Ct         := ← field j "x25519_ciphertext_hex"
    x25519Ss         := ← field j "x25519_shared_secret_hex"
    mlkemD           := ← field j "mlkem_d_hex"
    mlkemZ           := ← field j "mlkem_z_hex"
    mlkemM           := ← field j "mlkem_m_hex"
    mlkemEk          := ← field j "mlkem_encapsulation_key_hex"
    mlkemCt          := ← field j "mlkem_ciphertext_hex"
    mlkemSs          := ← field j "mlkem_shared_secret_hex"
    combinedCt       := ← field j "combined_ciphertext_hex"
    combinedSs       := ← field j "combined_shared_secret_hex"
  }

def parseFile (s : String) : Except String (Array Vec) := do
  let j ← Json.parse s
  let prim ← (← j.getObjVal? "primitive").getStr?
  if prim ≠ "mlkem768_x25519_combiner" then throw s!"unexpected primitive: {prim}"
  let arr ← (← j.getObjVal? "vectors").getArr?
  arr.mapM parseVec

def check (label : String) (want got : ByteArray) : IO Bool := do
  if hexOfB want == hexOfB got then
    IO.println s!"    ok   {label}"
    pure true
  else
    IO.println s!"    FAIL {label}"
    IO.println s!"           want {hexOfB want}"
    IO.println s!"           got  {hexOfB got}"
    pure false

/-- The X25519 KEM for a PRF name. -/
def x25519KEMByPRFName : String → Option KEM
  | "sha256-v1"   => some kemX25519
  | "blake2b-xof" => some kemX25519Blake2b
  | _             => none

/-- Checks the X25519 component; also returns its ciphertext and shared secret. -/
def runX25519 (kem : KEM) (v : Vec) : IO (Bool × ByteArray × ByteArray) := do
  match kem.decodePrivateKey (toVecN kem.privateKeySize v.x25519StaticPriv) with
  | none => IO.println "    FAIL x25519 static privkey decode"; pure (false, ByteArray.empty, ByteArray.empty)
  | some sk =>
    let pk := kem.derivePublicKey sk
    let mut ok := ← check "x25519 static pubkey" v.x25519StaticPub (ofVector (kem.encodePublicKey pk))
    match kem.encap pk (kem.stateFromSeed (toVecN 32 v.x25519EphPriv)) with
    | .error _ _ => IO.println "    FAIL x25519 encap"; pure (false, ByteArray.empty, ByteArray.empty)
    | .ok (ct, ssEncap) _ =>
      let ctBytes := ofVector (kem.encodeCiphertext ct)
      let ssBytes := ofVector (kem.encodePlaintext ssEncap)
      ok := (← check "x25519 ciphertext" v.x25519Ct ctBytes) && ok
      ok := (← check "x25519 encap shared secret" v.x25519Ss ssBytes) && ok
      match kem.decap sk ct (kem.stateFromSeed (toVecN 32 v.x25519EphPriv)) with
      | .error _ _ => IO.println "    FAIL x25519 decap"; pure (false, ctBytes, ssBytes)
      | .ok ssDecap _ =>
        ok := (← check "x25519 decap shared secret" v.x25519Ss
          (ofVector (kem.encodePlaintext ssDecap))) && ok
        pure (ok, ctBytes, ssBytes)

/-- Checks the ML-KEM-768 component; also returns its ciphertext and shared secret. -/
def runMLKEM (v : Vec) : IO (Bool × ByteArray × ByteArray) := do
  let d := toVecN 32 v.mlkemD
  let z := toVecN 32 v.mlkemZ
  let m := toVecN 32 v.mlkemM
  let (ek, _dk) := keygen768 d z
  let mut ok ← check "mlkem768 encapsulation key" v.mlkemEk (encodeEKRaw ek)
  let (ss, ct) := encaps768 ek m
  let ctBytes := encodeCTRaw ct
  let ssBytes := ofVector ss
  ok := (← check "mlkem768 ciphertext" v.mlkemCt ctBytes) && ok
  ok := (← check "mlkem768 shared secret" v.mlkemSs ssBytes) && ok
  pure (ok, ctBytes, ssBytes)

/-- `(ran, ok)`: whether the vector's PRF is supported, and whether its checks passed. -/
def runVec (v : Vec) : IO (Bool × Bool) := do
  match x25519KEMByPRFName v.prf with
  | none =>
      IO.println s!"  {v.name}  [skipped: PRF {v.prf} not implemented here]"
      pure (false, true)
  | some kemX25519' => do
    IO.println s!"  {v.name}"
    let (okX25519, ctX25519, ssX25519) ← runX25519 kemX25519' v
    let (okMLKEM, ctMLKEM, ssMLKEM) ← runMLKEM v
    let mut ok := okX25519 && okMLKEM
    ok := (← check "combined ciphertext" v.combinedCt (ctX25519 ++ ctMLKEM)) && ok
    let ssCombined := Combiner.splitPRF blake2b256CombinerPRF (ssX25519, ctX25519) [(ssMLKEM, ctMLKEM)]
    ok := (← check "combined shared secret" v.combinedSs (ofVector ssCombined)) && ok
    pure (true, ok)

def main : IO UInt32 := do
  let path := "testdata/mlkem768_x25519_combiner.json"
  let raw ← IO.FS.readFile path
  match parseFile raw with
  | .error e => IO.eprintln s!"failed to parse {path}: {e}"; pure 1
  | .ok vs =>
    IO.println s!"X25519 + ML-KEM-768 hybrid combiner vectors ({vs.size} from hpqc)"
    let mut ok := true
    let mut ran := 0
    for v in vs do
      let (didRun, vecOk) ← runVec v
      ok := ok && vecOk
      if didRun then ran := ran + 1
    IO.println ""
    if ran == 0 then
      IO.eprintln "no vector used a PRF this implementation has -- nothing was verified"
      return 1
    if !ok then
      IO.eprintln s!"FAILED ({ran} of {vs.size} vectors run)"
      return 1
    IO.println s!"all checks passed ({ran} of {vs.size} vectors run; the rest name PRFs not implemented here)"
    pure 0

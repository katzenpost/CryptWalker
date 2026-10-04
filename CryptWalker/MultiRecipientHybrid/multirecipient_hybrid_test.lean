/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.MultiRecipientHybrid.Schemes
import CryptWalker.Util.newhex

/-! # Multi-recipient hybrid: known-answer tests, against `hpqc`

Checks `hybridMLKEM768X25519Blake2b` against vectors vendored from hpqc
(`testdata/multirecipient_hybrid.json`, hpqc's `kem/mrhybrid` over `"MLKEM768-X25519"`). KEM
encapsulation is randomized on both sides, so for each recipient: build the private key from its
X25519 scalar and ML-KEM-768 `(d, z)`, decapsulate the ciphertext reduced to that recipient
(`forRecipient`), and check the derived key and the payload; then open the reply under recipient
0's derived key. -/

open Lean
open CryptWalker.KEM (kemX25519Blake2b kemMLKEM768X25519Blake2b)
open CryptWalker.MultiRecipientHybrid.MultiRecipientHybrid (Ciphertext)
open CryptWalker.MultiRecipientHybrid.Schemes (hybridMLKEM768X25519Blake2b)
open CryptWalker.Util.newhex
open CryptWalker.Util.Bytes (ofVector toVecN)

def H := hybridMLKEM768X25519Blake2b
def K := kemMLKEM768X25519Blake2b

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

structure Recipient where
  x : ByteArray
  d : ByteArray
  z : ByteArray
  derivedKey : ByteArray
  kemCt : ByteArray
  dek : ByteArray

def parseRecipient (j : Json) : Except String Recipient := do
  pure { x := ← field j "x25519_private_key_hex", d := ← field j "mlkem_d_hex",
         z := ← field j "mlkem_z_hex", derivedKey := ← field j "derived_key_hex",
         kemCt := ← field j "kem_ciphertext_hex", dek := ← field j "dek_hex" }

def runVec (j : Json) : IO Bool := do
  match (do
    let name ← (← j.getObjVal? "name").getStr?
    let rs ← (← (← j.getObjVal? "recipients").getArr?).mapM parseRecipient
    pure (name, rs, ← field j "payload_hex", ← field j "envelope_hex",
      ← field j "reply_plaintext_hex", ← field j "reply_envelope_hex")
      : Except String _) with
  | .error e => do IO.eprintln e; pure false
  | .ok (name, rs, payload, envelope, replyPt, replyEnv) =>
    IO.println s!"  {name} ({rs.size} recipients)"
    if rs.isEmpty then
      IO.println "    FAIL no recipients"
      return false
    let kcs := rs.toList.filterMap fun r =>
      if r.kemCt.size = K.ciphertextSize then K.decodeCiphertext (toVecN _ r.kemCt) else none
    if kcs.length ≠ rs.size then
      IO.println "    FAIL kem ciphertext decode"
      return false
    let ct : Ciphertext H.KEMCiphertext :=
      { kemCiphertexts := kcs, deks := rs.toList.map (·.dek), envelope }
    let mut ok := true
    for i in [0:rs.size] do
      let some r := rs[i]? | return false
      match kemX25519Blake2b.decodePrivateKey (toVecN 32 r.x) with
      | none => IO.println s!"    FAIL recipient {i}: x25519 private key decode"; ok := false
      | some xsk =>
        let sk : H.PrivateKey :=
          show K.PrivateKey from (xsk, ((toVecN 32 r.d, toVecN 32 r.z), PUnit.unit))
        match H.decapsulate sk (ct.forRecipient i) with
        | .ok (k, pt) =>
          ok := (← check s!"recipient {i} derived key" r.derivedKey k) && ok
          ok := (← check s!"recipient {i} payload" payload pt) && ok
        | .error _ => IO.println s!"    FAIL recipient {i}: decapsulate"; ok := false
    let some r0 := rs[0]? | return false
    match H.decryptEnvelope r0.derivedKey replyEnv with
    | .ok pt => ok := (← check "reply" replyPt pt) && ok
    | .error _ => IO.println "    FAIL reply decrypt"; ok := false
    pure ok

def main : IO UInt32 := do
  let path := "testdata/multirecipient_hybrid.json"
  let raw ← IO.FS.readFile path
  match (do
    let j ← Json.parse raw
    let prim ← (← j.getObjVal? "primitive").getStr?
    if prim ≠ "multirecipient_hybrid_mlkem768_x25519" then throw s!"unexpected primitive: {prim}"
    (← j.getObjVal? "vectors").getArr? : Except String _) with
  | .error e => IO.eprintln s!"failed to parse {path}: {e}"; pure 1
  | .ok vs =>
    IO.println s!"Multi-recipient hybrid vectors ({vs.size} from hpqc)"
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

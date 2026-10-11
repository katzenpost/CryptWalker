/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.Hash.Sha512
import CryptWalker.Hash.Blake2b
import CryptWalker.Sign.Ed25519_math
import CryptWalker.Util.newhex

/-! # hpqc primitive vectors BACAP builds on, not checked elsewhere

Reads `testdata/sha512_256.json`, `testdata/blake2b_512.json` and `testdata/ed25519.json`,
vendored from `hpqc/testvectors/primitives/`. SHA-512/256 and BLAKE2b-512 are hashed and compared;
`ed25519.json` records only public keys, messages and signatures, so each signature must verify,
and must stop verifying when one bit of it is flipped. The other primitive files hpqc shares are
read by `Hash.test`, `Hash.hkdf_test`, `Hash.blake2b_256_test`, `Hash.blake2b_xof_test`,
`Cipher.test` and `Sign.blinded_test`. -/

open Lean
open CryptWalker.Util.newhex

def hexBytes (j : Json) (k : String) : Except String ByteArray := do
  let s ← (← j.getObjVal? k).getStr?
  match hexStringToByteArray s with
  | some b => pure b
  | none => throw s!"field {k}: not valid hex"

def toHex {n} (v : Vector UInt8 n) : String := byteArrayToHex ⟨v.toArray⟩

def loadFile (path primitive : String) : IO (Array Json) := do
  let j ← IO.ofExcept (Json.parse (← IO.FS.readFile path))
  let prim ← IO.ofExcept (do (← j.getObjVal? "primitive").getStr?)
  if prim ≠ primitive then throw (IO.userError s!"{path}: unexpected primitive {prim}")
  IO.ofExcept (do (← j.getObjVal? "vectors").getArr?)

def report (ok : Bool) (name : String) : IO Bool := do
  IO.println (if ok then s!"  ok    {name}" else s!"  FAIL  {name}")
  pure ok

def testHash (path primitive : String) (h : ByteArray → String) : IO Bool := do
  let vs ← loadFile path primitive
  IO.println s!"{primitive} ({vs.size} vectors from hpqc)"
  let mut ok := true
  for v in vs do
    let name ← IO.ofExcept (do (← v.getObjVal? "name").getStr?)
    let input ← IO.ofExcept (hexBytes v "input_hex")
    let output ← IO.ofExcept (hexBytes v "output_hex")
    ok := (← report (h input == byteArrayToHex output) name) && ok
  pure ok

def toVec (n : Nat) (b : ByteArray) : Option (Vector UInt8 n) :=
  if h : b.data.size = n then some ⟨b.data, h⟩ else none

def testEd25519 : IO Bool := do
  let vs ← loadFile "testdata/ed25519.json" "ed25519"
  IO.println s!"ed25519 ({vs.size} vectors from hpqc)"
  let mut ok := true
  for v in vs do
    let name ← IO.ofExcept (do (← v.getObjVal? "name").getStr?)
    let msg ← IO.ofExcept (hexBytes v "message_hex")
    let good := match toVec 32 (← IO.ofExcept (hexBytes v "public_key_hex")),
        toVec 64 (← IO.ofExcept (hexBytes v "signature_hex")) with
      | some pk, some sig =>
        let flipped := sig.set 0 (sig[0] ^^^ 1)
        CryptWalker.Sign.Ed25519Math.verifyNative pk msg sig &&
          !CryptWalker.Sign.Ed25519Math.verifyNative pk msg flipped
      | _, _ => false
    ok := (← report good name) && ok
  pure ok

def main : IO UInt32 := do
  let a ← testHash "testdata/sha512_256.json" "sha512_256"
    (fun m => toHex (CryptWalker.Hash.Sha512.sha512_256 m))
  IO.println ""
  let b ← testHash "testdata/blake2b_512.json" "blake2b_512"
    (fun m => toHex (CryptWalker.Hash.Blake2b.hash m))
  IO.println ""
  let c ← testEd25519
  IO.println ""
  if a && b && c then
    IO.println "all primitive vectors passed"
    pure 0
  else
    IO.eprintln "some primitive vectors FAILED"
    pure 1

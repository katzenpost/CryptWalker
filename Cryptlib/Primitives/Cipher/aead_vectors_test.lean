import Lean.Data.Json

import Cryptlib.Primitives.Cipher.AEAD
import Cryptlib.Primitives.Cipher.AESGCM
import Cryptlib.Primitives.Cipher.ChaChaPoly
import Cryptlib.Util.Bytes
import Cryptlib.Util.newhex

open Lean
open Cryptlib.Primitives.Cipher.AEAD
open Cryptlib.Util.Bytes (toVecN)
open Cryptlib.Util.newhex

/-! Wycheproof vectors for the `AEAD` instances, run through the generic interface. Invalid
vectors must fail to decrypt; valid ones must encrypt to the expected ciphertext and tag. -/

def hexField (j : Json) (k : String) : Except String ByteArray := do
  match hexStringToByteArray (← (← j.getObjVal? k).getStr?) with
  | some b => pure b
  | none => throw s!"{k} is not valid hex"

def check (A : AEAD) (j : Json) : Except String Bool := do
  let key ← hexField j "key_hex"
  let n ← hexField j "nonce_hex"
  if key.size ≠ A.keySize ∨ n.size ≠ A.nonceSize then throw "bad sizes"
  let k := A.keyFromBytes (toVecN _ key)
  let nv := toVecN A.nonceSize n
  let ad ← hexField j "ad_hex"
  let pt ← hexField j "pt_hex"
  let ct := (← hexField j "ct_hex") ++ (← hexField j "tag_hex")
  let valid ← (← j.getObjVal? "valid").getBool?
  let opened := A.decrypt k nv ad ct
  if valid then pure (A.encrypt k nv ad pt == ct && opened == some pt)
  else pure opened.isNone

def runFile (A : AEAD) (path : String) : IO Nat := do
  let json ← IO.ofExcept (Json.parse (← IO.FS.readFile path))
  let vs ← IO.ofExcept ((← IO.ofExcept (json.getObjVal? "vectors")).getArr?)
  let mut failed := 0
  for v in vs do
    match check A v with
    | .ok true => pure ()
    | r =>
      failed := failed + 1
      IO.println s!"  FAIL  {A.name} tcId {v.getObjValD "tcId"} {match r with | .error e => e | _ => ""}"
  IO.println s!"{A.name}: {vs.size - failed}/{vs.size} Wycheproof vectors passed"
  pure failed

def main : IO UInt32 := do
  let f1 ← runFile Cryptlib.Primitives.Cipher.ChaChaPoly.Scheme "testdata/chacha20_poly1305.json"
  let f2 ← runFile Cryptlib.Primitives.Cipher.AESGCM.Scheme "testdata/aes256_gcm.json"
  pure (if f1 + f2 == 0 then 0 else 1)

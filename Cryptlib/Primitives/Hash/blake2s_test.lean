import Lean.Data.Json

import Cryptlib.Primitives.Hash.Blake2s
import Cryptlib.Util.newhex

open Lean
open Cryptlib.Primitives.Hash.Blake2s
open Cryptlib.Util.newhex

def hexField (j : Json) (k : String) : Except String ByteArray := do
  match hexStringToByteArray (← (← j.getObjVal? k).getStr?) with
  | some b => pure b
  | none => throw s!"{k} is not valid hex"

def check (j : Json) : Except String Bool := do
  let key ← hexField j "key_hex"
  let msg ← hexField j "msg_hex"
  let got := if key.size = 0 then Cryptlib.Primitives.Hash.Blake2s.hash msg else hashKeyed key msg
  pure (ByteArray.mk got.toArray == (← hexField j "digest_hex"))

def main : IO UInt32 := do
  let json ← IO.ofExcept (Json.parse (← IO.FS.readFile "testdata/blake2s_256.json"))
  let vs ← IO.ofExcept ((← IO.ofExcept (json.getObjVal? "vectors")).getArr?)
  let mut failed := 0
  for v in vs do
    match check v with
    | .ok true => pure ()
    | _ => failed := failed + 1; IO.println s!"  FAIL  {v.getObjValD "name"}"
  IO.println s!"blake2s: {vs.size - failed}/{vs.size} vectors passed"
  pure (if failed == 0 then 0 else 1)

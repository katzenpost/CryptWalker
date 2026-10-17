import Lean.Data.Json

import Cryptlib.Primitives.KDF.Argon2
import Cryptlib.Util.newhex

open Lean
open Cryptlib.Primitives.KDF.Argon2
open Cryptlib.Util.newhex

def hexField (j : Json) (k : String) : Except String ByteArray := do
  match hexStringToByteArray (← (← j.getObjVal? k).getStr?) with
  | some b => pure b
  | none => throw s!"{k} is not valid hex"

def natField (j : Json) (k : String) : Except String Nat := do
  match (← j.getObjVal? k).getNat? with
  | .ok n => pure n
  | .error e => throw e

def variantOf : String → Except String Variant
  | "d" => pure .d
  | "i" => pure .i
  | "id" => pure .id
  | v => throw s!"unknown variant {v}"

def check (j : Json) : Except String Bool := do
  let p : Params := {
    variant := ← variantOf (← (← j.getObjVal? "variant").getStr?)
    parallelism := ← natField j "parallelism"
    tagLength := ← natField j "tag_length"
    memoryKiB := ← natField j "memory_kib"
    passes := ← natField j "passes"
    secret := ← hexField j "secret_hex"
    ad := ← hexField j "ad_hex" }
  let tag ← hash p (← hexField j "password_hex") (← hexField j "salt_hex")
  pure (tag == (← hexField j "tag_hex"))

/-- `hPrime` up to 64 bytes is one BLAKE2b call, so a 48-byte `hashN` must match it. -/
def hashNCheck : Bool :=
  let x := "abc".toUTF8
  -- BLAKE2b-384("abc"), from the BLAKE2 reference implementation.
  hexStringToByteArray "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"
    == some (Cryptlib.Primitives.Hash.Blake2b.hashN 48 x)

def rejects : List (String × Params × ByteArray) := [
  ("short salt", { memoryKiB := 8, passes := 1 }, "short".toUTF8),
  ("too little memory", { memoryKiB := 7, passes := 1 }, "saltsalt".toUTF8),
  ("no passes", { memoryKiB := 8, passes := 0 }, "saltsalt".toUTF8),
  ("short tag", { memoryKiB := 8, passes := 1, tagLength := 3 }, "saltsalt".toUTF8),
  ("no lanes", { memoryKiB := 8, passes := 1, parallelism := 0 }, "saltsalt".toUTF8)]

def main : IO UInt32 := do
  let json ← IO.ofExcept (Json.parse (← IO.FS.readFile "testdata/argon2.json"))
  let vs ← IO.ofExcept ((← IO.ofExcept (json.getObjVal? "vectors")).getArr?)
  let mut failed := 0
  for v in vs do
    match check v with
    | .ok true => IO.println s!"  ok    {(v.getObjValD "name").getStr?.toOption.getD ""}"
    | .ok false => failed := failed + 1; IO.println s!"  FAIL  {(v.getObjValD "name").getStr?.toOption.getD ""}"
    | .error e => failed := failed + 1; IO.println s!"  FAIL  {(v.getObjValD "name").getStr?.toOption.getD ""}: {e}"
  if hashNCheck then IO.println "  ok    blake2b hashN 48" else
    failed := failed + 1; IO.println "  FAIL  blake2b hashN 48"
  for (name, p, salt) in rejects do
    match hash p "pw".toUTF8 salt with
    | .error _ => IO.println s!"  ok    rejects {name}"
    | .ok _ => failed := failed + 1; IO.println s!"  FAIL  rejects {name}"
  IO.println s!"argon2: {vs.size + 1 + rejects.length - failed}/{vs.size + 1 + rejects.length} passed"
  pure (if failed == 0 then 0 else 1)

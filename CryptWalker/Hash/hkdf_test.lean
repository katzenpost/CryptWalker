import Lean.Data.Json

import CryptWalker.Hash.Blake2b
import CryptWalker.Util.newhex

open Lean
open CryptWalker.Hash.Blake2b
open CryptWalker.Util.newhex

structure HKDFVector where
  name : String
  secret : ByteArray
  salt : ByteArray
  info : ByteArray
  length : Nat
  output : ByteArray

def field (json : Json) (name : String) : Except String ByteArray := do
  let value ← (← json.getObjVal? name).getStr?
  match hexStringToByteArray value with
  | some bytes => pure bytes
  | none => throw s!"{name} is not valid hex"

def parseVector (json : Json) : Except String HKDFVector := do
  pure {
    name := ← (← json.getObjVal? "name").getStr?
    secret := ← field json "secret_hex"
    salt := ← field json "salt_hex"
    info := ← field json "info_hex"
    length := (← (← json.getObjVal? "length").getNat?)
    output := ← field json "okm_hex"
  }

def parseFile (contents : String) : Except String (Array HKDFVector) := do
  let json ← Json.parse contents
  let primitive ← (← json.getObjVal? "primitive").getStr?
  if primitive ≠ "hkdf_blake2b" then throw s!"unexpected primitive: {primitive}"
  (← (← json.getObjVal? "vectors").getArr?).mapM parseVector

def unwrap {α : Type} : Except String α → IO α
  | .ok value => pure value
  | .error message => throw (IO.userError message)

def main : IO UInt32 := do
  let path := "testdata/hkdf_blake2b.json"
  let contents ← IO.FS.readFile path
  let vectors ← unwrap (parseFile contents)
  let mut ok := true
  for vector in vectors do
    let got := hkdf vector.secret vector.salt vector.info vector.length
    if got == vector.output then
      IO.println s!"  ok    {vector.name} ({vector.length} bytes)"
    else
      ok := false
      IO.println s!"  FAIL  {vector.name}"
      IO.println s!"        expected {byteArrayToHex vector.output}"
      IO.println s!"        got      {byteArrayToHex got}"
  if ok then
    IO.println s!"all {vectors.size} HKDF-BLAKE2b vectors passed"
    pure 0
  else
    IO.eprintln "HKDF-BLAKE2b vectors FAILED"
    pure 1

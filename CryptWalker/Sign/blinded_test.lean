import Lean
import Lean.Data.Json

import CryptWalker.Hash.Sha512
import CryptWalker.Sign.Ed25519_blinded
import CryptWalker.Sign.Ed25519_math
import CryptWalker.Util.newhex

open Lean
open CryptWalker.Sign.Ed25519Blinded
open CryptWalker.Sign.Ed25519Math
open CryptWalker.Hash.Sha512
open CryptWalker.Util.newhex

private def hexToVec32 (s : String) : Option (Vector UInt8 32) := do
  let bytes ← hexStringToByteArray s
  if h : bytes.data.size = 32 then some ⟨bytes.data, h⟩ else none

private def hexToBytes (s : String) : Option ByteArray :=
  hexStringToByteArray s

private def check (condition : Bool) (message : String) : IO Unit :=
  if condition then pure () else throw (IO.userError message)

private def unwrap {α : Type} : Except String α → IO α
  | .ok value => pure value
  | .error message => throw (IO.userError message)

private structure VectorCase where
  name : String
  privateKey : ByteArray
  message : ByteArray
  factors : Array ByteArray
  publicKey : ByteArray
  signature : ByteArray

private def hexField (json : Json) (name : String) : Except String ByteArray := do
  let value ← (← json.getObjVal? name).getStr?
  match hexStringToByteArray value with
  | some bytes => pure bytes
  | none => throw s!"{name} is not valid hex"

private def parseVector (json : Json) : Except String VectorCase := do
  let factors ← (← (← json.getObjVal? "blind_factors_hex").getArr?).mapM (fun factor => do
    let value ← factor.getStr?
    match hexStringToByteArray value with
    | some bytes => pure bytes
    | none => throw "blind factor is not valid hex")
  pure {
    name := ← (← json.getObjVal? "name").getStr?
    privateKey := ← hexField json "private_key_hex"
    message := ← hexField json "message_hex"
    factors := factors
    publicKey := ← hexField json "blinded_pubkey_hex"
    signature := ← hexField json "blinded_signature_hex"
  }

private def parseVectors (contents : String) : Except String (Array VectorCase) := do
  let json ← Json.parse contents
  let primitive ← (← json.getObjVal? "primitive").getStr?
  if primitive ≠ "blinded_ed25519" then throw s!"unexpected primitive: {primitive}"
  (← (← json.getObjVal? "vectors").getArr?).mapM parseVector

private def vec32 (bytes : ByteArray) : Except String (Vector UInt8 32) :=
  if h : bytes.data.size = 32 then pure ⟨bytes.data, h⟩
  else throw "expected 32 bytes"

private def vec64 (bytes : ByteArray) : Except String (Vector UInt8 64) :=
  if h : bytes.data.size = 64 then pure ⟨bytes.data, h⟩
  else throw "expected 64 bytes"

private def runVector (vector : VectorCase) : IO Unit := do
  let privateSeed : Vector UInt8 32 ← unwrap (vec32 ⟨vector.privateKey.data.extract 0 32⟩)
  let privateScalar := CryptWalker.Sign.Ed25519Blinded.scalarFromSeed privateSeed
  let mut blinded := privateScalar
  for factorBytes in vector.factors do
    blinded := blindPriv blinded (scalarOfBytes factorBytes)
  let gotPublic := publicKey blinded
  let gotSignature := signNative blinded vector.message
  let expectedPublic ← unwrap (vec32 vector.publicKey)
  let expectedSignature ← unwrap (vec64 vector.signature)
  check (gotPublic = expectedPublic) s!"{vector.name}: public-key mismatch"
  check (gotSignature = expectedSignature) s!"{vector.name}: signature mismatch"
  check (CryptWalker.Sign.Ed25519Blinded.verifyNative gotPublic vector.message gotSignature)
    s!"{vector.name}: signature failed verification"
  IO.println s!"hpqc blinded vector passed: {vector.name}"

def main : IO Unit := do
  let contents ← IO.FS.readFile "testdata/blinded_ed25519.json"
  let vectors ← unwrap (parseVectors contents)
  check (byteArrayToHex ⟨(sha512_256 "abc".toUTF8).toArray⟩ =
      "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23")
    "SHA-512/256 abc test vector failed"
  check (byteArrayToHex ⟨(sha512_256 (ByteArray.mk (Array.replicate 32 0))).toArray⟩ =
      "af13c048991224a5e4c664446b688aaf48fb5456db3629601b00ec160c74e554")
    "SHA-512/256 32-byte zero test vector failed"
  for vector in vectors do
    runVector vector
  IO.println "All hpqc blinded Ed25519 tests passed!"

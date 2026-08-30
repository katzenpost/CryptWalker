import Lean

import CryptWalker.Hash.Sha512
import CryptWalker.Sign.Ed25519_math
import CryptWalker.Util.newhex

open CryptWalker.Hash.Sha512
open CryptWalker.Sign.Ed25519Math
open CryptWalker.Util.newhex

private def hexToVec32 (s : String) : Option (Vector UInt8 32) := do
  let bytes ← hexStringToByteArray s
  if h : bytes.data.size = 32 then some ⟨bytes.data, h⟩ else none

private def hexToVec64 (s : String) : Option (Vector UInt8 64) := do
  let bytes ← hexStringToByteArray s
  if h : bytes.data.size = 64 then some ⟨bytes.data, h⟩ else none

private def hexToBytes (s : String) : Option ByteArray :=
  hexStringToByteArray s

private def vecToHex {n : Nat} (v : Vector UInt8 n) : String :=
  byteArrayToHex ⟨v.toArray⟩

private structure Kat where
  seed : String
  message : String
  publicKey : String
  signature : String

private def rfc8032Vectors : List Kat := [
  { seed := "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    message := ""
    publicKey := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    signature :=
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
      ++ "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
  { seed := "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    message := "72"
    publicKey := "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    signature :=
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
      ++ "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" }
]

private def runKat (kat : Kat) : IO Unit := do
  let some seed := hexToVec32 kat.seed | throw (IO.userError "invalid RFC seed")
  let some message := hexToBytes kat.message | throw (IO.userError "invalid RFC message")
  let some expectedPublicKey := hexToVec32 kat.publicKey |
    throw (IO.userError "invalid RFC public key")
  let some expectedSignature := hexToVec64 kat.signature |
    throw (IO.userError "invalid RFC signature")
  let publicKey := publicKey seed
  let signature := signNative seed message
  if !onCurve basepoint then
    throw (IO.userError "Ed25519 basepoint is not on the curve")
  if !onCurve (scalarMul (scalarFromSeed seed) basepoint) then
    throw (IO.userError "Ed25519 public-key scalar multiplication left the curve")
  if publicKey != expectedPublicKey then
    throw (IO.userError s!"public key mismatch: expected {vecToHex expectedPublicKey}, got {vecToHex publicKey}")
  if signature != expectedSignature then
    throw (IO.userError s!"signature mismatch: expected {vecToHex expectedSignature}, got {vecToHex signature}")
  if decodePoint ⟨publicKey.toArray, by simp⟩ |>.isNone then
    throw (IO.userError "generated public key failed to decode")
  if decodePoint ⟨signature.toArray.extract 0 32, by simp⟩ |>.isNone then
    throw (IO.userError "generated R point failed to decode")
  let publicPoint := scalarMul (scalarFromSeed seed) basepoint
  if decodePoint ⟨publicKey.toArray, by simp⟩ != some publicPoint then
    throw (IO.userError "public-key decode changed the generated point")
  let digest := (sha512 (vectorToByteArray seed)).toList
  let nonce := hashNat [⟨(digest.drop 32).toArray⟩, message] % ell
  let rPoint := scalarMul nonce basepoint
  if decodePoint ⟨signature.toArray.extract 0 32, by simp⟩ != some rPoint then
    throw (IO.userError "R decode changed the generated point")
  if !verifyNative publicKey message signature then
    throw (IO.userError "RFC signature did not verify")
  IO.println s!"RFC 8032 KAT passed for message length {message.size}"

def testTampering : IO Unit := do
  let some seed := hexToVec32 "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" |
    throw (IO.userError "invalid tamper-test seed")
  let some message := hexToBytes "" | throw (IO.userError "invalid tamper-test message")
  let publicKey := publicKey seed
  let signature := signNative seed message
  let tampered := signature.set 0 (signature[0]! ^^^ 1)
  if verifyNative publicKey message tampered then
    throw (IO.userError "tampered signature was accepted")
  IO.println "Ed25519 tamper rejection passed"

def main : IO Unit := do
  for kat in rfc8032Vectors do
    runKat kat
  testTampering
  IO.println "All Ed25519 tests passed!"

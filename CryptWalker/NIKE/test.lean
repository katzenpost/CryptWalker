
import Lean
import Mathlib.Data.ByteArray

import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.X25519
import CryptWalker.NIKE.Schemes

open CryptWalker.Util.newhex
open CryptWalker.NIKE.NIKE


instance : BEq ByteArray where
  beq a b := a.data = b.data

def testX25519Vector : IO Unit := do
  let vectors := #[
    ( "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
      "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552" )
  ]
  for (scalarHex, baseHex, expectedHex) in vectors do
    let scalarBytes : ByteArray := (hexStringToByteArray scalarHex).getD ByteArray.empty
    let baseBytes : ByteArray := (hexStringToByteArray baseHex).getD ByteArray.empty
    let expectedBytes : ByteArray := (hexStringToByteArray expectedHex).getD ByteArray.empty
    let result := CryptWalker.NIKE.X25519.curve25519 scalarBytes baseBytes
    if result != expectedBytes then
      panic! s!"Mismatch in KAT: expected {expectedHex}, got {result}"
  IO.println "All vector tests passed for X25519!"

def testNIKE (scheme : NIKE) : IO Unit := do
  let (alicePublicKey, alicePrivateKey) ← scheme.generateKeyPair
  let (bobPublicKey, bobPrivateKey) ← scheme.generateKeyPair
  let bobSharedSecret := scheme.groupAction bobPrivateKey alicePublicKey
  let aliceSharedSecret := scheme.groupAction alicePrivateKey bobPublicKey
  if scheme.encodePublicKey bobSharedSecret == scheme.encodePublicKey aliceSharedSecret then
    IO.println s!"NIKE test for {scheme.name} PASSED."
  else
    panic! s!"NIKE test of {scheme.name} failed!"

def testAllNIKEs (schemes : List NIKE): IO Unit := do
match schemes with
| [] => IO.println "All NIKE tests passed!"
| nike :: rest => do
  testNIKE nike
  testAllNIKEs rest

def main : IO Unit := do
  testX25519Vector
  testAllNIKEs CryptWalker.NIKE.Schemes

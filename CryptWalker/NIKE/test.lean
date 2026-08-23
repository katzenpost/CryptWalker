import Lean

import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.X25519
import CryptWalker.NIKE.Schemes

open CryptWalker.Util.newhex
open CryptWalker.NIKE.NIKE

def hexToVec32 (s : String) : Option (Vector UInt8 32) := do
  let ba ← hexStringToByteArray s
  if h : ba.data.size = 32 then some ⟨ba.data, h⟩ else none

def showVec {n} (v : Vector UInt8 n) : String :=
  String.join (v.toArray.toList.map fun b =>
    let d := String.ofList (Nat.toDigits 16 b.toNat)
    if d.length = 1 then "0" ++ d else d)

def testX25519Vector : IO Unit := do
  let vectors := #[
    ( "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
      "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552" )
  ]
  for (scalarHex, baseHex, expectedHex) in vectors do
    let some scalar := hexToVec32 scalarHex | throw (IO.userError "bad scalar hex")
    let some base   := hexToVec32 baseHex   | throw (IO.userError "bad base hex")
    let got := showVec (CryptWalker.NIKE.X25519.curve25519 scalar base)
    if got ≠ expectedHex then
      throw (IO.userError s!"KAT mismatch: expected {expectedHex}, got {got}")
  IO.println "All vector tests passed for X25519!"

def testNIKE (scheme : NIKE) (aliceSeed bobSeed : Vector UInt8 32) : IO Unit := do
  let aliceSk := scheme.privateKeyFromSeed aliceSeed
  let bobSk   := scheme.privateKeyFromSeed bobSeed
  let alicePk := scheme.derivePublicKey aliceSk
  let bobPk   := scheme.derivePublicKey bobSk
  let bobSS   := scheme.groupAction bobSk   alicePk (scheme.derive_safe aliceSk)
  let aliceSS := scheme.groupAction aliceSk bobPk   (scheme.derive_safe bobSk)
  if scheme.encodeSharedSecret bobSS = scheme.encodeSharedSecret aliceSS then
    IO.println s!"NIKE test for {scheme.name} PASSED."
  else
    throw (IO.userError s!"NIKE test of {scheme.name} failed!")

def testAllNIKEs : List NIKE → IO Unit
  | [] => IO.println "All NIKE tests passed!"
  | nike :: rest => do
      testNIKE nike (Vector.replicate 32 1) (Vector.replicate 32 2)
      testAllNIKEs rest

def main : IO Unit := do
  testX25519Vector
  testAllNIKEs CryptWalker.NIKE.Schemes

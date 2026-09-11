import Lean

import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.X25519_montgomery_ladder
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
    let got := showVec (CryptWalker.NIKE.X25519_montgomery_ladder.x25519 scalar base)
    if got ≠ expectedHex then
      throw (IO.userError s!"KAT mismatch: expected {expectedHex}, got {got}")
  IO.println "All vector tests passed for X25519!"

/-- The same RFC 7748 vector as above, but through the group implementation: lift the
u-coordinate to a curve point, multiply, and project back. This is what distinguishes a correct
group implementation from a merely self-consistent one -- `testNIKE` below would pass even if
every operation returned zero. -/
def testX25519GroupVector : IO Unit := do
  let vectors := #[
    ( "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
      "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552" )
  ]
  for (scalarHex, baseHex, expectedHex) in vectors do
    let some scalar := hexToVec32 scalarHex | throw (IO.userError "bad scalar hex")
    let some base   := hexToVec32 baseHex   | throw (IO.userError "bad base hex")
    match CryptWalker.NIKE.X25519.x25519 scalar base with
    | none => throw (IO.userError "group x25519: u-coordinate not on the curve")
    | some got =>
      if showVec got ≠ expectedHex then
        throw (IO.userError s!"group KAT mismatch: expected {expectedHex}, got {showVec got}")
  IO.println "All vector tests passed for X25519-group!"

/-- Cross-check the two implementations against each other: for the same private key, the group
scheme's point and the ladder's byte string must have the same u-coordinate, and the two must
agree on a full Diffie-Hellman exchange. -/
def testX25519GroupAgreesWithLadder : IO Unit := do
  let seeds := #[Vector.replicate 32 1, Vector.replicate 32 2,
                 Vector.replicate 32 7, Vector.replicate 32 255]
  for seed in seeds do
    let sk : CryptWalker.NIKE.X25519Common.PrivateKey :=
      ⟨CryptWalker.NIKE.X25519Common.clampScalar seed⟩
    let ladderPub := (CryptWalker.NIKE.X25519_montgomery_ladder.derivePub sk).data
    let groupPub := CryptWalker.NIKE.X25519.uBytes
      (CryptWalker.NIKE.X25519.scalarOf sk • CryptWalker.NIKE.X25519.G)
    if showVec ladderPub ≠ showVec groupPub then
      throw (IO.userError
        s!"public key mismatch for seed: ladder {showVec ladderPub} vs group {showVec groupPub}")
  -- A full exchange, computed each way.
  let aSk : CryptWalker.NIKE.X25519Common.PrivateKey :=
    ⟨CryptWalker.NIKE.X25519Common.clampScalar (Vector.replicate 32 3)⟩
  let bSk : CryptWalker.NIKE.X25519Common.PrivateKey :=
    ⟨CryptWalker.NIKE.X25519Common.clampScalar (Vector.replicate 32 5)⟩
  let ladderSS := CryptWalker.NIKE.X25519_montgomery_ladder.curve25519 aSk.data
    (CryptWalker.NIKE.X25519_montgomery_ladder.derivePub bSk).data
  let groupSS := CryptWalker.NIKE.X25519.uBytes
    (CryptWalker.NIKE.X25519.scalarOf aSk •
      (CryptWalker.NIKE.X25519.scalarOf bSk • CryptWalker.NIKE.X25519.G))
  if showVec ladderSS ≠ showVec groupSS then
    throw (IO.userError
      s!"shared secret mismatch: ladder {showVec ladderSS} vs group {showVec groupSS}")
  IO.println "X25519 group and ladder agree on public keys and shared secrets!"

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
  testX25519GroupVector
  testX25519GroupAgreesWithLadder
  testAllNIKEs CryptWalker.NIKE.Schemes

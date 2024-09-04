
import Lean
import Mathlib.Data.ByteArray

import CryptWalker.protocol.merkle_tree
import CryptWalker.nike.nike
import CryptWalker.nike.x25519
import CryptWalker.nike.x41417
import CryptWalker.nike.schemes

import CryptWalker.kem.adapter
import CryptWalker.kem.schemes
import CryptWalker.hash.Sha512
import CryptWalker.util.newhex

open CryptWalker.util.newhex
open CryptWalker.nike.nike

open CryptWalker.kem.adapter
open CryptWalker.kem.schemes
open CryptWalker.kem.kem


instance : BEq ByteArray where
  beq a b := a.data = b.data


-- Merkle hash tree tests

def testUntilSet : IO Unit := do
  let testCases := [
    (0, 10, (0, 10)),   -- Test case when fst is 0
    (1, 10, (1, 10)),   -- Test case when fst is odd
    (4, 16, (1, 4)),    -- Test case when fst is a power of 2
    (6, 24, (3, 12)),   -- Test case when fst is even but not a power of 2
    (15, 45, (15, 45))  -- Test case when fst is odd and doesn't need shifting
  ]

  for (fst, snd, expected) in testCases do
    let result := untilSet fst snd
    if result != expected then
      IO.println s!"Test failed for inputs ({fst}, {snd}). Expected: {expected}, but got: {result}"
    else
      IO.println s!"Test passed for inputs ({fst}, {snd})"

def testMerkleHashTreeInclusionProof : IO Unit := do
  let target := "3"
  let targetByteArray := String.toUTF8 target
  let mht := fromList ByteArray sha256HashByteArraySettings (List.map String.toUTF8 ["0", "1", "2", target, "4", "5", "6"])
  let treeSize := 5
  let leafDigest := sha256HashByteArraySettings.hash1 targetByteArray
  let maybeProof := generateInclusionProof ByteArray leafDigest treeSize mht
  let rootDigest := digest ByteArray treeSize mht
  match maybeProof with
  | none => panic! "not a proof"
  | some proof =>
    let isProofValid := verifyInclusionProof ByteArray sha256HashByteArraySettings leafDigest rootDigest proof
    if isProofValid then
          IO.println "Merkle Hash Tree inclusion proof is correct"
        else
          panic! "inclusion proof is false"


/-Creating a Merkle Hash Tree from a list of elements. O(n log n)-/
def testMerkleHashTreeFromList : IO Unit := do
  let mht := fromList ByteArray sha256HashByteArraySettings (List.map String.toUTF8 ["0", "1", "2"])
  let (treeSize, rootHash) := info ByteArray mht
  if treeSize != 3 then
    panic! "wrong tree size"
  else
    pure ()
  if s!"{rootHash}" != "725d5230db68f557470dc35f1d8865813acd7ebb07ad152774141decbae71327" then
    panic! "root hash mismatch"
  else
    pure ()
  IO.println s!"tree size {treeSize} root hash {rootHash}"

def testAddHashTree : IO Unit := do
  let (size, rootHash) := info _ $ empty ByteArray sha256HashByteArraySettings
  if size != 0 then
    panic! "wrong tree size"
  else
    pure ()
  if s!"{rootHash}" != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" then
    panic! "root hash mismatch"
  else
    pure ()
  IO.println s!"tree size {size} root hash {rootHash}"

def testAddHashTree1 : IO Unit := do
  let (size, rootHash) := info _ $ add _ (String.toUTF8 "1") $ empty ByteArray sha256HashByteArraySettings
  if size != 1 then
    panic! "wrong tree size"
  else
    pure ()
  if s!"{rootHash}" != "2215e8ac4e2b871c2a48189e79738c956c081e23ac2f2415bf77da199dfd920c" then
    panic! "root hash mismatch"
  else
    pure ()
  IO.println s!"tree size {size} root hash {rootHash}"


-- NIKE tests

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
    let result := CryptWalker.nike.x25519.curve25519 baseBytes scalarBytes
    if result != expectedBytes then
      panic! s!"Mismatch in KAT: expected {expectedHex}, got {result}"
  IO.println "All vector tests passed for X25519!"

def testX41417Vector : IO Unit := do
  let vectors := #[
    ( "75477721f3a25f894b1d9601f5cb7b16c9919533c62f549a4a8c4c1bd3efd32d5954cc76a24f0187413e97418d5b15f2714b7197",
      "ce7576439e5505276992c0474f305752361ad87520b220b956b6a104e71faa23c18cc14000186fdd79266718a907112184b8d71c" )
  ]
  for (scalarHex, expectedHex) in vectors do
    let scalarBytes : ByteArray := (hexStringToByteArray scalarHex).getD ByteArray.empty
    let expectedBytes : ByteArray := (hexStringToByteArray expectedHex).getD ByteArray.empty
    let privkey : CryptWalker.nike.x41417.PrivateKey := { data := scalarBytes }
    let pubkey : CryptWalker.nike.x41417.PublicKey := CryptWalker.nike.x41417.derivePublicKey privkey
    let result := pubkey.data
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



-- KEM tests
def testKEM (scheme : KEM) : IO Unit := do
  let (alicePublicKey, alicePrivateKey) ← scheme.generateKeyPair
  let (ct, ss) ← scheme.encapsulate alicePublicKey
  let ss2 := scheme.decapsulate alicePrivateKey ct
  if ss != ss2 then
    panic! "test failed"
  pure ()

def testAllKEMs (schemes : List KEM): IO Unit := do
match schemes with
| [] => IO.println "All KEM tests passed!"
| kem :: rest => do
  testKEM kem
  testAllKEMs rest



/--/
def testSha512 : IO Unit := do
  let sha512KATs := #[
    ("", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
    ("a", "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75")
  ]
  for (input, expectedHex) in sha512KATs do
    let inputBytes := input.toUTF8.toList.foldl (fun acc c => acc.push c) ByteArray.empty
    let output := CryptWalker.hash.Sha2.Sha512.hash inputBytes
    IO.println s!"output {output}"
    let expectedBytes : ByteArray := (hexStringToByteArray expectedHex).getD ByteArray.empty
    if output != expectedBytes then
      panic! s!"Mismatch in KAT: expected {expectedHex}, got {output}"
  pure ()
-/

def main : IO Unit := do
  -- Merkle hash tree tests
  testUntilSet
  testMerkleHashTreeFromList
  testAddHashTree
  testAddHashTree1
  testMerkleHashTreeInclusionProof

-- NIKE tests
  testX25519Vector
  testX41417Vector
  testAllNIKEs CryptWalker.nike.schemes.Schemes

-- KEM tests
  testAllKEMs CryptWalker.kem.schemes.Schemes

-- Hash tests
--  testSha512

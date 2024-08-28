
import Lean
import Mathlib.Data.ByteArray

import CryptWalker.protocol.merkle_tree
import CryptWalker.nike.nike
import CryptWalker.nike.x25519
import CryptWalker.nike.x448
import CryptWalker.nike.x41417
import CryptWalker.kem.adapter
import CryptWalker.kem.schemes
import CryptWalker.util.HList
import CryptWalker.hash.Sha512

open CryptWalker.kem.adapter
open CryptWalker.kem.schemes
open CryptWalker.kem.kem
open CryptWalker.util.HList


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
  let targetByteArray := String.toAsciiByteArray target
  let mht := fromList ByteArray sha256HashByteArraySettings (List.map String.toAsciiByteArray ["0", "1", "2", target, "4", "5", "6"])
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
  let mht := fromList ByteArray sha256HashByteArraySettings (List.map String.toAsciiByteArray ["0", "1", "2"])
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
  let (size, rootHash) := info _ $ add _ (String.toAsciiByteArray "1") $ empty ByteArray sha256HashByteArraySettings
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
  let privateKeyHex := "951c011657648c76090885822284c461e3c84bf66b8842adb438334499922890"
  let publicKeyHex := "f5ea54714e6ebfbce3d9073173261ca4ea50a15066ae33461bae83780cf51c43"
  let privKeyBytes : ByteArray := (hexStringToByteArray privateKeyHex).getD ByteArray.empty
  let pubKey := CryptWalker.nike.x25519.scalarmult privKeyBytes CryptWalker.nike.x25519.basepoint
  let pubKeyBytes := CryptWalker.nike.x25519.fromField pubKey
  let expectedPubBytes := (hexStringToByteArray publicKeyHex).getD ByteArray.empty
  if pubKeyBytes != expectedPubBytes then
    panic! "public key mismatch"

def testX25519 : IO Unit := do
  let scheme := inferInstanceAs (CryptWalker.nike.nike.NIKE CryptWalker.nike.x25519.X25519Scheme)
  let (alicePublicKey, alicePrivateKey) ← scheme.generateKeyPair
  let (bobPublicKey, bobPrivateKey) ← scheme.generateKeyPair

  let bobSharedSecret := scheme.groupAction bobPrivateKey alicePublicKey
  let aliceSharedSecret := scheme.groupAction alicePrivateKey bobPublicKey

  if scheme.encodePublicKey bobSharedSecret == scheme.encodePublicKey aliceSharedSecret then
    IO.println "X25519 shared secrets match!"
  else
    panic! "testX25519 failed!"

def testX448 : IO Unit := do
  let scheme := inferInstanceAs (CryptWalker.nike.nike.NIKE CryptWalker.nike.x448.X448Scheme)
  let (alicePublicKey, alicePrivateKey) ← scheme.generateKeyPair
  let (bobPublicKey, bobPrivateKey) ← scheme.generateKeyPair

  let bobSharedSecret := scheme.groupAction bobPrivateKey alicePublicKey
  let aliceSharedSecret := scheme.groupAction alicePrivateKey bobPublicKey

  if scheme.encodePublicKey bobSharedSecret == scheme.encodePublicKey aliceSharedSecret then
    IO.println "X448 shared secrets match!"
  else
    panic! "testX448 failed!"

def testX448KATs : IO Unit := do
  let vectors := #[
    ( "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
      "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
      "ce3e4ff95a60dc6697da1db1d85e6afbd79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f" ),

    ( "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
      "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
      "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d" )
  ]

  for (scalarHex, baseHex, expectedHex) in vectors do
    let scalarBytes : ByteArray := (hexStringToByteArray scalarHex).getD ByteArray.empty
    let baseBytes : ByteArray := (hexStringToByteArray baseHex).getD ByteArray.empty
    let expectedBytes : ByteArray := (hexStringToByteArray expectedHex).getD ByteArray.empty
    let result := CryptWalker.nike.x448.curve448 scalarBytes baseBytes
    if result != expectedBytes then
      panic! s!"Mismatch in KAT: expected {expectedHex}, got {result}"
  IO.println "All KATs passed for X448!"

def testX41417 : IO Unit := do
  let scheme := inferInstanceAs (CryptWalker.nike.nike.NIKE CryptWalker.nike.x41417.X41417Scheme)
  let (alicePublicKey, alicePrivateKey) ← scheme.generateKeyPair
  let (bobPublicKey, bobPrivateKey) ← scheme.generateKeyPair

  let bobSharedSecret := scheme.groupAction bobPrivateKey alicePublicKey
  let aliceSharedSecret := scheme.groupAction alicePrivateKey bobPublicKey

  if scheme.encodePublicKey bobSharedSecret == scheme.encodePublicKey aliceSharedSecret then
    IO.println "X41417 shared secrets match!"
  else
    panic! "testX41417 failed!"


-- KEM tests

def testKEM {α : Type} [kemInstance : KEM α] (kem : α) : IO Unit := do
  let (alicePublicKey, alicePrivateKey) ← kemInstance.generateKeyPair
  let (ciphertext, bobSharedSecret) ← kemInstance.encapsulate kem alicePublicKey
  let aliceSharedSecret := kemInstance.decapsulate kem alicePrivateKey ciphertext
  if bobSharedSecret == aliceSharedSecret then
    IO.println "Shared secrets match!"
  else
    panic! "KEM test failed!"

def testAllKEMs : List (Σ α : Type, KEM α × α) → IO Unit
| [] => IO.println "All KEM tests passed!"
| ⟨_, _, kem⟩ :: rest => do
  testKEM kem
  testAllKEMs rest


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

def main : IO Unit := do
  -- Merkle hash tree tests
  testUntilSet
  testMerkleHashTreeFromList
  testAddHashTree
  testAddHashTree1
  testMerkleHashTreeInclusionProof

-- NIKE tests
  testX25519Vector
  testX25519
  testX448
  testX41417

-- KEM tests
  testAllKEMs Schemes

-- Hash tests
--  testSha512

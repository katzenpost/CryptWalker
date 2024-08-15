
import Lean
import Mathlib.Data.ByteArray

import CryptWalker.protocol.merkle_tree
import CryptWalker.nike.x25519
import CryptWalker.nike.nike
import CryptWalker.nike.x25519pure


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

def testX25519FFI : IO Unit := do
  let scheme := inferInstanceAs (CryptWalker.nike.nike.NIKE CryptWalker.nike.x25519.X25519Scheme)
  let (alicePublicKey, alicePrivateKey) ← scheme.generateKeyPair
  let (bobPublicKey, bobPrivateKey) ← scheme.generateKeyPair

  let bobSharedSecret := scheme.groupAction bobPrivateKey alicePublicKey
  let aliceSharedSecret := scheme.groupAction alicePrivateKey bobPublicKey

  if scheme.encodePublicKey bobSharedSecret == scheme.encodePublicKey aliceSharedSecret then
    IO.println "shared secrets match!"
  else
    panic! "testX25519 failed!"

def testPureX25519Exchange : IO Unit := do
  let scheme := inferInstanceAs (CryptWalker.nike.nike.NIKE CryptWalker.nike.x25519.X25519Scheme)
  let (alicePublicKey, alicePrivateKey) ← scheme.generateKeyPair

  let mut arr := ByteArray.mkEmpty 32
  for _ in [0:32] do
    let randomByte ← IO.rand 0 255
    arr := arr.push (UInt8.ofNat randomByte)
  let bobPrivateKey := arr
  let bobPublicKey := CryptWalker.nike.x25519pure.scalarmult bobPrivateKey CryptWalker.nike.x25519pure.basepoint
  let bobSS := CryptWalker.nike.x25519pure.scalarmult bobPrivateKey $ CryptWalker.nike.x25519pure.byteArrayToZmod alicePublicKey.data
  let scheme := inferInstanceAs (CryptWalker.nike.nike.NIKE CryptWalker.nike.x25519.X25519Scheme)
  let bobPublicKeyBytes := CryptWalker.nike.x25519pure.zmodToByteArray bobPublicKey
  let bobpubkey := (scheme.decodePublicKey bobPublicKeyBytes).getD CryptWalker.nike.x25519.defaultPublicKey
  let aliceSS := scheme.groupAction alicePrivateKey bobpubkey

  if (CryptWalker.nike.x25519pure.zmodToByteArray bobSS) != aliceSS.data then
    panic! "shared secrets mismatch"

def testPureX25519DerivePubKey : IO Unit := do
  let privateKeyHex := "951c011657648c76090885822284c461e3c84bf66b8842adb438334499922890"
  let publicKeyHex := "f5ea54714e6ebfbce3d9073173261ca4ea50a15066ae33461bae83780cf51c43"
  let privKeyBytes : ByteArray := (hexStringToByteArray privateKeyHex).getD ByteArray.empty
  let pubKey := CryptWalker.nike.x25519pure.scalarmult privKeyBytes CryptWalker.nike.x25519pure.basepoint
  let pubKeyBytes := CryptWalker.nike.x25519pure.zmodToByteArray pubKey
  let expectedPubBytes := (hexStringToByteArray publicKeyHex).getD ByteArray.empty
  if pubKeyBytes != expectedPubBytes then
    panic! "public key mismatch"

def testPureX25519BasepointDecode : IO Unit := do
  let basepoint := CryptWalker.nike.x25519pure.basepoint
  let basepoint2hex := "0900000000000000000000000000000000000000000000000000000000000000"
  let basepoint2bytes := (hexStringToByteArray basepoint2hex).getD ByteArray.empty
  let basepoint2 := CryptWalker.nike.x25519pure.byteArrayToZmod basepoint2bytes
  if basepoint.val != basepoint2.val then
    panic! "incorrectly decoded basepoint"
  let basepoint3bytes := CryptWalker.nike.x25519pure.zmodToByteArray basepoint
  IO.println s!"expected hex {basepoint2bytes}"
  IO.println s!"computed hex {basepoint3bytes}"
  if basepoint2bytes != basepoint2bytes then
    panic! "basepoint decoding to hex failure"

def testX25519 : IO Unit := do
  let scheme := inferInstanceAs (CryptWalker.nike.nike.NIKE CryptWalker.nike.x25519pure.X25519Scheme)
  let (alicePublicKey, alicePrivateKey) ← scheme.generateKeyPair
  let (bobPublicKey, bobPrivateKey) ← scheme.generateKeyPair

  let bobSharedSecret := scheme.groupAction bobPrivateKey alicePublicKey
  let aliceSharedSecret := scheme.groupAction alicePrivateKey bobPublicKey

  if scheme.encodePublicKey bobSharedSecret == scheme.encodePublicKey aliceSharedSecret then
    IO.println "shared secrets match!"
  else
    panic! "testX25519 failed!"


def main : IO Unit := do
  testUntilSet
  testMerkleHashTreeFromList
  testAddHashTree
  testAddHashTree1
  testMerkleHashTreeInclusionProof
  testX25519FFI
  testPureX25519BasepointDecode
  testPureX25519DerivePubKey
  testX25519


/-
def runX25519Benchmarks : IO Unit := do
  let scheme := inferInstanceAs (CryptWalker.nike.nike.NIKE CryptWalker.nike.x25519pure.X25519Scheme)
  let (alicePublicKey, alicePrivateKey) ← scheme.generateKeyPair
  let (bobPublicKey, bobPrivateKey) ← scheme.generateKeyPair

  let bobSharedSecret := scheme.groupAction bobPrivateKey alicePublicKey
  let mut i := 0
  while i < 10000 do
    let _ := scheme.groupAction alicePrivateKey bobPublicKey
    i := i + 1

  let aliceSharedSecret := scheme.groupAction alicePrivateKey bobPublicKey
  if scheme.encodePublicKey bobSharedSecret == scheme.encodePublicKey aliceSharedSecret then
    IO.println "shared secrets match!"
  else
    panic! "testX25519 failed!"


def main : IO Unit := do
  runX25519Benchmarks
-/

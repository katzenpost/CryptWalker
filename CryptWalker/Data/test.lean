
import Mathlib.Data.ByteArray
import CryptWalker.Data.MerkleHashTree
import CryptWalker.Util.newhex

open CryptWalker.Util.newhex
open CryptWalker.Data.MerkleHashTree

instance : BEq ByteArray where
  beq a b := a.data = b.data


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


def main : IO Unit := do
  testUntilSet
  testMerkleHashTreeFromList
  testAddHashTree
  testAddHashTree1
  testMerkleHashTreeInclusionProof


import Lean
import Mathlib.Data.ByteArray

import CryptWalker.protocol.merkle_tree


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

/--
def testMerkleHashTreeInclusionProof : IO Unit := do
  let target := String.toAsciiByteArray "Euoplocephalus"
  IO.println s!"target input value --> {target}"
  let dinosaurs := [
    String.toAsciiByteArray "Stegosaurus",
    String.toAsciiByteArray "Apatosaurus",
    target,
    String.toAsciiByteArray "Deinocheirus",
    String.toAsciiByteArray "Chasmosaurus"
  ]
  let mht := fromList ByteArray sha256HashByteArraySettings dinosaurs
  let (treeSize, maybeRootHash) := info ByteArray mht
  match currentHead ByteArray mht with
    | none => panic! "wtf1"
    | some rootTree =>
      let treeHex : String := reprIndented rootTree "    " false
      IO.println s!"mht\n{treeHex}"

  let leafDigest := sha256HashByteArraySettings.hash1 target

  IO.println s!"target leafDigest {leafDigest}"

  match genarateInclusionProof ByteArray leafDigest treeSize mht with
    | none => panic! "wtf2"
    | some proof =>
      IO.println s!"inclusion proof {proof}"
      match maybeRootHash with
      | none => panic! "wtf3"
      | some rootHash =>
        let isProved ← verifyInclusionProof ByteArray sha256HashByteArraySettings leafDigest rootHash proof
        if isProved then
          IO.println "tree proof true"
        else
          IO.println "tree proof false"
-/

def testMerkleHashTreeBasic : IO Unit := do
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


def main : IO Unit := do
  testUntilSet
  testMerkleHashTreeBasic

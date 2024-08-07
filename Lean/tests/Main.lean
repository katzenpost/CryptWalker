import CryptWalker
import Lean
import Mathlib.Data.ByteArray


def main : IO Unit := do
  let target := String.toAsciiByteArray "Euoplocephalus"
  IO.println s!"target input value --> {target}"
  let dinosaurs := [
    String.toAsciiByteArray "Stegosaurus",
    String.toAsciiByteArray "Apatosaurus",
    target,
    String.toAsciiByteArray "Deinocheirus",
    String.toAsciiByteArray "Chasmosaurus"
  ]
  let mht := fromList ByteArray defaultByteArraySettings dinosaurs
  let (treeSize, maybeRootHash) := info ByteArray mht
  match currentHead ByteArray mht with
    | none => panic! "wtf1"
    | some rootTree =>
      let treeHex : String := reprIndented rootTree "    " false
      IO.println s!"mht\n{treeHex}"

  --let rootHash := digest ByteArray treeSize mht
  let leafDigest := defaultByteArraySettings.hash1 target

  IO.println s!"target leafDigest {leafDigest}"

  match genarateInclusionProof ByteArray leafDigest treeSize mht with
    | none => panic! "wtf2"
    | some proof =>
      IO.println s!"inclusion proof {proof}"
      match maybeRootHash with
      | none => panic! "wtf3"
      | some rootHash =>
        let isProved ← verifyInclusionProof ByteArray defaultByteArraySettings leafDigest rootHash proof
        if isProved then
          IO.println "tree proof true"
        else
          IO.println "tree proof false"

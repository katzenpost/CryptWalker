import CryptWalker
import Lean
import Mathlib.Data.ByteArray


def main : IO Unit := do
  let target := String.toAsciiByteArray "Euoplocephalus"
  let targetHex := byteArrayToHex target
  IO.println s!"target hex is {targetHex}"
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
    | none => panic! "wtf"
    | some rootTree =>
      let treeHex : String := reprIndented rootTree "    " false
      IO.println s!"mht\n{treeHex}"

  --let rootHash := digest ByteArray treeSize mht
  let leafDigest := defaultByteArraySettings.hash1 target

  match genarateInclusionProof ByteArray leafDigest treeSize mht with
    | none => panic! "wtf"
    | some proof =>
      match maybeRootHash with
      | none => panic! "wtf2"
      | some rootHash =>
        if verifyInclusionProof ByteArray defaultByteArraySettings leafDigest rootHash proof then
          IO.println "tree proof true"
        else
          IO.println "tree proof false"

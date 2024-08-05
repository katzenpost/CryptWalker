import CryptWalker
import Lean
import Mathlib.Data.ByteArray


def main : IO Unit := do
  let target := String.toAsciiByteArray "Euoplocephalus"
  let dinosaurs := [
    String.toAsciiByteArray "Stegosaurus",
    String.toAsciiByteArray "Apatosaurus",
    target,
    String.toAsciiByteArray "Deinocheirus",
    String.toAsciiByteArray "Chasmosaurus"
  ]
  let mht := fromList ByteArray defaultByteArraySettings dinosaurs
  let (treeSize, _) := info ByteArray mht
  IO.println s!"treeSize {treeSize}"

  let rootHash := digest ByteArray treeSize mht
  let leafDigest := defaultByteArraySettings.hash1 target

  match genarateInclusionProof ByteArray leafDigest treeSize mht with
    | none => panic! "wtf"
    | some proof =>
      let isProof := verifyInclusionProof ByteArray defaultByteArraySettings leafDigest rootHash proof
      if isProof then
        IO.println "tree proof true"
      else
        IO.println "tree proof false"

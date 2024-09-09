
import Mathlib.Data.ByteArray
import CryptWalker.Hash.Sha512
import CryptWalker.Hash.Sha2
import CryptWalker.Util.newhex

open CryptWalker.Util.newhex
open CryptWalker.Hash.Sha2.Sha512


instance : BEq ByteArray where
  beq a b := a.data = b.data


def testSha512 : IO Unit := do
  let sha512KATs := #[
    ("", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
    ("a", "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75")
  ]
  for (input, expectedHex) in sha512KATs do
    let inputBytes := input.toUTF8.toList.foldl (fun acc c => acc.push c) ByteArray.empty
    let output := CryptWalker.Hash.Sha2.Sha512.hash inputBytes
    IO.println s!"output {output}"
    let expectedBytes : ByteArray := (hexStringToByteArray expectedHex).getD ByteArray.empty
    if output != expectedBytes then
      panic! s!"Mismatch in KAT: expected {expectedHex}, got {output}"
  pure ()

def main : IO Unit := do
  testSha512

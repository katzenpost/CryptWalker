import CryptWalker
import Lean
import Mathlib.Data.ByteArray


def main : IO Unit := do
  let b := natToBytes 222211555
  IO.println s!"b {b}"
  let a := ByteArray.mk #[0x00] ++ ByteArray.mk #[0x01]
  IO.println s!"string a is {a}"
  let _ ← hello
  let result := addFromRust1 1 2
  if result == 3 then
    IO.println "Test passed"
  else
    IO.println s!"Test failed: expected 3, got {result}"

  let a := (10 : Nat)
  let b := (20 : Nat)
  let pair := createNatPair a b
  let (xa, xb) := pair
  IO.println s!"Created pair: {pair} has {xa} and {xb}"

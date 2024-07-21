import CryptWalker
import Lean

def main : IO Unit := do
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

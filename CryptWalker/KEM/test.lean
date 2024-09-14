
import Mathlib.Data.ByteArray

import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.X25519

import CryptWalker.KEM.Adapter
import CryptWalker.KEM.Schemes

open CryptWalker.Util.newhex
open CryptWalker.NIKE
open CryptWalker.KEM.Adapter
open CryptWalker.KEM
open CryptWalker.KEM.KEM

instance : BEq ByteArray where
  beq a b := a.data = b.data

def testKEM (scheme : KEM) : IO Unit := do
  IO.println s!"Testing KEM {scheme.name}"
  let (alicePublicKey, alicePrivateKey) ← scheme.generateKeyPair
  let (ct, ss) ← scheme.encapsulate alicePublicKey
  let ss2 := scheme.decapsulate alicePrivateKey ct
  if ss != ss2 then
    panic! "test failed"
  pure ()

def testAllKEMs (schemes : List KEM): IO Unit := do
match schemes with
| [] => IO.println "All KEM tests passed!"
| kem :: rest => do
  testKEM kem
  testAllKEMs rest

def main : IO Unit := do
  testAllKEMs Schemes

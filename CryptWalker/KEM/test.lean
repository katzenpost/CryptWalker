
import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.X25519
import CryptWalker.KEM.KEM
import CryptWalker.KEM.Adapter
import CryptWalker.KEM.Schemes

open CryptWalker.KEM
open CryptWalker.KEM.KEM
open CryptWalker.KEM.Adapter

def kemRoundTrip (k : KEM) : EStateM KEMError k.State Bool :=
  haveI := k.plaintextEq
  do
    let ⟨pk, sk, _⟩ ← k.generate
    let (c, p) ← k.encap pk
    let p' ← k.decap sk c
    pure (decide (p' = p))

def testKEM (name : String) (k : KEM) (s : k.State) : IO Unit := do
  IO.println s!"Testing KEM {name}"
  match kemRoundTrip k s with
  | .ok true  _ => IO.println "  round trip ok"
  | .ok false _ => throw (IO.userError "round trip produced mismatched secrets")
  | .error .badCiphertext   _ => throw (IO.userError "round trip failed: bad ciphertext")
  | .error .unsafePublicKey _ => throw (IO.userError "round trip failed: unsafe public key")

def main : IO Unit := do
  let seed ← (Vector.range 32).mapM fun _ => do
    let b ← IO.rand 0 255
    pure (UInt8.ofNat b)
  -- A constant stream would make the ephemeral key equal the static key, so the
  -- round trip would pass without ever exercising a real two-party exchange.
  let str : Nat → Vector UInt8 32 := fun i =>
    sha256V (Adapter.toBytes seed ++ ⟨#[i.toUInt8]⟩)
  testKEM "X25519" kemX25519 (initWith str)

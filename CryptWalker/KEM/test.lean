
import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.X25519_montgomery_ladder
import CryptWalker.KEM.KEM
import CryptWalker.KEM.Adapter
import CryptWalker.KEM.Schemes

open CryptWalker.KEM
open CryptWalker.KEM.KEM
open CryptWalker.KEM.Adapter

/-- Separate seeds for keys and encapsulation, so ephemeral and static keys differ. -/
def kemRoundTrip (k : KEM) (keySeed encapSeed : Vector UInt8 32) : Except KEMError Bool :=
  haveI := k.plaintextEq
  match k.generate (k.stateFromSeed keySeed) with
  | .error e _ => .error e
  | .ok ⟨pk, sk, _⟩ _ =>
    match k.encap pk (k.stateFromSeed encapSeed) with
    | .error e _ => .error e
    | .ok (c, p) _ =>
      match k.decap sk c (k.stateFromSeed encapSeed) with
      | .error e _ => .error e
      | .ok p' _ => .ok (decide (p' = p))

def randomSeed : IO (Vector UInt8 32) :=
  (Vector.range 32).mapM fun _ => do pure (UInt8.ofNat (← IO.rand 0 255))

/-- Every scheme in the KEM registry must round-trip. -/
def main : IO Unit := do
  for entry in registry do
    IO.println s!"Testing KEM {entry.name}"
    match kemRoundTrip entry.scheme (← randomSeed) (← randomSeed) with
    | .ok true => IO.println "  round trip ok"
    | .ok false => throw (IO.userError s!"{entry.name}: round trip produced mismatched secrets")
    | .error .badCiphertext => throw (IO.userError s!"{entry.name}: bad ciphertext")
    | .error .unsafePublicKey => throw (IO.userError s!"{entry.name}: unsafe public key")

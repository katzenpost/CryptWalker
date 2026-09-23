import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.X25519_montgomery_ladder
import CryptWalker.NIKE.X25519
import CryptWalker.NIKE.X25519Common
import CryptWalker.NIKE.Schemes
import CryptWalker.Util.newnat
import CryptWalker.Util.newhex

import LeanBench

open CryptWalker.Util.newhex
open CryptWalker.NIKE.NIKE
open CryptWalker.NIKE.X25519_montgomery_ladder
open CryptWalker.NIKE.X25519Common

def genkey : IO (Vector UInt8 keySize) := do
  let mut arr : Array UInt8 := Array.emptyWithCapacity keySize
  for _ in [0:keySize] do
    let randomByte ← IO.rand 0 255
    arr := arr.push (UInt8.ofNat randomByte)
  if h : arr.size = keySize then
    pure ⟨arr, h⟩
  else
    throw (IO.userError "genkey produced wrong length")

def benchConfig : LeanBench.BenchConfig := { suite := some "nike", samples := 1000, warmup := 10 }

/-- A fresh private key is drawn before each sample, outside the timed region; only `f` is timed. -/
def ecdhBench {α : Type} (name : String) (f : Vector UInt8 keySize → Vector UInt8 keySize → α) :
    IO LeanBench.Bench := do
  let pubkey := fromField (scalarmult (← genkey) basepoint)
  let sk ← IO.mkRef (← genkey)
  let out ← IO.mkRef (none : Option α)
  pure {
    name
    config := benchConfig
    beforeEach? := some (do sk.set (← genkey))
    action := do out.set (some (f (← sk.get) pubkey))
  }

def main (args : List String) : IO UInt32 := do
  -- The ladder implementation (`X25519_montgomery_ladder.curve25519`).
  LeanBench.register (← ecdhBench "benchmarkCurve25519ECDH_Ladder" curve25519)
  -- The group implementation (`X25519.x25519`), same RFC 7748 signature as the ladder's
  -- `curve25519`, so the two are directly comparable.
  LeanBench.register (← ecdhBench "benchmarkCurve25519ECDH_Group" CryptWalker.NIKE.X25519.x25519)
  LeanBench.runMain args

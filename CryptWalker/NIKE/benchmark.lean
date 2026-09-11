import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.X25519_montgomery_ladder
import CryptWalker.NIKE.X25519
import CryptWalker.NIKE.X25519Common
import CryptWalker.NIKE.Schemes
import CryptWalker.Util.newnat
import CryptWalker.Util.newhex

import Bench
open Bench

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

/-- The ladder implementation (`X25519_montgomery_ladder.curve25519`). -/
def benchmarkCurve25519ECDH_Ladder : IO Unit := do
  let mut b := Bench.new

  let privkey ← genkey
  let pubkey := fromField (scalarmult privkey basepoint)
  let mut privkeys : List (Vector UInt8 keySize) := []

  for _ in (List.range b.N) do
    let key ← genkey
    privkeys := privkeys ++ [key]

  let mut results := Array.replicate 1000 (Vector.replicate keySize (0 : UInt8))
  let mut i := 0
  for sk in privkeys do
    b ← b.start
    let result := curve25519 sk pubkey
    b ← b.stop
    results := results.set! i result
    i := i + 1

  b.report "benchmarkCurve25519ECDH_Ladder"

/-- The group implementation (`X25519.x25519`), same RFC 7748 signature as the ladder's
`curve25519`, so the two are directly comparable. -/
def benchmarkCurve25519ECDH_Group : IO Unit := do
  let mut b := Bench.new

  let privkey ← genkey
  let pubkey := fromField (scalarmult privkey basepoint)
  let mut privkeys : List (Vector UInt8 keySize) := []

  for _ in (List.range b.N) do
    let key ← genkey
    privkeys := privkeys ++ [key]

  let mut results := Array.replicate 1000 (none : Option (Vector UInt8 keySize))
  let mut i := 0
  for sk in privkeys do
    b ← b.start
    let result := CryptWalker.NIKE.X25519.x25519 sk pubkey
    b ← b.stop
    results := results.set! i result
    i := i + 1

  b.report "benchmarkCurve25519ECDH_Group"

def main : IO Unit := do
  benchmarkCurve25519ECDH_Ladder
  benchmarkCurve25519ECDH_Group

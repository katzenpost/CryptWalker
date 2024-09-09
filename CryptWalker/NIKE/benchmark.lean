
import Lean
import Mathlib.Data.ByteArray

import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.X25519
import CryptWalker.NIKE.Schemes
import CryptWalker.Util.newnat
import CryptWalker.Util.newhex

open CryptWalker.Util.newhex
open CryptWalker.NIKE.NIKE
open CryptWalker.NIKE.X25519

instance : BEq ByteArray where
  beq a b := a.data = b.data


def genkey : IO ByteArray := do
  let mut arr := ByteArray.mkEmpty keySize
  for _ in [0:keySize] do
    let randomByte ← IO.rand 0 255
    arr := arr.push (UInt8.ofNat randomByte)
  pure arr


def benchmarkCurve25519ECDH : IO Unit := do
  let privkey : ByteArray ← genkey
  let pubkey := fromField $ (scalarmult privkey basepoint)
  let mut privkeys : List ByteArray := []
  for _ in (List.range 1000) do
    let key ← genkey
    privkeys := privkeys ++ [key]

  let mut startTime := 0
  let mut endTime := 0
  let mut elapsed := 0

  startTime ← IO.monoNanosNow

  let mut results := []

  for sk in privkeys do
    let result := curve25519 sk pubkey
    results := results ++ [result]

  endTime ← IO.monoNanosNow
  elapsed := (endTime - startTime).toFloat
  let count := privkeys.length
  let average := elapsed / count.toFloat
  IO.println s!"count: {privkeys.length} elapsed: {elapsed} ns average {average} ns"

  pure ()


def main : IO Unit := do
  benchmarkCurve25519ECDH

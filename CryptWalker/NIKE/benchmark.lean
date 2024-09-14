import Mathlib.Data.ByteArray

import CryptWalker.NIKE.NIKE
import CryptWalker.NIKE.X25519
import CryptWalker.NIKE.Schemes
import CryptWalker.Util.newnat
import CryptWalker.Util.newhex

import Bench
open Bench

open CryptWalker.Util.newhex
open CryptWalker.NIKE.NIKE
open CryptWalker.NIKE.X25519

def genkey : IO ByteArray := do
  let mut arr := ByteArray.mkEmpty keySize
  for _ in [0:keySize] do
    let randomByte ← IO.rand 0 255
    arr := arr.push (UInt8.ofNat randomByte)
  pure arr


def benchmarkCurve25519ECDH : IO Unit := do
  let mut b := Bench.new

  let privkey : ByteArray ← genkey
  let pubkey := fromField $ (scalarmult privkey basepoint)
  let mut privkeys : List ByteArray := []

  -- create b.N number of test cases
  for _ in (List.range b.N) do
    let key ← genkey
    privkeys := privkeys ++ [key]

  let mut results :=  Array.mkArray 1000 ByteArray.empty
  let mut i := 0
  for sk in privkeys do
    b ← b.start
    let result := curve25519 sk pubkey
    b ← b.stop
    results := results.set! i result
    i := i + 1

  b.report "benchmarkCurve25519ECDH"
  pure ()


def main : IO Unit := do
  benchmarkCurve25519ECDH

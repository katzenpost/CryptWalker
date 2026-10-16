/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Hash.Blake2b

namespace CryptWalker.KDF.Argon2

/-! # Argon2 (RFC 9106), version 0x13

Argon2d, Argon2i and Argon2id, the memory-hard password hash. RFC 9106 recommends Argon2id.

Memory is one `ByteArray` of 1 KiB blocks, block `j` of lane `l` at `l * laneLength + j`. Words
are 64-bit little-endian and are loaded into locals for the permutation, since an `Array UInt64`
would box every word. Lanes are filled one after another: within a slice no lane reads another
lane's current segment, so the order does not change the result. -/

open CryptWalker.Hash

inductive Variant
  | d
  | i
  | id
  deriving Repr, BEq, DecidableEq

/-- The type field `y` of RFC 9106 §3.2. -/
def Variant.code : Variant → Nat
  | .d => 0
  | .i => 1
  | .id => 2

structure Params where
  variant : Variant := .id
  /-- `p`, the number of lanes. -/
  parallelism : Nat := 1
  /-- `T`, the tag length in bytes. -/
  tagLength : Nat := 32
  /-- `m`, the memory size in KiB. -/
  memoryKiB : Nat
  /-- `t`, the number of passes. -/
  passes : Nat
  /-- `K`, the optional secret. -/
  secret : ByteArray := .empty
  /-- `X`, the optional associated data. -/
  ad : ByteArray := .empty

def version : Nat := 0x13

private def blockSize : Nat := 1024

private def le32 (x : Nat) : ByteArray :=
  ⟨#[x.toUInt8, (x >>> 8).toUInt8, (x >>> 16).toUInt8, (x >>> 24).toUInt8]⟩

private def lenPrefixed (b : ByteArray) : ByteArray := le32 b.size ++ b

private def zeros (n : Nat) : ByteArray := ⟨Array.replicate n 0⟩

/-- RFC 9106 §3.3: the variable-length hash H'^T. -/
def hPrime (t : Nat) (x : ByteArray) : ByteArray :=
  let x := le32 t ++ x
  if t ≤ 64 then Blake2b.hashN t x
  else
    let r := (t + 31) / 32 - 2
    let rec go : Nat → ByteArray → ByteArray → ByteArray
      | 0, v, out => out ++ v.extract 0 32 ++ Blake2b.hashN (t - 32 * r) v
      | n + 1, v, out =>
        let v' := Blake2b.hashN 64 v
        go n v' (out ++ v.extract 0 32)
    let v1 := Blake2b.hashN 64 x
    go (r - 1) v1 ByteArray.empty

@[inline] private def ld (b : ByteArray) (w : Nat) : UInt64 :=
  let o := 8 * w
  (b.get! o).toUInt64 ||| ((b.get! (o + 1)).toUInt64 <<< 8) |||
    ((b.get! (o + 2)).toUInt64 <<< 16) ||| ((b.get! (o + 3)).toUInt64 <<< 24) |||
    ((b.get! (o + 4)).toUInt64 <<< 32) ||| ((b.get! (o + 5)).toUInt64 <<< 40) |||
    ((b.get! (o + 6)).toUInt64 <<< 48) ||| ((b.get! (o + 7)).toUInt64 <<< 56)

@[inline] private def st (b : ByteArray) (w : Nat) (x : UInt64) : ByteArray :=
  let o := 8 * w
  b.set! o x.toUInt8 |>.set! (o + 1) (x >>> 8).toUInt8 |>.set! (o + 2) (x >>> 16).toUInt8
    |>.set! (o + 3) (x >>> 24).toUInt8 |>.set! (o + 4) (x >>> 32).toUInt8
    |>.set! (o + 5) (x >>> 40).toUInt8 |>.set! (o + 6) (x >>> 48).toUInt8
    |>.set! (o + 7) (x >>> 56).toUInt8

@[inline] private def rotr (x : UInt64) (n : UInt64) : UInt64 := (x >>> n) ||| (x <<< (64 - n))

/-- BlaMka's multiplication-hardened addition, `a + b + 2 · lo32(a) · lo32(b)`. -/
@[inline] private def fBlaMka (a b : UInt64) : UInt64 :=
  a + b + 2 * (a &&& 0xFFFFFFFF) * (b &&& 0xFFFFFFFF)

/-- RFC 9106 §3.6: the mixing function GB. -/
@[inline] private def gb (a b c d : UInt64) : UInt64 × UInt64 × UInt64 × UInt64 :=
  let a := fBlaMka a b
  let d := rotr (d ^^^ a) 32
  let c := fBlaMka c d
  let b := rotr (b ^^^ c) 24
  let a := fBlaMka a b
  let d := rotr (d ^^^ a) 16
  let c := fBlaMka c d
  let b := rotr (b ^^^ c) 63
  (a, b, c, d)

/-- RFC 9106 §3.6: the permutation P on 16 words of `r`, in place. Word `k` is at
`base + (k / 2) * step + k % 2`: `step = 2` walks a row, `step = 16` a column. -/
private def perm (r : ByteArray) (base step : Nat) : ByteArray :=
  let ix (k : Nat) := base + (k / 2) * step + k % 2
  let v0 := ld r (ix 0); let v1 := ld r (ix 1); let v2 := ld r (ix 2); let v3 := ld r (ix 3)
  let v4 := ld r (ix 4); let v5 := ld r (ix 5); let v6 := ld r (ix 6); let v7 := ld r (ix 7)
  let v8 := ld r (ix 8); let v9 := ld r (ix 9); let v10 := ld r (ix 10); let v11 := ld r (ix 11)
  let v12 := ld r (ix 12); let v13 := ld r (ix 13); let v14 := ld r (ix 14)
  let v15 := ld r (ix 15)
  let (v0, v4, v8, v12) := gb v0 v4 v8 v12
  let (v1, v5, v9, v13) := gb v1 v5 v9 v13
  let (v2, v6, v10, v14) := gb v2 v6 v10 v14
  let (v3, v7, v11, v15) := gb v3 v7 v11 v15
  let (v0, v5, v10, v15) := gb v0 v5 v10 v15
  let (v1, v6, v11, v12) := gb v1 v6 v11 v12
  let (v2, v7, v8, v13) := gb v2 v7 v8 v13
  let (v3, v4, v9, v14) := gb v3 v4 v9 v14
  st r (ix 0) v0 |> (st · (ix 1) v1) |> (st · (ix 2) v2) |> (st · (ix 3) v3)
    |> (st · (ix 4) v4) |> (st · (ix 5) v5) |> (st · (ix 6) v6) |> (st · (ix 7) v7)
    |> (st · (ix 8) v8) |> (st · (ix 9) v9) |> (st · (ix 10) v10) |> (st · (ix 11) v11)
    |> (st · (ix 12) v12) |> (st · (ix 13) v13) |> (st · (ix 14) v14) |> (st · (ix 15) v15)

/-- XOR the block at byte offset `sOff` of `src` into the block at `dOff` of `dst`. -/
private def xorBlock (dst : ByteArray) (dOff : Nat) (src : ByteArray) (sOff : Nat) :
    ByteArray := Id.run do
  let mut d := dst
  for k in [0:blockSize] do
    d := d.set! (dOff + k) (d.get! (dOff + k) ^^^ src.get! (sOff + k))
  return d

/-- RFC 9106 §3.5, given `R = X ⊕ Y`: P on each row, then on each column, XORed with `R`. -/
private def compressR (r : ByteArray) : ByteArray := Id.run do
  let mut q := r.extract 0 blockSize
  for i in [0:8] do q := perm q (16 * i) 2
  for i in [0:8] do q := perm q (2 * i) 16
  return xorBlock q 0 r 0

/-- `G(0, G(0, input))`, the next block of pseudo-random addresses (§3.4.1.2). -/
private def addresses (input : ByteArray) : ByteArray := compressR (compressR input)

/-- The input block for address generation, with counter `ctr` (§3.4.1.2). -/
private def addressInput (pass lane slice mPrime passes y ctr : Nat) : ByteArray :=
  let words := #[pass, lane, slice, mPrime, passes, y, ctr]
  (List.range words.size).foldl (fun b k => st b k (words[k]!).toUInt64) (zeros blockSize)

/-- RFC 9106 §3.4.2: map `j1` to a block index in the reference lane. -/
private def refIndex (pass slice index laneLength segLength : Nat) (sameLane : Bool) (j1 : Nat) :
    Nat :=
  let area :=
    if pass = 0 then
      if slice = 0 then index - 1
      else if sameLane then slice * segLength + index - 1
      else if index = 0 then slice * segLength - 1 else slice * segLength
    else
      if sameLane then laneLength - segLength + index - 1
      else if index = 0 then laneLength - segLength - 1 else laneLength - segLength
  let x := (j1 * j1) >>> 32
  let rel := area - 1 - ((area * x) >>> 32)
  let start := if pass = 0 ∨ slice = 3 then 0 else (slice + 1) * segLength
  (start + rel) % laneLength

/-- Fill one segment of one lane (§3.4). -/
private def fillSegment (mem : ByteArray) (p : Params) (pass slice lane mPrime : Nat) :
    ByteArray := Id.run do
  let lanes := p.parallelism
  let laneLength := mPrime / lanes
  let segLength := laneLength / 4
  let independent := p.variant == .i || (p.variant == .id && pass = 0 && slice < 2)
  let start := if pass = 0 && slice = 0 then 2 else 0
  let mut mem := mem
  let mut addr := ByteArray.empty
  let mut ctr := 0
  if independent && start = 2 then
    ctr := 1
    addr := addresses (addressInput pass lane slice mPrime p.passes p.variant.code ctr)
  for index in [start:segLength] do
    let cur := lane * laneLength + slice * segLength + index
    let prev := if cur % laneLength = 0 then cur + laneLength - 1 else cur - 1
    let rand ←
      if independent then
        if index % 128 = 0 then
          ctr := ctr + 1
          addr := addresses (addressInput pass lane slice mPrime p.passes p.variant.code ctr)
        pure (ld addr (index % 128))
      else pure (ld mem (prev * 128))
    let refLane := if pass = 0 && slice = 0 then lane else (rand >>> 32).toNat % lanes
    let ref := refLane * laneLength +
      refIndex pass slice index laneLength segLength (refLane = lane) (rand &&& 0xFFFFFFFF).toNat
    let r := xorBlock (mem.extract (prev * blockSize) (prev * blockSize + blockSize)) 0 mem
      (ref * blockSize)
    let z := compressR r
    mem := if pass = 0 then z.copySlice 0 mem (cur * blockSize) blockSize
      else xorBlock mem (cur * blockSize) z 0
  return mem

/-- Zeroed memory of `n` bytes, built by doubling so no `Array UInt8` is ever materialized. -/
private def zeroMemory (n : Nat) : ByteArray := Id.run do
  let mut b := zeros blockSize
  while b.size < n do b := b ++ b
  return b.extract 0 n

/-- RFC 9106 §3.1 bounds on the parameters, in bytes and KiB. -/
def validate (p : Params) (password salt : ByteArray) : Except String Unit := do
  let max32 := 2 ^ 32 - 1
  unless 1 ≤ p.parallelism ∧ p.parallelism ≤ 2 ^ 24 - 1 do throw "parallelism must be 1 to 2^24-1"
  unless 4 ≤ p.tagLength ∧ p.tagLength ≤ max32 do throw "tag length must be at least 4 bytes"
  unless 8 * p.parallelism ≤ p.memoryKiB ∧ p.memoryKiB ≤ max32 do
    throw "memory must be at least 8 KiB per lane"
  unless 1 ≤ p.passes ∧ p.passes ≤ max32 do throw "passes must be at least 1"
  unless 8 ≤ salt.size ∧ salt.size ≤ max32 do throw "salt must be at least 8 bytes"
  unless password.size ≤ max32 ∧ p.secret.size ≤ max32 ∧ p.ad.size ≤ max32 do
    throw "input too long"

/-- RFC 9106 §3.2: the Argon2 tag of `password` and `salt`. -/
def hash (p : Params) (password salt : ByteArray) : Except String ByteArray := do
  validate p password salt
  let lanes := p.parallelism
  let mPrime := 4 * lanes * (p.memoryKiB / (4 * lanes))
  let laneLength := mPrime / lanes
  let h0 := Blake2b.hashN 64 (le32 lanes ++ le32 p.tagLength ++ le32 p.memoryKiB ++
    le32 p.passes ++ le32 version ++ le32 p.variant.code ++ lenPrefixed password ++
    lenPrefixed salt ++ lenPrefixed p.secret ++ lenPrefixed p.ad)
  let mem := (List.range lanes).foldl (fun mem l =>
    let b0 := hPrime blockSize (h0 ++ le32 0 ++ le32 l)
    let b1 := hPrime blockSize (h0 ++ le32 1 ++ le32 l)
    b1.copySlice 0 (b0.copySlice 0 mem (l * laneLength * blockSize) blockSize)
      ((l * laneLength + 1) * blockSize) blockSize) (zeroMemory (mPrime * blockSize))
  let mem := (List.range p.passes).foldl (fun mem pass =>
    (List.range 4).foldl (fun mem slice =>
      (List.range lanes).foldl (fun mem lane => fillSegment mem p pass slice lane mPrime)
        mem) mem) mem
  let last (l : Nat) := (l * laneLength + laneLength - 1) * blockSize
  let c := (List.range (lanes - 1)).foldl (fun c l => xorBlock c 0 mem (last (l + 1)))
    (mem.extract (last 0) (last 0 + blockSize))
  pure (hPrime p.tagLength c)

end CryptWalker.KDF.Argon2

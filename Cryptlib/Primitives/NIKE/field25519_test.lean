/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.NIKE.Field25519
import Cryptlib.Primitives.NIKE.X25519_montgomery_ladder
import Cryptlib.Util.newhex

/-! Tests for `Field25519` and the limb-based ladder: every field operation against `Nat`
arithmetic modulo `p`, on edge cases and random values, with the limb bound checked after each;
RFC 7748 vectors; and agreement with the `ZMod` ladder. -/

open Cryptlib.Primitives.NIKE.Field25519 (Fe)
open Cryptlib.Primitives.NIKE.X25519Common (p)
open Cryptlib.Primitives.NIKE.X25519_montgomery_ladder (curve25519 curve25519_fe)
open Cryptlib.Util.newhex (byteArrayToHex hexStringToByteArray)

def failures : IO (IO.Ref Nat) := IO.mkRef 0

def check (fails : IO.Ref Nat) (ok : Bool) (what : String) : IO Unit := do
  unless ok do
    fails.modify (· + 1)
    IO.println s!"  FAIL {what}"

def bounded (f : Fe) : Bool := f.limbs.all (· < 2 ^ 26)

def randomNat (bits : Nat) : IO Nat := do
  let bs ← IO.getRandomBytes ((bits + 7) / 8).toUSize
  return (bs.foldl (fun acc b => acc * 256 + b.toNat) 0) % 2 ^ bits

def edges : List Nat :=
  [0, 1, 2, 19, 2 ^ 25, 2 ^ 26 - 1, 2 ^ 26, 2 ^ 51, p - 2, p - 1, p, p + 1, p + 18, 2 ^ 255 - 1,
   2 ^ 128 - 1, 2 ^ 254, 121665]

def hex32 (s : String) : Vector UInt8 32 :=
  match hexStringToByteArray s with
  | some b => if h : b.data.size = 32 then ⟨b.data, h⟩ else Vector.replicate 32 0
  | none => Vector.replicate 32 0

def hexOf (v : Vector UInt8 32) : String := byteArrayToHex ⟨v.toArray⟩

def fieldOps (fails : IO.Ref Nat) (a b : Nat) : IO Unit := do
  let fa := Fe.ofNat a
  let fb := Fe.ofNat b
  let cases : List (String × Fe × Nat) :=
    [("ofNat", fa, a % p), ("add", fa.add fb, (a + b) % p), ("sub", fa.sub fb, (a + p - b % p) % p),
     ("mul", fa.mul fb, a * b % p), ("sq", fa.sq, a * a % p), ("mulSmall", fa.mulSmall 121666, a * 121666 % p)]
  for (name, f, want) in cases do
    check fails (f.toNat % p == want) s!"{name} {a} {b}"
    check fails (bounded f) s!"{name} limb bound {a} {b}"

def main : IO UInt32 := do
  let fails ← failures
  -- field operations against Nat modulo p
  for a in edges do
    for b in edges do
      fieldOps fails a b
  for _ in [0:2000] do
    fieldOps fails (← randomNat 255) (← randomNat 255)
  -- long chains keep limbs in bound and stay equal to the reference
  let mut x := Fe.ofNat 9
  let mut xn : Nat := 9
  for i in [0:5000] do
    let y ← randomNat 255
    let fy := Fe.ofNat y
    match i % 4 with
    | 0 => x := x.mul fy; xn := xn * y % p
    | 1 => x := x.sub fy; xn := (xn + p - y % p) % p
    | 2 => x := x.add fy; xn := (xn + y) % p
    | _ => x := x.sq; xn := xn * xn % p
    check fails (bounded x) s!"chain bound at step {i}"
  check fails (x.toNat % p == xn) "chain of 5000 operations"
  -- inversion
  for a in edges ++ [← randomNat 255, ← randomNat 255] do
    let inv := (Fe.ofNat a).invert
    let want := if a % p == 0 then 0 else 1
    check fails ((inv.mul (Fe.ofNat a)).toNat % p == want) s!"invert {a}"
  -- cswap
  let (s0, t0) := Fe.cswap 0 (Fe.ofNat 5) (Fe.ofNat 7)
  let (s1, t1) := Fe.cswap 1 (Fe.ofNat 5) (Fe.ofNat 7)
  check fails (s0.toNat == 5 && t0.toNat == 7 && s1.toNat == 7 && t1.toNat == 5) "cswap"
  -- encoding
  for a in edges do
    let bytes := (Fe.ofNat a).toBytes
    let back := (List.range 32).foldr (fun i acc => acc * 256 + bytes[i]!.toNat) 0
    check fails (back == a % p) s!"toBytes {a}"
  check fails ((Fe.ofBytes (Vector.replicate 32 0xff)).toNat % p == (2 ^ 255 - 1) % p) "ofBytes masks bit 255"
  -- RFC 7748 §5.2
  let vectors := [
    ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
    ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")]
  for (k, u, want) in vectors do
    check fails (hexOf (curve25519_fe (hex32 k) (hex32 u)) == want) s!"RFC 7748 vector {k}"
    check fails (hexOf (curve25519 (hex32 k) (hex32 u)) == want) s!"RFC 7748 vector (ZMod) {k}"
  -- RFC 7748 §6.1 Diffie-Hellman
  let nine : Vector UInt8 32 := (Vector.replicate 32 0).set 0 9
  let alice := hex32 "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  let bob := hex32 "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
  let alicePub := curve25519_fe alice nine
  let bobPub := curve25519_fe bob nine
  check fails (hexOf alicePub == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a") "RFC 7748 alice public"
  check fails (hexOf bobPub == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f") "RFC 7748 bob public"
  let shared := "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
  check fails (hexOf (curve25519_fe alice bobPub) == shared && hexOf (curve25519_fe bob alicePub) == shared)
    "RFC 7748 shared secret"
  -- RFC 7748 §5.2 iterated
  let mut k := nine
  let mut u := nine
  for i in [1:1001] do
    (k, u) := (curve25519_fe k u, k)
    if i == 1 then
      check fails (hexOf k == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079") "RFC 7748 iterated once"
  check fails (hexOf k == "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51") "RFC 7748 iterated 1000 times"
  -- agreement with the ZMod ladder, including u ≥ p and the high bit set
  let rand32 : IO (Vector UInt8 32) := do
    let bs ← IO.getRandomBytes 32
    return Vector.ofFn fun i : Fin 32 => bs[i.val]!
  let pBytes := hex32 "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
  let specialU := [Vector.replicate 32 0, nine, pBytes, Vector.replicate 32 0xff,
    (Vector.replicate 32 0).set 0 1]
  for su in specialU do
    let sk ← rand32
    check fails (curve25519_fe sk su == curve25519 sk su) s!"agrees with ZMod ladder at u = {hexOf su}"
  for _ in [0:50] do
    let rk ← rand32
    let ru ← rand32
    check fails (curve25519_fe rk ru == curve25519 rk ru) s!"agrees with ZMod ladder: k = {hexOf rk}, u = {hexOf ru}"
  let n ← fails.get
  IO.println s!"field25519: {n} failures"
  return if n == 0 then 0 else 1

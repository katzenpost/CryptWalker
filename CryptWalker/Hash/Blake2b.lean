/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Util.UInt64

namespace CryptWalker.Hash.Blake2b

open CryptWalker.Util.UInt64

private def iv : Array UInt64 := #[
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
  0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
  0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4]

private def sigma : Array (Array Nat) := #[
  #[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  #[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  #[11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  #[7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  #[9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  #[2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  #[12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  #[13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  #[6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  #[10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  #[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  #[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
]

private def word (block : Array UInt8) (i : Nat) : UInt64 :=
  UInt64.ofNat block[8*i]!.toNat |||
    (UInt64.ofNat block[8*i+1]!.toNat <<< 8) |||
    (UInt64.ofNat block[8*i+2]!.toNat <<< 16) |||
    (UInt64.ofNat block[8*i+3]!.toNat <<< 24) |||
    (UInt64.ofNat block[8*i+4]!.toNat <<< 32) |||
    (UInt64.ofNat block[8*i+5]!.toNat <<< 40) |||
    (UInt64.ofNat block[8*i+6]!.toNat <<< 48) |||
    (UInt64.ofNat block[8*i+7]!.toNat <<< 56)

private def mix (v : Array UInt64) (a b c d : Nat) (x y : UInt64) : Array UInt64 :=
  let va := v[a]! + v[b]! + x
  let vd := (v[d]! ^^^ va).ror 32
  let vc := v[c]! + vd
  let vb := (v[b]! ^^^ vc).ror 24
  let va := va + vb + y
  let vd := (vd ^^^ va).ror 16
  let vc := vc + vd
  let vb := (vb ^^^ vc).ror 63
  (v.set! a va).set! b vb |>.set! c vc |>.set! d vd

private def round (v : Array UInt64) (m : Array UInt64) (r : Nat) : Array UInt64 :=
  let s := sigma[r]!
  let v := mix v 0 4 8 12 m[s[0]!]! m[s[1]!]!
  let v := mix v 1 5 9 13 m[s[2]!]! m[s[3]!]!
  let v := mix v 2 6 10 14 m[s[4]!]! m[s[5]!]!
  let v := mix v 3 7 11 15 m[s[6]!]! m[s[7]!]!
  let v := mix v 0 5 10 15 m[s[8]!]! m[s[9]!]!
  let v := mix v 1 6 11 12 m[s[10]!]! m[s[11]!]!
  let v := mix v 2 7 8 13 m[s[12]!]! m[s[13]!]!
  mix v 3 4 9 14 m[s[14]!]! m[s[15]!]!

private def compress (h : Array UInt64) (block : Array UInt8) (count : Nat) (last : Bool) : Array UInt64 :=
  let m := (List.range 16).toArray.map (word block)
  let v0 := h ++ iv
  let v1 := v0.set! 12 (v0[12]! ^^^ UInt64.ofNat count)
  let v2 := v1.set! 13 (v1[13]! ^^^ UInt64.ofNat (count >>> 64))
  let v3 := if last then v2.set! 14 (~~~v2[14]!) else v2
  let v := (List.range 12).foldl (fun v r => round v m r) v3
  (List.range 8).toArray.map fun i => h[i]! ^^^ v[i]! ^^^ v[i + 8]!

private def pad (msg : ByteArray) : ByteArray :=
  let blocks := (msg.size + 127) / 128
  let blocks := if blocks = 0 then 1 else blocks
  msg ++ ⟨Array.replicate (blocks * 128 - msg.size) 0⟩

private def digestArray (msg : ByteArray) : Array UInt64 :=
  let padded := pad msg
  let blocks := padded.size / 128
  let initial := (List.range 8).toArray.map fun i =>
    if i = 0 then iv[0]! ^^^ 0x01010040 else iv[i]!
  (List.range blocks).foldl (fun h i =>
    compress h (padded.data.extract (128*i) (128*i + 128)) (min msg.size (128*(i+1))) (i + 1 = blocks)) initial

/-- BLAKE2b-512, with the standard unkeyed 64-byte parameter block. -/
def hash (msg : ByteArray) : Vector UInt8 64 :=
  let h := digestArray msg
  Vector.ofFn fun i : Fin 64 =>
    (h[i.val / 8]! >>> UInt64.ofNat (8 * (i.val % 8))).toUInt8

private def xorPad (key : ByteArray) (pad : UInt8) : ByteArray :=
  let key := key ++ ⟨Array.replicate (128 - key.size) 0⟩
  ⟨key.data.map (fun b => b ^^^ pad)⟩

private def hmac (key msg : ByteArray) : Vector UInt8 64 :=
  let key := if key.size > 128 then ⟨(hash ⟨key.data⟩).toArray⟩ else key
  hash (xorPad key 0x5c ++ ⟨(hash (xorPad key 0x36 ++ msg)).toArray⟩)

private def toBytes {n : Nat} (v : Vector UInt8 n) : ByteArray := ⟨v.toArray⟩

/-- RFC 5869 HKDF using BLAKE2b-512 as the HMAC hash. -/
def hkdf (secret salt info : ByteArray) (length : Nat) : ByteArray :=
  let salt := if salt.size = 0 then ⟨Array.replicate 64 0⟩ else salt
  let prk := toBytes (hmac salt secret)
  let blocks := (length + 63) / 64
  let rec expand (fuel i : Nat) (previous : ByteArray) (out : ByteArray) : ByteArray :=
    if fuel = 0 then out.extract 0 length
    else
      let current := toBytes (hmac prk (previous ++ info ++ ⟨#[i.toUInt8]⟩))
      expand (fuel - 1) (i + 1) current (out ++ current)
  if length = 0 then ByteArray.empty
  else expand blocks 1 ByteArray.empty ByteArray.empty

end CryptWalker.Hash.Blake2b

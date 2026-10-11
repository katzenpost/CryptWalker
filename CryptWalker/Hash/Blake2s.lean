/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Hash.Hash

namespace CryptWalker.Hash.Blake2s

open CryptWalker.Hash.Hash

/-! # BLAKE2s (RFC 7693)

32-bit words, ten rounds, 64-byte blocks, digests of up to 32 bytes. -/

private def iv : Array UInt32 := #[
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

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
  #[10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]]

private def ror (x : UInt32) (n : UInt32) : UInt32 := (x >>> n) ||| (x <<< (32 - n))

private def word (block : Array UInt8) (i : Nat) : UInt32 :=
  block[4*i]!.toUInt32 ||| (block[4*i+1]!.toUInt32 <<< 8) |||
    (block[4*i+2]!.toUInt32 <<< 16) ||| (block[4*i+3]!.toUInt32 <<< 24)

private def mix (v : Array UInt32) (a b c d : Nat) (x y : UInt32) : Array UInt32 :=
  let va := v[a]! + v[b]! + x
  let vd := ror (v[d]! ^^^ va) 16
  let vc := v[c]! + vd
  let vb := ror (v[b]! ^^^ vc) 12
  let va := va + vb + y
  let vd := ror (vd ^^^ va) 8
  let vc := vc + vd
  let vb := ror (vb ^^^ vc) 7
  (v.set! a va).set! b vb |>.set! c vc |>.set! d vd

private def round (v : Array UInt32) (m : Array UInt32) (r : Nat) : Array UInt32 :=
  let s := sigma[r]!
  let v := mix v 0 4 8 12 m[s[0]!]! m[s[1]!]!
  let v := mix v 1 5 9 13 m[s[2]!]! m[s[3]!]!
  let v := mix v 2 6 10 14 m[s[4]!]! m[s[5]!]!
  let v := mix v 3 7 11 15 m[s[6]!]! m[s[7]!]!
  let v := mix v 0 5 10 15 m[s[8]!]! m[s[9]!]!
  let v := mix v 1 6 11 12 m[s[10]!]! m[s[11]!]!
  let v := mix v 2 7 8 13 m[s[12]!]! m[s[13]!]!
  mix v 3 4 9 14 m[s[14]!]! m[s[15]!]!

private def compress (h : Array UInt32) (block : Array UInt8) (count : Nat) (last : Bool) :
    Array UInt32 :=
  let m := (List.range 16).toArray.map (word block)
  let v0 := h ++ iv
  let v1 := v0.set! 12 (v0[12]! ^^^ UInt32.ofNat count)
  let v2 := v1.set! 13 (v1[13]! ^^^ UInt32.ofNat (count >>> 32))
  let v3 := if last then v2.set! 14 (~~~v2[14]!) else v2
  let v := (List.range 10).foldl (fun v r => round v m r) v3
  (List.range 8).toArray.map fun i => h[i]! ^^^ v[i]! ^^^ v[i + 8]!

private def pad (msg : ByteArray) : ByteArray :=
  let blocks := max 1 ((msg.size + 63) / 64)
  msg ++ ⟨Array.replicate (blocks * 64 - msg.size) 0⟩

/-- Keyed mode prepends the key, zero-padded to a full block, and records its length in the
parameter block. -/
private def digestArray (key : ByteArray) (digestLen : Nat) (msg : ByteArray) : Array UInt32 :=
  let d := if key.size > 0 then key ++ ⟨Array.replicate (64 - key.size) 0⟩ ++ msg else msg
  let padded := pad d
  let blocks := padded.size / 64
  let param := UInt32.ofNat digestLen ||| (UInt32.ofNat key.size <<< 8) ||| ((1 : UInt32) <<< 16) ||| ((1 : UInt32) <<< 24)
  let initial := iv.set! 0 (iv[0]! ^^^ param)
  (List.range blocks).foldl (fun h i =>
    compress h (padded.data.extract (64*i) (64*i + 64)) (min d.size (64*(i+1)))
      (i + 1 = blocks)) initial

private def extractDigest (h : Array UInt32) (n : Nat) : Vector UInt8 n :=
  Vector.ofFn fun i : Fin n => (h[i.val / 4]! >>> UInt32.ofNat (8 * (i.val % 4))).toUInt8

/-- BLAKE2s-256, unkeyed. -/
def hash (msg : ByteArray) : Vector UInt8 32 :=
  extractDigest (digestArray ByteArray.empty 32 msg) 32

/-- BLAKE2s-256, keyed (keys of at most 32 bytes). -/
def hashKeyed (key msg : ByteArray) : Vector UInt8 32 :=
  extractDigest (digestArray key 32 msg) 32

def Scheme : Hash where
  State      := ByteArray
  name       := "BLAKE2s-256"
  digestSize := 32
  blockSize  := 64

  init     := ByteArray.empty
  update   := fun s m => s ++ m
  finalize := hash
  hash     := hash

  hash_spec     := fun m => by rw [ByteArray.empty_append]
  update_append := fun _ _ _ => ByteArray.append_assoc

end CryptWalker.Hash.Blake2s

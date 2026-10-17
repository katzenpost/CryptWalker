/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Primitives.Cipher.AES
import Cryptlib.Primitives.StreamCipher.StreamCipher
import Cryptlib.Util.Bytes

namespace Cryptlib.Primitives.StreamCipher.AES256CTR

open Cryptlib.Primitives.Cipher.AES
open Cryptlib.Util.Bytes

/-! # AES-256-CTR

The IV is a big-endian 128-bit counter, incremented once per block with wraparound. -/

/-- 16 bytes read as a big-endian 128-bit natural number. -/
private def toNat128 (v : Vector UInt8 16) : Nat :=
  v.toList.foldl (fun acc b => acc * 256 + b.toNat) 0

/-- A natural number as 16 big-endian bytes, modulo `2^128`. -/
private def ofNat128 (n : Nat) : Vector UInt8 16 :=
  Vector.ofFn fun i : Fin 16 => UInt8.ofNat ((n % 2 ^ 128) >>> (8 * (15 - i.val)))

/-- Counter block `i`: the IV as a 128-bit big-endian integer, plus `i`. -/
private def counterBlock (iv : Vector UInt8 16) (i : Nat) : Vector UInt8 16 :=
  ofNat128 (toNat128 iv + i)

/-- `len` bytes of AES-256-CTR keystream. -/
def keystream (key : Vector UInt8 32) (iv : Vector UInt8 16) (len : Nat) : ByteArray :=
  let rk := expandKey key
  ((List.range ((len + 15) / 16)).foldl
    (fun out i => out ++ ofVector (encryptBlock rk (counterBlock iv i)))
    ByteArray.empty).extract 0 len

/-- Generic over the per-block function `f`, so it need not name the private `counterBlock`. -/
private theorem fold16_size (f : Nat → Vector UInt8 16) (n : Nat) :
    ((List.range n).foldl (fun (out : ByteArray) i => out ++ ofVector (f i))
      ByteArray.empty).size = 16 * n := by
  induction n with
  | zero => simp
  | succ n ih =>
    rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil]
    simp [ByteArray.size_append, ih, Nat.mul_succ]

theorem keystream_size (key : Vector UInt8 32) (iv : Vector UInt8 16) (len : Nat) :
    (keystream key iv len).size = len := by
  unfold keystream
  dsimp only
  rw [ByteArray.size_extract, fold16_size]
  have : len ≤ 16 * ((len + 15) / 16) := by omega
  omega

/-- AES-256-CTR as a `StreamCipher`. -/
def aes256CTR : Cryptlib.Primitives.StreamCipher.StreamCipher where
  keySize := 32
  ivSize  := 16
  keystream := fun key iv len => keystream (toVecN 32 key) (toVecN 16 iv) len
  keystream_size := fun key iv len => keystream_size (toVecN 32 key) (toVecN 16 iv) len

end Cryptlib.Primitives.StreamCipher.AES256CTR

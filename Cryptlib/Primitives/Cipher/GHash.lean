/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace Cryptlib.Primitives.Cipher.GHash

/-! # GHASH, the GCM authenticator (NIST SP 800-38D §6.4)

Blocks are read as big-endian 128-bit integers. GCM numbers bits from the most significant end,
so the coefficient of `x⁰` is the integer's top bit and multiplying by `x` is a right shift,
reduced by `R = 0xE1 ‖ 0¹²⁰`. -/

def R : Nat := 0xE1 <<< 120

def ofBytes (b : Array UInt8) : Nat := b.foldl (fun acc x => (acc <<< 8) ||| x.toNat) 0

def toBytes (n : Nat) : Vector UInt8 16 :=
  Vector.ofFn fun i : Fin 16 => UInt8.ofNat (n >>> (8 * (15 - i.val)))

/-- SP 800-38D Algorithm 1, `X • Y` in `GF(2¹²⁸)`. -/
def mul (x y : Nat) : Nat :=
  ((List.range 128).foldl (fun (z, v) i =>
    let z := if x.testBit (127 - i) then z ^^^ v else z
    let v := if v.testBit 0 then (v >>> 1) ^^^ R else v >>> 1
    (z, v)) (0, y)).1

/-- `GHASH_H` over a byte string, a short final block read as zero-padded. -/
def ghash (h : Vector UInt8 16) (blocks : ByteArray) : Vector UInt8 16 :=
  let hf := ofBytes h.toArray
  -- `ByteArray.data` copies, so convert once rather than per block
  let b := blocks.data
  toBytes <| (List.range ((blocks.size + 15) / 16)).foldl (fun y i =>
    let chunk := b.extract (16 * i) (16 * i + 16)
    mul (y ^^^ (ofBytes chunk <<< (8 * (16 - chunk.size)))) hf) 0

end Cryptlib.Primitives.Cipher.GHash

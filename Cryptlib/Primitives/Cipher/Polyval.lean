/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace Cryptlib.Primitives.Cipher.Polyval

/-! # POLYVAL, the GCM-SIV authenticator

RFC 8452 §3: `POLYVAL(H, X₁, …, Xₛ) = Σᵢ Xᵢ • H^(s-i+1)` where `a • b = a·b·x⁻¹²⁸`, over
`GF(2)[x] / (x¹²⁸ + x¹²⁷ + x¹²⁶ + x¹²¹ + 1)`. Field elements are little-endian `Nat`s: byte `j`,
bit `i` is the coefficient of `x^(8j+i)`.
-/

/-- `x¹²⁸ + x¹²⁷ + x¹²⁶ + x¹²¹ + 1`, as bits of a `Nat`. -/
def modulus : Nat := 1 ||| (1 <<< 121) ||| (1 <<< 126) ||| (1 <<< 127) ||| (1 <<< 128)

/-- A 16-byte string as a field element, little-endian per RFC 8452 §3. -/
def ofBytes (v : Vector UInt8 16) : Nat :=
  v.toArray.foldr (fun b acc => (acc <<< 8) ||| b.toNat) 0

/-- A field element as 16 little-endian bytes. Bits at or above `x¹²⁸` are dropped. -/
def toBytes (n : Nat) : Vector UInt8 16 :=
  Vector.ofFn fun i : Fin 16 => UInt8.ofNat ((n >>> (8 * i.val)) % 256)

/-- Carry-less multiplication over `GF(2)`, without reduction. -/
def clmul (a b : Nat) : Nat :=
  (List.range 128).foldl (fun acc i => if a.testBit i then acc ^^^ (b <<< i) else acc) 0

/-- Multiplication by `x⁻¹²⁸`, one division by `x` at a time; also reduces the input below
`x¹²⁸`. -/
def divX128 (c : Nat) : Nat :=
  (List.range 128).foldl
    (fun c _ => if c.testBit 0 then (c ^^^ modulus) >>> 1 else c >>> 1) c

/-- RFC 8452's `dot`: `a • b = a·b·x⁻¹²⁸`. -/
def dot (a b : Nat) : Nat := divX128 (clmul a b)

/-- The 16-byte block at index `i`, read little-endian; a short final block is zero-padded. -/
private def blockAt (b : ByteArray) (i : Nat) : Nat :=
  (b.extract (16 * i) (16 * i + 16)).data.foldr (fun x acc => (acc <<< 8) ||| x.toNat) 0

/-- `POLYVAL(H, X₁ ‖ … ‖ Xₛ)`, in Horner form: `Sⱼ = (Sⱼ₋₁ + Xⱼ) • H`. -/
def polyval (h : Vector UInt8 16) (blocks : ByteArray) : Vector UInt8 16 :=
  let hf := ofBytes h
  toBytes <| (List.range ((blocks.size + 15) / 16)).foldl
    (fun s i => dot (s ^^^ blockAt blocks i) hf) 0

end Cryptlib.Primitives.Cipher.Polyval

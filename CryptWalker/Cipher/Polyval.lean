/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Cipher.Polyval

/-! # POLYVAL, the GCM-SIV authenticator

RFC 8452 §3. A universal hash over `GF(2^128)`, the "little-endian sibling" of GHASH:

```
POLYVAL(H, X₁, …, Xₛ) = Σᵢ Xᵢ • H^(s-i+1)      where  a • b = a·b·x⁻¹²⁸
```

Two details make this its own primitive rather than a call to GHASH.

*The field is different.* GHASH reduces modulo `x¹²⁸ + x⁷ + x² + x + 1`; POLYVAL reduces
modulo `x¹²⁸ + x¹²⁷ + x¹²⁶ + x¹²¹ + 1`.

*The bit order is different.* GHASH reads a byte string big-endian in both bytes and bits —
the most significant bit of the first byte is the coefficient of `x⁰`. POLYVAL reads it
little-endian: byte `j`, bit `i`, is the coefficient of `x^(8j+i)`. That is precisely
`Nat`'s own bit numbering of the little-endian integer, which is why field elements here are
`Nat` and the encoding is a fold rather than a bit-reversal table.

The extra `x⁻¹²⁸` in `dot` is what keeps the little-endian convention closed: it is the
Montgomery form that makes POLYVAL and GHASH isomorphic under byte reversal, and it costs a
128-step division that `divX128` performs directly rather than via the usual carry-less
multiply-and-reduce.
-/

/-- `x¹²⁸ + x¹²⁷ + x¹²⁶ + x¹²¹ + 1`, as bits of a `Nat`. -/
def modulus : Nat := 1 ||| (1 <<< 121) ||| (1 <<< 126) ||| (1 <<< 127) ||| (1 <<< 128)

/-- A 16-byte string as a field element, little-endian per RFC 8452 §3. -/
def ofBytes (v : Vector UInt8 16) : Nat :=
  v.toArray.foldr (fun b acc => (acc <<< 8) ||| b.toNat) 0

/-- The inverse encoding. Bits at or above `x¹²⁸` are dropped, so this is total on any `Nat`;
every field element produced below is already reduced. -/
def toBytes (n : Nat) : Vector UInt8 16 :=
  Vector.ofFn fun i : Fin 16 => UInt8.ofNat ((n >>> (8 * i.val)) % 256)

/-- Carry-less multiplication: polynomial multiplication over `GF(2)`, no reduction. The result
has degree below 256. -/
def clmul (a b : Nat) : Nat :=
  (List.range 128).foldl (fun acc i => if a.testBit i then acc ^^^ (b <<< i) else acc) 0

/-- Division by `x¹²⁸` in the field, one step at a time. Dividing by `x` is a right shift when
the constant term is zero; when it is one, adding the modulus — which changes nothing modulo
the modulus — makes it zero first. 128 such steps multiply by `x⁻¹²⁸` and, as a side effect,
reduce the 256-bit input back below `x¹²⁸`. -/
def divX128 (c : Nat) : Nat :=
  (List.range 128).foldl
    (fun c _ => if c.testBit 0 then (c ^^^ modulus) >>> 1 else c >>> 1) c

/-- RFC 8452's `dot`: `a • b = a·b·x⁻¹²⁸`. -/
def dot (a b : Nat) : Nat := divX128 (clmul a b)

/-- The 16-byte block at index `i`, read little-endian. A short final block is read as though
zero-padded, which is exactly how RFC 8452 §4 treats a trailing partial block — and, since
`extract` clamps, it is also what keeps this total without an out-of-range index. -/
private def blockAt (b : ByteArray) (i : Nat) : Nat :=
  (b.extract (16 * i) (16 * i + 16)).data.foldr (fun x acc => (acc <<< 8) ||| x.toNat) 0

/-- `POLYVAL(H, X₁ ‖ … ‖ Xₛ)`, in Horner form: `Sⱼ = (Sⱼ₋₁ + Xⱼ) • H`. -/
def polyval (h : Vector UInt8 16) (blocks : ByteArray) : Vector UInt8 16 :=
  let hf := ofBytes h
  toBytes <| (List.range ((blocks.size + 15) / 16)).foldl
    (fun s i => dot (s ^^^ blockAt blocks i) hf) 0

end CryptWalker.Cipher.Polyval

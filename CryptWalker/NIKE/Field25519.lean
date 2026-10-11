/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.NIKE.X25519Common

/-! # Arithmetic modulo `2^255 - 19` on ten `UInt64` limbs

An element is `Σ hᵢ · 2^⌈25.5·i⌉`: limbs alternate 26 and 25 bits, so a product of two limbs fits
in 64 bits with room to sum ten of them. Every operation ends with `carry`, which leaves each limb
below `2^26`; operations accept any input in that bound. Values are not kept fully reduced: `toNat`
is the represented number and `toNat % p` its canonical value. The limbs are separate structure
fields rather than an array so that they stay unboxed. -/

namespace CryptWalker.NIKE.Field25519

open CryptWalker.NIKE.X25519Common (p keySize)

structure Fe where
  h0 : UInt64
  h1 : UInt64
  h2 : UInt64
  h3 : UInt64
  h4 : UInt64
  h5 : UInt64
  h6 : UInt64
  h7 : UInt64
  h8 : UInt64
  h9 : UInt64
  deriving Inhabited, Repr

namespace Fe

/-- Bit offset of each limb. -/
def offsets : List Nat := [0, 26, 51, 77, 102, 128, 153, 179, 204, 230]

def limbs (f : Fe) : List UInt64 := [f.h0, f.h1, f.h2, f.h3, f.h4, f.h5, f.h6, f.h7, f.h8, f.h9]

/-- The number the limbs represent. -/
def toNat (f : Fe) : Nat := (f.limbs.zip offsets).foldl (fun acc (l, o) => acc + l.toNat <<< o) 0

/-- Split `n < 2^256` into limbs; bits from 255 up are folded back in as multiples of 19. -/
def ofNat (n : Nat) : Fe :=
  let limb (o w : Nat) : UInt64 := ((n >>> o) % 2 ^ w).toUInt64
  carry' ⟨limb 0 26 + (19 : UInt64) * (n >>> 255).toUInt64, limb 26 25, limb 51 26, limb 77 25, limb 102 26,
    limb 128 25, limb 153 26, limb 179 25, limb 204 26, limb 230 25⟩
where
  carry' (h : Fe) : Fe :=
    let c0 := h.h0 >>> 26
    ⟨h.h0 &&& 0x3ffffff, h.h1 + c0, h.h2, h.h3, h.h4, h.h5, h.h6, h.h7, h.h8, h.h9⟩

def zero : Fe := ⟨0, 0, 0, 0, 0, 0, 0, 0, 0, 0⟩
def one : Fe := ⟨1, 0, 0, 0, 0, 0, 0, 0, 0, 0⟩

/-- Bring every limb back under its width, folding the overflow of the top limb into the bottom
one as a multiple of 19. Accepts limbs up to `2^62`. -/
def carry (h : Fe) : Fe :=
  let m26 : UInt64 := 0x3ffffff
  let m25 : UInt64 := 0x1ffffff
  let h1 := h.h1 + (h.h0 >>> 26)
  let h0 := h.h0 &&& m26
  let h2 := h.h2 + (h1 >>> 25)
  let h1 := h1 &&& m25
  let h3 := h.h3 + (h2 >>> 26)
  let h2 := h2 &&& m26
  let h4 := h.h4 + (h3 >>> 25)
  let h3 := h3 &&& m25
  let h5 := h.h5 + (h4 >>> 26)
  let h4 := h4 &&& m26
  let h6 := h.h6 + (h5 >>> 25)
  let h5 := h5 &&& m25
  let h7 := h.h7 + (h6 >>> 26)
  let h6 := h6 &&& m26
  let h8 := h.h8 + (h7 >>> 25)
  let h7 := h7 &&& m25
  let h9 := h.h9 + (h8 >>> 26)
  let h8 := h8 &&& m26
  let h0 := h0 + (19 : UInt64) * (h9 >>> 25)
  let h9 := h9 &&& m25
  let h1 := h1 + (h0 >>> 26)
  let h0 := h0 &&& m26
  ⟨h0, h1, h2, h3, h4, h5, h6, h7, h8, h9⟩

def add (f g : Fe) : Fe :=
  carry ⟨f.h0 + g.h0, f.h1 + g.h1, f.h2 + g.h2, f.h3 + g.h3, f.h4 + g.h4,
    f.h5 + g.h5, f.h6 + g.h6, f.h7 + g.h7, f.h8 + g.h8, f.h9 + g.h9⟩

/-- `f - g` as `f + 2p - g`, so no limb goes negative. -/
def sub (f g : Fe) : Fe :=
  carry ⟨f.h0 + 0x7ffffda - g.h0, f.h1 + 0x3fffffe - g.h1, f.h2 + 0x7fffffe - g.h2,
    f.h3 + 0x3fffffe - g.h3, f.h4 + 0x7fffffe - g.h4, f.h5 + 0x3fffffe - g.h5,
    f.h6 + 0x7fffffe - g.h6, f.h7 + 0x3fffffe - g.h7, f.h8 + 0x7fffffe - g.h8,
    f.h9 + 0x3fffffe - g.h9⟩

/-- Multiplication by a constant below `2^30`. -/
def mulSmall (f : Fe) (c : UInt64) : Fe :=
  carry ⟨f.h0 * c, f.h1 * c, f.h2 * c, f.h3 * c, f.h4 * c, f.h5 * c, f.h6 * c, f.h7 * c,
    f.h8 * c, f.h9 * c⟩

/-- `hₖ = Σ_{i+j=k} c·fᵢgⱼ + Σ_{i+j=k+10} 19·c·fᵢgⱼ`, where `c = 2` when `i` and `j` are both odd:
the offsets of two odd limbs sum to one more than the offset of their product's limb, and
`2^255 ≡ 19`. -/
def mul (f g : Fe) : Fe :=
  let g119 := 19 * g.h1
  let g219 := 19 * g.h2
  let g319 := 19 * g.h3
  let g419 := 19 * g.h4
  let g519 := 19 * g.h5
  let g619 := 19 * g.h6
  let g719 := 19 * g.h7
  let g819 := 19 * g.h8
  let g919 := 19 * g.h9
  let f12 := 2 * f.h1
  let f32 := 2 * f.h3
  let f52 := 2 * f.h5
  let f72 := 2 * f.h7
  let f92 := 2 * f.h9
  let h0 := f.h0 * g.h0 + f12 * g919 + f.h2 * g819 + f32 * g719 + f.h4 * g619 + f52 * g519 + f.h6 * g419 + f72 * g319 + f.h8 * g219 + f92 * g119
  let h1 := f.h0 * g.h1 + f.h1 * g.h0 + f.h2 * g919 + f.h3 * g819 + f.h4 * g719 + f.h5 * g619 + f.h6 * g519 + f.h7 * g419 + f.h8 * g319 + f.h9 * g219
  let h2 := f.h0 * g.h2 + f12 * g.h1 + f.h2 * g.h0 + f32 * g919 + f.h4 * g819 + f52 * g719 + f.h6 * g619 + f72 * g519 + f.h8 * g419 + f92 * g319
  let h3 := f.h0 * g.h3 + f.h1 * g.h2 + f.h2 * g.h1 + f.h3 * g.h0 + f.h4 * g919 + f.h5 * g819 + f.h6 * g719 + f.h7 * g619 + f.h8 * g519 + f.h9 * g419
  let h4 := f.h0 * g.h4 + f12 * g.h3 + f.h2 * g.h2 + f32 * g.h1 + f.h4 * g.h0 + f52 * g919 + f.h6 * g819 + f72 * g719 + f.h8 * g619 + f92 * g519
  let h5 := f.h0 * g.h5 + f.h1 * g.h4 + f.h2 * g.h3 + f.h3 * g.h2 + f.h4 * g.h1 + f.h5 * g.h0 + f.h6 * g919 + f.h7 * g819 + f.h8 * g719 + f.h9 * g619
  let h6 := f.h0 * g.h6 + f12 * g.h5 + f.h2 * g.h4 + f32 * g.h3 + f.h4 * g.h2 + f52 * g.h1 + f.h6 * g.h0 + f72 * g919 + f.h8 * g819 + f92 * g719
  let h7 := f.h0 * g.h7 + f.h1 * g.h6 + f.h2 * g.h5 + f.h3 * g.h4 + f.h4 * g.h3 + f.h5 * g.h2 + f.h6 * g.h1 + f.h7 * g.h0 + f.h8 * g919 + f.h9 * g819
  let h8 := f.h0 * g.h8 + f12 * g.h7 + f.h2 * g.h6 + f32 * g.h5 + f.h4 * g.h4 + f52 * g.h3 + f.h6 * g.h2 + f72 * g.h1 + f.h8 * g.h0 + f92 * g919
  let h9 := f.h0 * g.h9 + f.h1 * g.h8 + f.h2 * g.h7 + f.h3 * g.h6 + f.h4 * g.h5 + f.h5 * g.h4 + f.h6 * g.h3 + f.h7 * g.h2 + f.h8 * g.h1 + f.h9 * g.h0
  carry ⟨h0, h1, h2, h3, h4, h5, h6, h7, h8, h9⟩

def sq (f : Fe) : Fe := mul f f

/-- `f^(2^k)`. -/
def sqN (f : Fe) : Nat → Fe
  | 0 => f
  | k + 1 => sqN (sq f) k

/-- `f^(p-2)`, which is `f⁻¹` for `f ≠ 0` and `0` for `f = 0`, by the usual addition chain. -/
def invert (z : Fe) : Fe :=
  let z2 := sq z
  let z9 := mul (sqN z2 2) z
  let z11 := mul z9 z2
  let z2_5_0 := mul (sq z11) z9
  let z2_10_0 := mul (sqN z2_5_0 5) z2_5_0
  let z2_20_0 := mul (sqN z2_10_0 10) z2_10_0
  let z2_40_0 := mul (sqN z2_20_0 20) z2_20_0
  let z2_50_0 := mul (sqN z2_40_0 10) z2_10_0
  let z2_100_0 := mul (sqN z2_50_0 50) z2_50_0
  let z2_200_0 := mul (sqN z2_100_0 100) z2_100_0
  let z2_250_0 := mul (sqN z2_200_0 50) z2_50_0
  mul (sqN z2_250_0 5) z11

/-- Swap `f` and `g` when `swap` is 1, without branching on it. `swap` must be 0 or 1. -/
def cswap (swap : UInt64) (f g : Fe) : Fe × Fe :=
  let mask := 0 - swap
  let t (a b : UInt64) := mask &&& (a ^^^ b)
  let t0 := t f.h0 g.h0
  let t1 := t f.h1 g.h1
  let t2 := t f.h2 g.h2
  let t3 := t f.h3 g.h3
  let t4 := t f.h4 g.h4
  let t5 := t f.h5 g.h5
  let t6 := t f.h6 g.h6
  let t7 := t f.h7 g.h7
  let t8 := t f.h8 g.h8
  let t9 := t f.h9 g.h9
  (⟨f.h0 ^^^ t0, f.h1 ^^^ t1, f.h2 ^^^ t2, f.h3 ^^^ t3, f.h4 ^^^ t4, f.h5 ^^^ t5, f.h6 ^^^ t6,
     f.h7 ^^^ t7, f.h8 ^^^ t8, f.h9 ^^^ t9⟩,
   ⟨g.h0 ^^^ t0, g.h1 ^^^ t1, g.h2 ^^^ t2, g.h3 ^^^ t3, g.h4 ^^^ t4, g.h5 ^^^ t5, g.h6 ^^^ t6,
     g.h7 ^^^ t7, g.h8 ^^^ t8, g.h9 ^^^ t9⟩)

/-- Little-endian bytes with bit 255 masked, as RFC 7748 decodes a u-coordinate. -/
def ofBytes (v : Vector UInt8 keySize) : Fe :=
  ofNat ((List.range keySize).foldr (fun i acc => acc * 256 + v[i]!.toNat) 0 % 2 ^ 255)

/-- The canonical little-endian encoding. -/
def toBytes (f : Fe) : Vector UInt8 keySize :=
  let n := f.toNat % p
  Vector.ofFn fun i : Fin keySize => (n >>> (8 * i.val)).toUInt8

end Fe

end CryptWalker.NIKE.Field25519

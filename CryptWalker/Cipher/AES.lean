/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Cipher.AES

/-! # AES-256

The block cipher underneath `AESGCMSIV`, and only as much of it as that mode needs.

## Encryption direction only

There is no inverse cipher here, and its absence is not an omission. GCM-SIV never decrypts a
block: POLYVAL authenticates, CTR encrypts by XOR against a keystream built from *forward* AES
calls, and the tag is a forward AES call on the authenticator output. Opening a ciphertext runs
the same forward machinery as sealing it. An `InvCipher` would be dead code carrying a real
proof obligation — that it inverts `encryptBlock` — for no caller.

## The S-box is computed, not tabulated

`sboxByte` is FIPS-197 §5.1.1 as written: invert in `GF(2^8)`, then apply the affine map. The
usual 256-entry table is 256 chances to transcribe a byte wrong, silently, in a way no type
catches; the algebraic definition can be checked against the standard by eye. `sbox` tabulates
it once at startup so lookups stay cheap, and `Cipher.test` pins the result to FIPS-197's
known-answer vector.

## Not constant time

Every S-box lookup indexes an array with a secret byte, and `mul` branches on secret bits. This
is a model of AES, suitable for stating and proving things about protocols that use it. It is
not suitable for handling real keys on a machine an adversary can time.
-/

/-- Multiplication in `GF(2^8)` modulo AES's `x^8 + x^4 + x^3 + x + 1`. -/
def mul (a b : UInt8) : UInt8 := Id.run do
  let mut x := a
  let mut y := b
  let mut p : UInt8 := 0
  for _ in [0:8] do
    if y &&& 1 != 0 then
      p := p ^^^ x
    let carry := x &&& 0x80
    x := x <<< 1
    if carry != 0 then
      x := x ^^^ 0x1b
    y := y >>> 1
  return p

/-- The multiplicative inverse in `GF(2^8)`, computed as `a^254`: the nonzero elements form a
group of order 255, so `a^254 = a^(-1)`. Total, and `inv 0 = 0` — which is the convention the
S-box wants for zero anyway. -/
def inv (a : UInt8) : UInt8 := Id.run do
  let mut square := a
  let mut acc : UInt8 := 1
  for _ in [0:7] do
    square := mul square square
    acc := mul acc square
  return acc

private def rotl (x : UInt8) (n : UInt8) : UInt8 := (x <<< n) ||| (x >>> (8 - n))

/-- FIPS-197 §5.1.1: invert in `GF(2^8)`, then apply the affine transformation over `GF(2)`. -/
def sboxByte (a : UInt8) : UInt8 :=
  let b := inv a
  b ^^^ rotl b 1 ^^^ rotl b 2 ^^^ rotl b 3 ^^^ rotl b 4 ^^^ 0x63

/-- `sboxByte` tabulated over all 256 inputs. -/
def sbox : Array UInt8 := (Array.range 256).map fun i => sboxByte (UInt8.ofNat i)

/-- The round constant for round `i` of the key schedule: `x^i` in `GF(2^8)`. The 256-bit
schedule reaches `i ≤ 6`, so this never gets as far as the `0x1b` wrap that the 128-bit
schedule's table is famous for. -/
private def rcon (i : Nat) : UInt8 := Id.run do
  let mut c : UInt8 := 1
  for _ in [0:i] do
    c := mul c 2
  return c

/-- The AES-256 key schedule: sixty 4-byte words, i.e. fifteen round keys laid end to end.
`Nk = 8`, `Nr = 14`, and note the extra `SubWord` at `i % 8 == 4` that the 128- and 192-bit
schedules do not have. -/
def expandKey (key : Vector UInt8 32) : Array UInt8 := Id.run do
  let mut w := key.toArray
  for i in [8:60] do
    let mut t := #[w[4*i - 4]!, w[4*i - 3]!, w[4*i - 2]!, w[4*i - 1]!]
    if i % 8 == 0 then
      t := #[sbox[t[1]!.toNat]! ^^^ rcon (i / 8 - 1), sbox[t[2]!.toNat]!,
             sbox[t[3]!.toNat]!, sbox[t[0]!.toNat]!]
    else if i % 8 == 4 then
      t := t.map fun b => sbox[b.toNat]!
    for j in [0:4] do
      w := w.push (w[4*(i - 8) + j]! ^^^ t[j]!)
  return w

/-- Not `private`: `Sphinx.Crypto.AEZ` reuses this directly as AEZ's AES4/AES10 round function
composes the same four steps under a different (fixed, 4- or 10-round) key schedule than
AES-256 proper. -/
def subBytes (s : Array UInt8) : Array UInt8 := s.map fun b => sbox[b.toNat]!

/-- Byte `i` of the state is row `i % 4`, column `i / 4`; row `r` rotates left by `r` columns.
Not `private`, for the same reason as `subBytes`. -/
def shiftRows (s : Array UInt8) : Array UInt8 :=
  Array.ofFn fun i : Fin 16 => s[(i.val + 4 * (i.val % 4)) % 16]!

/-- Each column multiplied by the fixed polynomial `{03}x³ + {01}x² + {01}x + {02}`. Not
`private`, for the same reason as `subBytes`. -/
def mixColumns (s : Array UInt8) : Array UInt8 :=
  Array.ofFn fun i : Fin 16 =>
    let a := fun j => s[4 * (i.val / 4) + j]!
    match i.val % 4 with
    | 0 => mul (a 0) 2 ^^^ mul (a 1) 3 ^^^ a 2 ^^^ a 3
    | 1 => a 0 ^^^ mul (a 1) 2 ^^^ mul (a 2) 3 ^^^ a 3
    | 2 => a 0 ^^^ a 1 ^^^ mul (a 2) 2 ^^^ mul (a 3) 3
    | _ => mul (a 0) 3 ^^^ a 1 ^^^ a 2 ^^^ mul (a 3) 2

private def addRoundKey (s : Array UInt8) (rk : Array UInt8) (round : Nat) : Array UInt8 :=
  Array.ofFn fun i : Fin 16 => s[i.val]! ^^^ rk[16 * round + i.val]!

/-- AES-256 on one block, against an already-expanded schedule. Fourteen rounds, the last
without `MixColumns`. -/
def encryptBlock (rk : Array UInt8) (input : Vector UInt8 16) : Vector UInt8 16 := Id.run do
  let mut s := addRoundKey input.toArray rk 0
  for round in [1:14] do
    s := addRoundKey (mixColumns (shiftRows (subBytes s))) rk round
  s := addRoundKey (shiftRows (subBytes s)) rk 14
  return Vector.ofFn fun i : Fin 16 => s[i.val]!

/-- Expand and encrypt in one call, for the one-off block encryptions in key derivation. -/
def encryptBlockWithKey (key : Vector UInt8 32) (input : Vector UInt8 16) : Vector UInt8 16 :=
  encryptBlock (expandKey key) input

end CryptWalker.Cipher.AES

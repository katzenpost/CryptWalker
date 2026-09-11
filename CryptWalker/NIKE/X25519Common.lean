/-
SPDX-FileCopyrightText: © 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic.NormNum

/-!
# X25519 primitives shared by both implementations

`X25519.lean` (the group formulation) and `X25519_montgomery_ladder.lean` (the byte-level
Montgomery ladder) are otherwise-independent implementations of the same exchange. What they
actually share, and nothing more: the field prime, RFC 7748's byte encoding and scalar
clamping, the basepoint, and the shape of a private key. -/

namespace CryptWalker.NIKE.X25519Common

abbrev keySize : ℕ := 32

/-- The Curve25519 prime, `2^255 - 19`. -/
def p : ℕ := 2 ^ 255 - 19

instance : NeZero p := ⟨by norm_num [p]⟩

/-- The `x`-coordinate of the standard basepoint. -/
def basepoint : ZMod p := 9

/-- Little-endian byte decoding, with bit 255 masked per RFC 7748. -/
def toField (v : Vector UInt8 keySize) : ZMod p :=
  let masked := v.set 31 (v[31] &&& 0x7f)
  (List.range keySize).foldr (fun i acc => acc * 256 + (masked[i]!).toNat) 0

/-- RFC 7748 clamping: clear the low three bits, clear bit 255, set bit 254. -/
def clampScalar (v : Vector UInt8 keySize) : Vector UInt8 keySize :=
  let v1 := v.set 0  (v[0]  &&& 0xf8)
  v1.set 31 ((v1[31] &&& 0x7f) ||| 0x40)

/-- A private key: a 32-byte scalar seed, clamped on use. -/
structure PrivateKey where data : Vector UInt8 keySize

end CryptWalker.NIKE.X25519Common

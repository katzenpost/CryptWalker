/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Data.ZMod.Basic
import CryptWalker.Hash.Sha512
import CryptWalker.Sign.Sign
import CryptWalker.NIKE.X25519

namespace CryptWalker.Sign.Ed25519Math

open CryptWalker.Hash.Sha512
open CryptWalker.Sign.Sign

/-! # Native Ed25519 arithmetic

This is the RFC 8032 arithmetic path, expressed over Mathlib's finite field `ZMod p`.
Mathlib does not currently provide an Edwards-curve group, so the affine twisted-Edwards
addition formula is written here. The field, inverses, powers, finite-width vectors, and
decidable checks are all supplied by Mathlib.

The final `Signature.verify_sign` field is an axiom: proving the complete RFC 8032 correctness
theorem would require a substantial formalization of the Edwards formulas and the order-`l`
subgroup. The operations themselves are executable and contain no assumed cryptographic primitive.
-/

abbrev p : Nat := CryptWalker.NIKE.X25519.p
abbrev ell : Nat := 2^252 + 27742317777372353535851937790883648493

lemma p_prime : Nat.Prime p := CryptWalker.NIKE.X25519.p_prime
instance : Fact (Nat.Prime p) := ⟨p_prime⟩

abbrev F := ZMod p

def d : F := (-121665 : F) / 121666

structure Point where
  x : F
  y : F
deriving DecidableEq

def onCurve (q : Point) : Prop :=
  -q.x ^ 2 + q.y ^ 2 = 1 + d * q.x ^ 2 * q.y ^ 2

instance decidableOnCurve (q : Point) : Decidable (onCurve q) :=
  inferInstanceAs (Decidable (_ = _))

def zero : Point := ⟨0, 1⟩

def add (q r : Point) : Point :=
  let t := d * q.x * r.x * q.y * r.y
  ⟨(q.x * r.y + q.y * r.x) / (1 + t),
   (q.y * r.y + q.x * r.x) / (1 - t)⟩

def scalarMul (n : Nat) (q : Point) : Point :=
  if n = 0 then zero
  else
    let half := scalarMul (n / 2) q
    let doubled := add half half
    if n % 2 = 0 then doubled else add q doubled
termination_by n
decreasing_by
  exact Nat.div_lt_self (Nat.pos_of_ne_zero ‹n ≠ 0›) (by norm_num)

def basepoint : Point :=
  ⟨15112221349535400772501151409588531511454012693041857206046113283949847762202,
   46316835694926478169428394003475163141307993866256225615783033603165251855960⟩

def bytesToNat (bs : List UInt8) : Nat :=
  Nat.ofDigits 256 (bs.map UInt8.toNat)

def natToBytes (width n : Nat) : List UInt8 :=
  (List.range width).map (fun i => (n >>> (8 * i)).toUInt8)

def vectorToByteArray {n : Nat} (v : Vector UInt8 n) : ByteArray := ⟨v.toArray⟩

def leBytes (z : F) (width : Nat) : List UInt8 := natToBytes width z.val

def encodePoint (q : Point) : Vector UInt8 32 :=
  let ys := bytesToNat (leBytes q.y 32)
  let signed := ys ||| ((q.x.val % 2) <<< 255)
  Vector.ofFn fun i : Fin 32 => (signed >>> (8 * i.val)).toUInt8

private def powAux (base : F) (e : Nat) : F :=
  if _h : e = 0 then 1
  else
    let half := powAux (base * base) (e / 2)
    if e % 2 = 1 then base * half else half
termination_by e
decreasing_by exact Nat.div_lt_self (Nat.pos_of_ne_zero _h) (by norm_num)

def sqrtMinusOne : F :=
  19681161376707505956807079304988542015446066515923890162744021073123829784752

def decodePoint (v : Vector UInt8 32) : Option Point :=
  let raw := bytesToNat v.toList
  let sign := raw >>> 255
  let yNat : Nat := raw % (2^255 : Nat)
  let y : F := yNat
  let xx := (y ^ 2 - 1) / (d * y ^ 2 + 1)
  let x0 := powAux xx ((p + 3) / 8)
  let x := if x0 ^ 2 = xx then x0 else x0 * sqrtMinusOne
  let x' := if x.val % 2 = sign then x else -x
  let q : Point := ⟨x', y⟩
  if _h : onCurve q then some q else none

def scalarFromSeed (seed : Vector UInt8 32) : Nat :=
  let digest := (sha512 (vectorToByteArray seed)).toList
  let h := digest.take 32
  let clamped := (h[0]! &&& 248) ::
    (h.drop 1 |>.take 30) ++
    [((h[31]! &&& 127) ||| 64)]
  bytesToNat clamped

def publicKey (seed : Vector UInt8 32) : Vector UInt8 32 :=
  encodePoint (scalarMul (scalarFromSeed seed) basepoint)

def hashNat (parts : List ByteArray) : Nat :=
  bytesToNat ((sha512 (parts.foldl ByteArray.append ByteArray.empty)).toList)

def signNative (seed : Vector UInt8 32) (message : ByteArray) : Vector UInt8 64 :=
  let digest := (sha512 (vectorToByteArray seed)).toList
  let noncePrefix := digest.drop 32
  let r := hashNat [⟨noncePrefix.toArray⟩, message] % ell
  let rBytes := encodePoint (scalarMul r basepoint)
  let pk := publicKey seed
  let k := hashNat [vectorToByteArray rBytes, vectorToByteArray pk, message] % ell
  let s := (r + k * (scalarFromSeed seed)) % ell
  Vector.ofFn fun i : Fin 64 =>
    if i.val < 32 then rBytes[i.val]! else (s >>> (8 * (i.val - 32))).toUInt8

def verifyNative (pk : Vector UInt8 32) (message : ByteArray) (sig : Vector UInt8 64) : Bool :=
  match decodePoint pk, decodePoint ⟨sig.toArray.extract 0 32, by simp⟩ with
  | some a, some r =>
    let s := bytesToNat (sig.toList.drop 32)
    if s < ell then
      let k := hashNat [⟨sig.toArray.extract 0 32⟩, vectorToByteArray pk, message] % ell
      decide (scalarMul (8 * s) basepoint =
        add (scalarMul 8 r) (scalarMul (8 * k) a))
    else false
  | _, _ => false

axiom verify_signNative : ∀ sk m,
  verifyNative (publicKey sk) m (signNative sk m) = true

def nativeSignature : Signature where
  State := Unit
  PublicKey := Vector UInt8 32
  PrivateKey := Vector UInt8 32
  Sig := Vector UInt8 64
  seedSize := 32
  publicKeySize := 32
  privateKeySize := 32
  sigSize := 64
  encodePublicKey := id
  decodePublicKey := some
  encodePrivateKey := id
  decodePrivateKey := some
  encodeSig := id
  decodeSig := some
  privateKeyFromSeed := id
  pub := publicKey
  sign := fun sk m => pure (signNative sk m)
  verify := verifyNative
  decode_encode_pub := fun _ => rfl
  decode_encode_priv := fun _ => rfl
  decode_encode_sig := fun _ => rfl
  verify_sign := fun sk m _ => verify_signNative sk m

end CryptWalker.Sign.Ed25519Math

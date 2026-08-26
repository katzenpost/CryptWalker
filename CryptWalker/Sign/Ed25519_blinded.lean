/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Data.ZMod.Basic
import CryptWalker.Sign.Ed25519_math
import CryptWalker.Sign.Blindable

namespace CryptWalker.Sign.Ed25519Blinded

open CryptWalker.Hash.Sha512
open CryptWalker.Sign.Sign
open CryptWalker.Sign.Blindable
open CryptWalker.Sign.Ed25519Math

/-! # Blinded Ed25519

Concrete scalar-based Ed25519 operations matching hpqc's `blinded25519.go`: private keys are
canonical scalars in `ZMod ell`, public keys are compressed Edwards points, and signing derives
its nonce from `SHA-512(sk)[32:] || message || SHA-512(sk)[33:]`.

The remaining laws are named assumptions because the affine Edwards group law has not yet been
formalized. The operations below are executable.
-/

abbrev Scalar : Type := ZMod ell
abbrev PubBytes : Type := Vector UInt8 32
abbrev SigBytes : Type := Vector UInt8 64

axiom ell_prime : Nat.Prime ell
instance : Fact (Nat.Prime ell) := ⟨ell_prime⟩

private def scalarBytes (s : Scalar) : Vector UInt8 32 :=
  Vector.ofFn fun i : Fin 32 => (s.val >>> (8 * i.val)).toUInt8

def scalarOfBytes (bytes : ByteArray) : Scalar :=
  let digest := (sha512_256 bytes).toList
  let clamped := (digest[0]! &&& 248) ::
    (digest.drop 1 |>.take 30) ++
    [((digest[31]! &&& 127) ||| 64)]
  bytesToNat clamped

def scalarFromSeed (seed : Vector UInt8 32) : Scalar :=
  (Ed25519Math.scalarFromSeed seed : Scalar)

def publicKey (sk : Scalar) : PubBytes :=
  encodePoint (scalarMul sk.val basepoint)

def signNative (sk : Scalar) (message : ByteArray) : SigBytes :=
  let digest := (sha512 (⟨scalarBytes sk |>.toArray⟩)).toList
  let noncePrefix := digest.drop 32
  let r := hashNat [⟨noncePrefix.toArray⟩, message, ⟨(digest.drop 33).toArray⟩] % ell
  let rBytes := encodePoint (scalarMul r basepoint)
  let k := hashNat [⟨rBytes.toArray⟩, ⟨(publicKey sk).toArray⟩, message] % ell
  let s := (r + k * sk.val) % ell
  Vector.ofFn fun i : Fin 64 =>
    if i.val < 32 then rBytes[i.val]! else (s >>> (8 * (i.val - 32))).toUInt8

def verifyNative (pk : PubBytes) (message : ByteArray) (sig : SigBytes) : Bool :=
  Ed25519Math.verifyNative pk message sig

def blindPriv (sk factor : Scalar) : Scalar := factor * sk

def blindPub (pk : PubBytes) (factor : Scalar) : PubBytes :=
  match decodePoint pk with
  | some point => encodePoint (scalarMul factor.val point)
  | none => Vector.replicate 32 0

def inv (factor : Scalar) : Scalar := factor⁻¹

axiom scalarOfBytes_scalarBytes (sk : Scalar) :
  scalarOfBytes ⟨(scalarBytes sk).toArray⟩ = sk
axiom verify_signNative : ∀ sk m, verifyNative (publicKey sk) m (signNative sk m) = true

axiom blind_hom : ∀ sk factor,
  publicKey (blindPriv sk factor) = blindPub (publicKey sk) factor
axiom blind_assoc : ∀ pk f g,
  blindPub (blindPub pk f) g = blindPub pk (f * g)
axiom blind_inv : ∀ pk f,
  blindPub (blindPub pk f) (inv f) = pk

def signature : Signature where
  State := Unit
  PublicKey := PubBytes
  PrivateKey := Scalar
  Sig := SigBytes
  seedSize := 32
  publicKeySize := 32
  privateKeySize := 32
  sigSize := 64
  encodePublicKey := id
  decodePublicKey := some
  encodePrivateKey := scalarBytes
  decodePrivateKey := fun bytes => some (scalarOfBytes ⟨bytes.toArray⟩)
  encodeSig := id
  decodeSig := some
  privateKeyFromSeed := scalarFromSeed
  pub := publicKey
  sign := fun sk m => pure (signNative sk m)
  verify := verifyNative
  decode_encode_pub := fun _ => rfl
  decode_encode_priv := fun sk => congrArg some (scalarOfBytes_scalarBytes sk)
  decode_encode_sig := fun _ => rfl
  verify_sign := fun sk m _ => verify_signNative sk m

def blindable : Blindable where
  base := signature
  Scalar := Scalar
  mul := (· * ·)
  inv := inv
  scalarOfBytes := scalarOfBytes
  blindPriv := blindPriv
  blindPub := blindPub
  blind_hom := blind_hom
  blind_assoc := blind_assoc
  blind_comm := mul_comm
  blind_inv := blind_inv

end CryptWalker.Sign.Ed25519Blinded

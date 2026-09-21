/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Data.ZMod.Basic
import CryptWalker.Sign.Ed25519_math
import CryptWalker.Sign.Ed25519_verify
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

The operations are executable, and every law is a theorem: the Edwards group law is Curve25519's,
transported (`Ed25519_group`), so `blindPub (publicKey s) f = publicKey (f * s)` is `mul_smul` plus
`ℓ • G = 0` (`Ed25519_order`). The only assumption is `ell_prime`, that `ℓ = 2^252 +
27742317777372353535851937790883648493` is prime (RFC 7748 §4.1 / RFC 8032 §5.1).

The laws that need more than `blind_hom` hold for *valid* keys, those of the form `publicKey s`, and
invertible (nonzero) factors; they are false on an arbitrary decodable point, which can carry a
small-order component (see `Blindable`).
-/

abbrev Scalar : Type := ZMod ell
abbrev PubBytes : Type := Vector UInt8 32
abbrev SigBytes : Type := Vector UInt8 64

axiom ell_prime : Nat.Prime ell
instance : Fact (Nat.Prime ell) := ⟨ell_prime⟩
instance : NeZero ell := ⟨ell_prime.ne_zero⟩

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

lemma ell_lt : ell < 256 ^ 32 := by unfold ell; norm_num

private lemma decode_publicKey (s : Scalar) :
    decodePoint (publicKey s) = some (scalarMul s.val basepoint) :=
  CryptWalker.Sign.Ed25519Codec.decode_encode _ (CryptWalker.Sign.Ed25519Scalar.sm_base_onCurve _)

/-- Blinding the public key of `s` is the public key of `f * s`. -/
theorem blindPub_publicKey (s f : Scalar) : blindPub (publicKey s) f = publicKey (f * s) := by
  unfold blindPub
  rw [decode_publicKey]
  simp only []
  unfold publicKey
  congr 1
  rw [CryptWalker.Sign.Ed25519Scalar.sm_sm]
  apply CryptWalker.Sign.Ed25519Scalar.sm_mod_eq
  rw [ZMod.val_mul, Nat.mod_mod]

theorem blind_hom : ∀ sk factor,
    publicKey (blindPriv sk factor) = blindPub (publicKey sk) factor := by
  intro sk factor
  rw [blindPub_publicKey]; rfl

/-- **RFC 8032 correctness of the scalar-based signer.** -/
theorem verify_signNative : ∀ sk m, verifyNative (publicKey sk) m (signNative sk m) = true := by
  intro sk m
  have hell : 0 < ell := by unfold ell; norm_num
  unfold signNative
  simp only []
  rw [CryptWalker.Sign.Ed25519Verify.sig_eq]
  exact CryptWalker.Sign.Ed25519Verify.verify_of_parts (publicKey sk) _ m sk.val _ _ _ rfl rfl rfl
    (Nat.mod_lt _ hell) (Nat.mod_mod _ _)

/-- `ψ` is injective: `ψ P = ψ Q` makes `ψ (P + -Q)` the Edwards identity. -/
lemma psi_injective {P Q : CryptWalker.Sign.Ed25519Group.W}
    (h : CryptWalker.Sign.Ed25519Group.psi P = CryptWalker.Sign.Ed25519Group.psi Q) : P = Q := by
  have h0 : CryptWalker.Sign.Ed25519Group.psi (P + -Q) = CryptWalker.Sign.Ed25519Math.zero := by
    rw [CryptWalker.Sign.Ed25519Group.psi_add, CryptWalker.Sign.Ed25519Group.psi_neg, ← h]
    exact CryptWalker.Sign.Ed25519Edwards.add_neg (CryptWalker.Sign.Ed25519Group.psi P) (CryptWalker.Sign.Ed25519Group.psi_onCurve P)
  exact add_neg_eq_zero.mp (CryptWalker.Sign.Ed25519Scalar.eq_zero_of_psi_eq_zero h0)

lemma G_ne_zero : CryptWalker.NIKE.X25519.G ≠ 0 := by
  unfold CryptWalker.NIKE.X25519.G CryptWalker.NIKE.X25519.mkPoint
  exact WeierstrassCurve.Affine.Point.some_ne_zero _

/-- The basepoint has order exactly `ℓ`. -/
lemma addOrderOf_G : addOrderOf CryptWalker.NIKE.X25519.G = ell := by
  have hd := addOrderOf_dvd_of_nsmul_eq_zero CryptWalker.Sign.Ed25519Scalar.ell_smul_G
  rcases (Nat.dvd_prime ell_prime).mp hd with h1 | h1
  · exfalso
    apply G_ne_zero
    have := addOrderOf_nsmul_eq_zero CryptWalker.NIKE.X25519.G
    rw [h1, one_nsmul] at this
    exact this
  · exact h1

lemma smul_G_inj {a b : ℕ} (ha : a < ell) (hb : b < ell)
    (h : a • CryptWalker.NIKE.X25519.G = b • CryptWalker.NIKE.X25519.G) : a = b := by
  have := nsmul_eq_nsmul_iff_modEq.mp h
  rw [addOrderOf_G] at this
  exact this.eq_of_lt_of_lt ha hb

theorem publicKey_injective : Function.Injective publicKey := by
  intro a b h
  unfold publicKey at h
  have hab := congrArg CryptWalker.Sign.Ed25519Math.decodePoint h
  rw [CryptWalker.Sign.Ed25519Codec.decode_encode _ (CryptWalker.Sign.Ed25519Scalar.sm_base_onCurve _),
    CryptWalker.Sign.Ed25519Codec.decode_encode _ (CryptWalker.Sign.Ed25519Scalar.sm_base_onCurve _)] at hab
  have hpt := Option.some.inj hab
  rw [CryptWalker.Sign.Ed25519Scalar.sm_base, CryptWalker.Sign.Ed25519Scalar.sm_base] at hpt
  exact ZMod.val_injective ell (smul_G_inj (ZMod.val_lt a) (ZMod.val_lt b) (psi_injective hpt))

/-- Blinding a nonzero root key by different factors gives different box IDs. -/
theorem blindPub_injective (s : Scalar) (hs : s ≠ 0) :
    Function.Injective (blindPub (publicKey s)) := by
  intro f g h
  rw [blindPub_publicKey, blindPub_publicKey] at h
  exact mul_right_cancel₀ hs (publicKey_injective h)


/-- A private key is its 32 little-endian bytes, and back. -/
private def scalarOfLE (bytes : Vector UInt8 32) : Scalar := ((bytesToNat bytes.toList : ℕ) : Scalar)

private lemma scalarOfLE_scalarBytes (sk : Scalar) : scalarOfLE (scalarBytes sk) = sk := by
  unfold scalarOfLE scalarBytes
  rw [CryptWalker.Sign.Ed25519Codec.bytesToNat_ofFn, Nat.mod_eq_of_lt
    (lt_trans (ZMod.val_lt sk) ell_lt)]
  exact ZMod.natCast_zmod_val sk

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
  decodePrivateKey := fun bytes => some (scalarOfLE bytes)
  encodeSig := id
  decodeSig := some
  privateKeyFromSeed := scalarFromSeed
  pub := publicKey
  sign := fun sk m => pure (signNative sk m)
  verify := verifyNative
  decode_encode_pub := fun _ => rfl
  decode_encode_priv := fun sk => congrArg some (scalarOfLE_scalarBytes sk)
  decode_encode_sig := fun _ => rfl
  verify_sign := fun sk m _ => verify_signNative sk m

def blindable : Blindable where
  base := signature
  Scalar := Scalar
  Valid := fun pk => ∃ s : Scalar, pk = publicKey s
  Invertible := fun f => f ≠ 0
  Regular := fun pk => ∃ s : Scalar, s ≠ 0 ∧ pk = publicKey s
  mul := (· * ·)
  inv := inv
  scalarOfBytes := scalarOfBytes
  blindPriv := blindPriv
  blindPub := blindPub
  blind_hom := blind_hom
  valid_pub := fun sk => ⟨sk, rfl⟩
  valid_blind := fun _ f ⟨s, hs⟩ => ⟨f * s, by rw [hs, blindPub_publicKey]⟩
  blind_assoc := fun _ ⟨s, hs⟩ f g => by
    subst hs
    rw [blindPub_publicKey, blindPub_publicKey, blindPub_publicKey]
    exact congrArg publicKey (by ring)
  blind_comm := mul_comm
  blind_inv := fun _ ⟨s, hs⟩ f hf => by
    subst hs
    rw [blindPub_publicKey, blindPub_publicKey]
    exact congrArg publicKey (inv_mul_cancel_left₀ hf s)
  blind_injective := fun _ ⟨s, hs, e⟩ => by
    subst e
    exact blindPub_injective s hs

end CryptWalker.Sign.Ed25519Blinded

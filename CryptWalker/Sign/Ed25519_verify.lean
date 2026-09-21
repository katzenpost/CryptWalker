/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sign.Ed25519_scalar
import CryptWalker.Sign.Ed25519_codec
import CryptWalker.Sign.Sign

/-! # Signature verification is correct

`verify_of_parts` is hash-independent: a signature `R ‖ s`, where `R` encodes `r·B`, `pk` encodes
`a·B`, and `s ≡ r + k·a (mod ℓ)` for the challenge `k` the verifier recomputes, always satisfies
the cofactored check `8s·B = 8R + 8k·A`. Both signers' `verify_signNative` are instances. -/

namespace CryptWalker.Sign.Ed25519Verify

open CryptWalker.Sign.Ed25519Math (Point onCurve add scalarMul basepoint ell encodePoint decodePoint
  bytesToNat hashNat vectorToByteArray verifyNative)
open CryptWalker.Sign.Ed25519Scalar
open CryptWalker.Sign.Ed25519Codec

/-- The 32 little-endian bytes of `s`. -/
def sBytes (s : ℕ) : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => (s >>> (8 * i.val)).toUInt8

lemma bytesToNat_sBytes (s : ℕ) (h : s < 256 ^ 32) : bytesToNat (sBytes s).toList = s := by
  unfold sBytes; rw [bytesToNat_ofFn, Nat.mod_eq_of_lt h]

lemma extract_eq (rBytes sb : Vector UInt8 32) :
    (rBytes ++ sb).toArray.extract 0 32 = rBytes.toArray := by
  rw [Vector.toArray_append]
  have h := Array.extract_append_left (as := rBytes.toArray) (bs := sb.toArray)
  rw [Vector.size_toArray] at h
  rw [h]; simp

theorem verify_of_parts (pk rBytes : Vector UInt8 32) (m : ByteArray) (a r k s : ℕ)
    (hpk : pk = encodePoint (scalarMul a basepoint))
    (hR : rBytes = encodePoint (scalarMul r basepoint))
    (hk : hashNat [⟨rBytes.toArray⟩, vectorToByteArray pk, m] % ell = k)
    (hs : s < ell) (hsk : s % ell = (r + k * a) % ell) :
    verifyNative pk m (rBytes ++ sBytes s) = true := by
  have hv : (⟨(rBytes ++ sBytes s).toArray.extract 0 32, by simp⟩ : Vector UInt8 32) = rBytes := by
    apply Vector.toArray_inj.mp
    simpa using extract_eq rBytes (sBytes s)
  have hdrop : (rBytes ++ sBytes s).toList.drop 32 = (sBytes s).toList := by
    rw [Vector.toList_append]
    exact List.drop_left' (by simp)
  have hell : ell < 256 ^ 32 := by unfold ell; norm_num
  have hsB : bytesToNat ((rBytes ++ sBytes s).toList.drop 32) = s := by
    rw [hdrop]
    exact bytesToNat_sBytes s (lt_trans hs hell)
  unfold verifyNative
  rw [hv]
  subst hpk
  rw [decode_encode _ (sm_base_onCurve a)]
  subst hR
  rw [decode_encode _ (sm_base_onCurve r)]
  simp only [hsB, extract_eq]
  rw [hk, if_pos hs, decide_eq_true_eq, sm_sm, sm_sm, add_sm]
  apply sm_mod_eq
  have h := (Nat.ModEq.mul_left 8 hsk : 8 * s ≡ 8 * (r + k * a) [MOD ell])
  rw [show 8 * r + 8 * k * a = 8 * (r + k * a) by ring]
  exact h

/-- A signature laid out as `R ‖ s`. -/
lemma sig_eq (rBytes : Vector UInt8 32) (s : ℕ) :
    (Vector.ofFn fun i : Fin 64 =>
      if i.val < 32 then rBytes[i.val]! else (s >>> (8 * (i.val - 32))).toUInt8)
      = rBytes ++ sBytes s := by
  apply Vector.ext
  intro i hi
  rw [Vector.getElem_ofFn, Vector.getElem_append]
  by_cases h : i < 32
  · rw [if_pos h, dif_pos h, getElem!_pos rBytes i h]
  · rw [if_neg h, dif_neg h]
    unfold sBytes
    rw [Vector.getElem_ofFn]

open CryptWalker.Sign.Ed25519Math (signNative publicKey scalarFromSeed) in
/-- **RFC 8032 correctness of the native signer.** Was an axiom. -/
theorem verify_signNative (sk : Vector UInt8 32) (m : ByteArray) :
    verifyNative (publicKey sk) m (signNative sk m) = true := by
  have hell : 0 < ell := by unfold ell; norm_num
  unfold signNative
  simp only []
  rw [sig_eq]
  refine verify_of_parts _ _ m (scalarFromSeed sk) _ _ _ rfl rfl rfl (Nat.mod_lt _ hell) ?_
  exact Nat.mod_mod _ _

open CryptWalker.Sign.Sign in
open CryptWalker.Sign.Ed25519Math in
/-- Ed25519 as a plain signature scheme, over the native arithmetic. -/
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

end CryptWalker.Sign.Ed25519Verify

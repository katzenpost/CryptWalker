/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.BACAP.Protocol
import CryptWalker.Sign.Ed25519_blinded
import CryptWalker.Cipher.AESGCMSIV

namespace CryptWalker.BACAP.Impl

open CryptWalker.BACAP.Types
open CryptWalker.BACAP.Ratchet
open CryptWalker.Hash.HKDF
open CryptWalker.Sign.Ed25519Blinded
open CryptWalker.Sign.Blindable
open CryptWalker.Cipher.AESGCMSIV
open CryptWalker.BACAP.Protocol

@[simp] private theorem Scheme_nonceSize : Scheme.nonceSize = 12 := rfl
@[simp] private theorem Scheme_tagSize : Scheme.tagSize = 16 := rfl
@[simp] private theorem Scheme_keySize : Scheme.keySize = 32 := rfl

@[simp] private theorem implEncrypt_size (k : Scheme.Key) (n : Vector UInt8 12)
    (ad pt : ByteArray) :
    (Scheme.encrypt k n ad pt).size = pt.size + 16 :=
  Scheme.size_encrypt k n ad pt

def getBlindScalar (m : MessageBoxIndex) (ctx : ByteArray) : Scalar :=
  let kICtx := deriveKForContext m blake2b512_hkdf ctx
  scalarOfBytes ⟨kICtx.toArray⟩

def getEncKey (m : MessageBoxIndex) (ctx : ByteArray) : Scheme.Key :=
  let eICtx := deriveEForContext m blake2b512_hkdf ctx
  Scheme.keyFromBytes eICtx

/-- Box ID for a context: blinds the root public key by `K_i^ctx`. -/
def implDeriveBoxID (rootPub : PubBytes) (m : MessageBoxIndex)
    (ctx : ByteArray) : PubBytes :=
  blindPub rootPub (getBlindScalar m ctx)

/-- Box ID with no context: blinds the root public key by `K_i` directly.

This is the sequence a bare cap addresses, without the per-context detour that
`implDeriveBoxID` takes. Matches `hpqc/bacap/bacap_impl.go:DeriveMessageBoxID`. -/
def implDeriveMessageBoxID (rootPub : PubBytes) (m : MessageBoxIndex) : PubBytes :=
  blindPub rootPub (scalarOfBytes ⟨m.curBlindingFactor.toArray⟩)

def implSignBox (rootPriv : Scalar) (m : MessageBoxIndex)
    (ctx : ByteArray) (ct : ByteArray) : PubBytes × SigBytes :=
  let s := getBlindScalar m ctx
  (blindPub (publicKey rootPriv) s, signNative (blindPriv rootPriv s) ct)

def implVerifyBox (boxId : PubBytes) (ct : ByteArray)
    (sig : SigBytes) : Bool :=
  verifyNative boxId ct sig

def implEncryptBox (rootPriv : Scalar) (rootPub : PubBytes)
    (m : MessageBoxIndex) (ctx : ByteArray) (pt : ByteArray) :
    PubBytes × ByteArray × SigBytes :=
  let boxId := implDeriveBoxID rootPub m ctx
  let key := getEncKey m ctx
  let nonce := Vector.ofFn fun i : Fin 12 => boxId[i]!
  let ad := ⟨boxId.toArray⟩
  let ct := Scheme.encrypt key nonce ad pt
  let sig := (implSignBox rootPriv m ctx ct).2
  (boxId, ct, sig)

def implDecryptBox (boxId : PubBytes) (m : MessageBoxIndex)
    (ctx : ByteArray) (ct : ByteArray) (sig : SigBytes) : Option ByteArray :=
  if !implVerifyBox boxId ct sig then none
  else if ct.size == 0 then some ByteArray.empty
  else
    let key := getEncKey m ctx
    let nonce := Vector.ofFn fun i : Fin 12 => boxId[i]!
    let ad := ⟨boxId.toArray⟩
    Scheme.decrypt key nonce ad ct

/-- Decrypting a box produced by `implEncryptBox` returns the original plaintext.

The public key must be the one derived from the private key, as it is inside a `WriteCap`.
Stated standalone rather than only as a `BACAPSpec` field so callers can apply it without
projecting through `bacapSpec`. -/
theorem implDecrypt_implEncrypt (sk : Scalar) (pk : PubBytes) (idx : MessageBoxIndex)
    (ctx pt : ByteArray) (hpk : pk = publicKey sk) :
    implDecryptBox (implEncryptBox sk pk idx ctx pt).1 idx ctx
      (implEncryptBox sk pk idx ctx pt).2.1
      (implEncryptBox sk pk idx ctx pt).2.2 = some pt := by
  unfold implEncryptBox implDecryptBox implDeriveBoxID
  dsimp only [implSignBox, implVerifyBox]
  rw [hpk, ← blind_hom]
  simp only [verify_signNative]
  rw [if_neg (by decide)]
  simp [Scheme_nonceSize, Scheme_tagSize, implEncrypt_size, ByteArray.size_empty]
  exact Scheme.decrypt_encrypt _ _ _ _

def bacapSpec : BACAPSpec where
  blindable := blindable
  hkdf      := blake2b512_hkdf
  aead      := Scheme

  deriveBoxID := implDeriveBoxID
  signBox     := implSignBox
  verifyBox   := implVerifyBox
  encryptBox  := implEncryptBox
  decryptBox  := implDecryptBox

  sign_verify    := fun (sk : Scalar) (idx : MessageBoxIndex) (ctx ct : ByteArray) => by
    show implVerifyBox (implSignBox sk idx ctx ct).1 ct (implSignBox sk idx ctx ct).2 = true
    unfold implSignBox implVerifyBox
    dsimp only []
    rw [← blind_hom]
    exact verify_signNative (blindPriv sk (getBlindScalar idx ctx)) ct

  decrypt_encrypt := fun (sk : Scalar) (pk : PubBytes) (idx : MessageBoxIndex)
      (ctx pt : ByteArray) (hpk : pk = publicKey sk) => by
    show implDecryptBox (implEncryptBox sk pk idx ctx pt).1 idx ctx
          (implEncryptBox sk pk idx ctx pt).2.1
          (implEncryptBox sk pk idx ctx pt).2.2 = some pt
    exact implDecrypt_implEncrypt sk pk idx ctx pt hpk

  decrypt_sound := sorry

end CryptWalker.BACAP.Impl

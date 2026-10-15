/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Protocols.BACAP.Ratchet
import CryptWalker.Sign.Blindable
import CryptWalker.Cipher.AEAD

/-! # BACAP protocol

Built from a `Blindable` signature scheme (box IDs), an `HKDF` (ratchet) and an `AEAD` (box
encryption). Operations are stateless and take a `MessageBoxIndex` explicitly. -/

namespace CryptWalker.Protocols.BACAP.Protocol

open CryptWalker.Protocols.BACAP.Types
open CryptWalker.Protocols.BACAP.Ratchet
open CryptWalker.Hash.HKDF
open CryptWalker.Sign.Blindable
open CryptWalker.Cipher.AEAD
open OracleComp OracleSpec ENNReal

structure BACAPSpec where
  blindable : Blindable
  hkdf      : HKDF
  aead      : AEAD

  /-- Blinding factors can be sampled uniformly. -/
  [scalarFintype : Fintype blindable.Scalar]
  [scalarSampleable : SampleableType blindable.Scalar]
  [pubDecEq : DecidableEq blindable.base.PublicKey]

  /-- The box ID `blindPub(rootPub, K_i^ctx)`. -/
  deriveBoxID : blindable.base.PublicKey → MessageBoxIndex → ByteArray → blindable.base.PublicKey

  /-- Sign a ciphertext with the blinded write key; returns (boxID, signature). -/
  signBox : blindable.base.PrivateKey → MessageBoxIndex → ByteArray → ByteArray →
    blindable.base.PublicKey × blindable.base.Sig

  verifyBox : blindable.base.PublicKey → ByteArray → blindable.base.Sig → Bool

  /-- Returns (boxID, ciphertext, signature). The box ID's first 12 bytes are the AEAD nonce;
      all 32 bytes are the AD. -/
  encryptBox : blindable.base.PrivateKey → blindable.base.PublicKey →
    MessageBoxIndex → ByteArray → ByteArray →
    blindable.base.PublicKey × ByteArray × blindable.base.Sig

  /-- Verifies the signature first; a tombstone (empty ciphertext) decrypts to empty. -/
  decryptBox : blindable.base.PublicKey →
    MessageBoxIndex → ByteArray → ByteArray → blindable.base.Sig → Option ByteArray

  /-- A signed ciphertext verifies under the box ID from the same inputs. -/
  sign_verify : ∀ sk idx ctx ct,
    let r := signBox sk idx ctx ct
    verifyBox r.1 ct r.2 = true

  /-- `encryptBox` writes to the box a reader derives from the root public key. -/
  encrypt_boxid : ∀ sk pk idx ctx pt, (encryptBox sk pk idx ctx pt).1 = deriveBoxID pk idx ctx

  /-- The signature `encryptBox` produces verifies under its box ID. -/
  encrypt_verify : ∀ sk pk idx ctx pt, pk = blindable.base.pub sk →
    let r := encryptBox sk pk idx ctx pt
    blindable.base.verify r.1 r.2.1 r.2.2 = true

  /-- Decrypting an encrypted box returns the plaintext. -/
  decrypt_encrypt : ∀ sk pk idx ctx pt,
    pk = blindable.base.pub sk →
    let r := encryptBox sk pk idx ctx pt
    decryptBox r.1 idx ctx r.2.1 r.2.2 = some pt

  /-- A non-tombstone ciphertext that decrypts at the derived box ID is exactly what
      `encryptBox` produces for that plaintext. -/
  decrypt_sound : ∀ sk pk boxId idx ctx ct sig pt,
    pk = blindable.base.pub sk →
    deriveBoxID pk idx ctx = boxId →
    decryptBox boxId idx ctx ct sig = some pt →
    ct.size > 0 →
    (encryptBox sk pk idx ctx pt).2.1 = ct

  /-- Unlinkability (Echomix §4.3): for a regular root key `pk`, a uniform blinding factor yields
  each key in the orbit of `pk` with probability `1/|Scalar|`. -/
  unlinkable : ∀ pk, blindable.Regular pk → ∀ target, target ∈ Set.range (blindable.blindPub pk) →
      Pr[= true | ($ᵗ blindable.Scalar) >>=
          fun f => pure (decide (blindable.blindPub pk f = target))] =
        (Fintype.card blindable.Scalar : ℝ≥0∞)⁻¹ :=
    fun pk hpk _ ht => CryptWalker.Sign.Blindable.blind_unlinkable blindable pk hpk ht

end CryptWalker.Protocols.BACAP.Protocol

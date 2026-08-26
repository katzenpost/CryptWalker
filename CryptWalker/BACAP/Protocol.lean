/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.BACAP.Ratchet
import CryptWalker.Sign.Blindable
import CryptWalker.Cipher.AEAD

/-! # BACAP Protocol: abstract structure with correctness laws

This file defines the abstract BACAP protocol specification that wires together:

* A `Blindable` signature scheme (for box-ID derivation via key blinding)
* An `HKDF` (for the ratchet and context key derivation)
* An `AEAD` (for box encryption)

The structure carries no mutable state; all operations take a `MessageBoxIndex`
explicitly, matching the stateless-first design. -/

namespace CryptWalker.BACAP.Protocol

open CryptWalker.BACAP.Types
open CryptWalker.BACAP.Ratchet
open CryptWalker.Hash.HKDF
open CryptWalker.Sign.Blindable
open CryptWalker.Cipher.AEAD

/-- Abstract BACAP protocol structure. -/
structure BACAPSpec where
  blindable : Blindable
  hkdf      : HKDF
  aead      : AEAD

  /-- Derive the per-box public key from a root public key, ratchet state, and context.
      The box ID is `blindPub(rootPub, K_i^ctx)`. -/
  deriveBoxID : blindable.base.PublicKey → MessageBoxIndex → ByteArray → blindable.base.PublicKey

  /-- Sign ciphertext with a blinded write key. Returns (boxID, signature). -/
  signBox : blindable.base.PrivateKey → MessageBoxIndex → ByteArray → ByteArray →
    blindable.base.PublicKey × blindable.base.Sig

  /-- Verify a signature under a given box ID. -/
  verifyBox : blindable.base.PublicKey → ByteArray → blindable.base.Sig → Bool

  /-- Encrypt a plaintext under a write cap. Returns (boxID, ciphertext, signature).
      The box ID is both the AEAD nonce prefix (first 12 bytes) and AD (all 32 bytes). -/
  encryptBox : blindable.base.PrivateKey → blindable.base.PublicKey →
    MessageBoxIndex → ByteArray → ByteArray →
    blindable.base.PublicKey × ByteArray × blindable.base.Sig

  /-- Decrypt a ciphertext given a box ID, context, ciphertext, and signature.
      Verifies signature first; for tombstones (empty ciphertext),
      returns empty plaintext after verification. -/
  decryptBox : blindable.base.PublicKey →
    MessageBoxIndex → ByteArray → ByteArray → blindable.base.Sig → Option ByteArray

  /-- A signed ciphertext verifies under the box ID from the same inputs. -/
  sign_verify : ∀ sk idx ctx ct,
    let r := signBox sk idx ctx ct
    verifyBox r.1 ct r.2 = true

  /-- Decrypting an encrypted box returns the original plaintext. The public key must be the
      one derived from the private key (i.e. `pk = base.pub sk`), as in a valid WriteCap. -/
  decrypt_encrypt : ∀ sk pk idx ctx pt,
    pk = blindable.base.pub sk →
    let r := encryptBox sk pk idx ctx pt
    decryptBox r.1 idx ctx r.2.1 r.2.2 = some pt

  /-- Soundness: for non-tombstone ciphertexts, if decryption succeeds and the box ID
      matches what `encryptBox` would derive from the given root public key, then encrypting
      the plaintext with the same inputs produces the same ciphertext. The `ct.size > 0`
      precondition excludes tombstones, which bypass the AEAD entirely. -/
  decrypt_sound : ∀ sk pk boxId idx ctx ct sig pt,
    pk = blindable.base.pub sk →
    deriveBoxID pk idx ctx = boxId →
    decryptBox boxId idx ctx ct sig = some pt →
    ct.size > 0 →
    (encryptBox sk pk idx ctx pt).2.1 = ct

end CryptWalker.BACAP.Protocol

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
open OracleComp OracleSpec ENNReal

/-- Abstract BACAP protocol structure. -/
structure BACAPSpec where
  blindable : Blindable
  hkdf      : HKDF
  aead      : AEAD

  /-- The blinding factors can be sampled uniformly. Instance fields, as in
  `NIKESphinxScheme`: they are what `unlinkable` below is stated over. -/
  [scalarFintype : Fintype blindable.Scalar]
  [scalarSampleable : SampleableType blindable.Scalar]
  [pubDecEq : DecidableEq blindable.base.PublicKey]

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

  /-- The box `encryptBox` addresses is the one a reader derives from the root public key, index and
      context. This is what lets a reader find a box it never saw written. -/
  encrypt_boxid : ∀ sk pk idx ctx pt, (encryptBox sk pk idx ctx pt).1 = deriveBoxID pk idx ctx

  /-- What `encryptBox` produces is a genuine box: its signature verifies under its box ID with the
      signature scheme itself, which is what a replica checks. As for `decrypt_encrypt`,
      `pk = base.pub sk`. -/
  encrypt_verify : ∀ sk pk idx ctx pt, pk = blindable.base.pub sk →
    let r := encryptBox sk pk idx ctx pt
    blindable.base.verify r.1 r.2.1 r.2.2 = true

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

  /-- **Unlinkability** (Echomix §4.3), under the idealization that blinding factors are truly
  random: for a regular root key `pk`, a freshly drawn blinding factor produces each key in the
  orbit of `pk` with probability exactly `1/|Scalar|`, whichever root secret `pk` came from. That
  is `δ = 0` in the paper's game (`BACAP.Unlinkability` has the two-box form). Free for every
  instance, like `NIKESphinxScheme.wrap_resistant`: it is `uniformHit_eq_of_injective` applied to
  `blindable.blind_injective`, which is the only thing a scheme has to supply. -/
  unlinkable : ∀ pk, blindable.Regular pk → ∀ target, target ∈ Set.range (blindable.blindPub pk) →
      Pr[= true | ($ᵗ blindable.Scalar) >>=
          fun f => pure (decide (blindable.blindPub pk f = target))] =
        (Fintype.card blindable.Scalar : ℝ≥0∞)⁻¹ :=
    fun pk hpk _ ht => CryptWalker.Sign.Blindable.blind_unlinkable blindable pk hpk ht

end CryptWalker.BACAP.Protocol

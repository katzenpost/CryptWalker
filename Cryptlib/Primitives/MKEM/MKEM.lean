/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # Multi-recipient KEM

The sender draws an ephemeral key pair, encrypts the payload once under a fresh message key, and
encrypts the message key to each recipient under a NIKE shared key (a DEK). A recipient can reply
under the same shared key, which the sender reads with the ephemeral private key. The generic
construction is `MKEMAdapter.mkemOfNike`.

Correctness is stated for the ciphertext reduced to one recipient's DEK (`forRecipient`).
Decapsulating the full ciphertext trial-decrypts the DEKs, which is correct only under AEAD
authenticity, a computational property. IND-CCA2 and recipient anonymity are likewise not laws.
The ciphertext byte encoding is not modelled. -/

namespace Cryptlib.Primitives.MKEM.MKEM

inductive MKEMError where
  | unsafePublicKey
  | degenerateSharedSecret
  | invalidKeySize
  | ciphertextTooShort
  | trialDecryptFailed
deriving DecidableEq

/-- The ephemeral public key, one DEK per recipient, and the sealed payload. -/
structure Ciphertext (PublicKey : Type) where
  ephPub : PublicKey
  deks : List ByteArray
  envelope : ByteArray

/-- The ciphertext with only DEK `i`. -/
def Ciphertext.forRecipient {PublicKey : Type} (ct : Ciphertext PublicKey) (i : Nat) :
    Ciphertext PublicKey :=
  { ct with deks := (ct.deks[i]?).toList }

structure MKEM where
  PrivateKey : Type
  PublicKey : Type

  /-- Public keys the scheme will compute with, as for `NIKE`. -/
  Safe : PublicKey → Prop
  [decSafe : DecidablePred Safe]

  State : Type
  [stateI : Inhabited State]

  name : String

  publicKeySize : Nat
  dekSize : Nat
  envelopeOverhead : Nat

  derivePublicKey : PrivateKey → PublicKey
  encodePublicKey : PublicKey → Vector UInt8 publicKeySize
  decodePublicKey : Vector UInt8 publicKeySize → Option PublicKey

  stateFromSeed : Vector UInt8 32 → State

  generate : EStateM MKEMError State (PublicKey × PrivateKey)

  /-- Also returns the ephemeral private key, for reading replies. -/
  encapsulate : List {pk : PublicKey // Safe pk} → ByteArray →
    EStateM MKEMError State (PrivateKey × Ciphertext PublicKey)

  decapsulate : PrivateKey → Ciphertext PublicKey → Except MKEMError ByteArray

  /-- A recipient's reply, sealed under its shared key with the sender's ephemeral key. -/
  envelopeReply : PrivateKey → {pk : PublicKey // Safe pk} → ByteArray →
    EStateM MKEMError State ByteArray

  decryptEnvelope : PrivateKey → {pk : PublicKey // Safe pk} → ByteArray →
    Except MKEMError ByteArray

  derive_safe : ∀ sk, Safe (derivePublicKey sk)

  decode_encode_pub : ∀ pk, decodePublicKey (encodePublicKey pk) = some pk

  generate_derive : ∀ s pk sk s', generate s = .ok (pk, sk) s' → pk = derivePublicKey sk

  /-- The ciphertext carries the public key of the returned ephemeral private key. -/
  encapsulate_ephPub : ∀ keys payload s eph ct s',
    encapsulate keys payload s = .ok (eph, ct) s' → ct.ephPub = derivePublicKey eph

  /-- One `dekSize` DEK per recipient, and an envelope `envelopeOverhead` longer than the
  payload. -/
  encapsulate_shape : ∀ keys payload s eph ct s',
    encapsulate keys payload s = .ok (eph, ct) s' →
      ct.deks.length = keys.length ∧ (∀ d ∈ ct.deks, d.size = dekSize) ∧
        ct.envelope.size = payload.size + envelopeOverhead

  /-- Recipient `i` recovers the payload from `ct.forRecipient i`. -/
  decapsulate_encapsulate : ∀ keys payload s eph ct s',
    encapsulate keys payload s = .ok (eph, ct) s' →
      ∀ i (hi : i < keys.length) sk,
        keys[i] = ⟨derivePublicKey sk, derive_safe sk⟩ →
          decapsulate sk (ct.forRecipient i) = .ok payload

  /-- The sender reads a recipient's reply with the ephemeral private key. -/
  decryptEnvelope_envelopeReply : ∀ sk eph pt s env s',
    envelopeReply sk ⟨derivePublicKey eph, derive_safe eph⟩ pt s = .ok env s' →
      decryptEnvelope eph ⟨derivePublicKey sk, derive_safe sk⟩ env = .ok pt

attribute [instance] MKEM.decSafe MKEM.stateI

end Cryptlib.Primitives.MKEM.MKEM

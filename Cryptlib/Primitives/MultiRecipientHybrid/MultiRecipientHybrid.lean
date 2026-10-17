/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # Multi-recipient hybrid encryption, over a KEM

Like `MKEM`, but over a `KEM`, which cannot combine a private key with another party's public key.
There is one KEM ciphertext per recipient. The payload is sealed once under a message key, which
is wrapped under each recipient's derived key (a DEK). Replies are sealed directly under the
derived key, which the sender keeps per recipient and the recipient recovers on decapsulation.

IND-CCA2 and recipient anonymity are computational and not laws. The ciphertext byte encoding is
not modelled. The generic construction is `Adapter.hybridOfKEM`. -/

namespace Cryptlib.Primitives.MultiRecipientHybrid.MultiRecipientHybrid

/-- `decapFailed` covers any error from the underlying `KEM.decap`. -/
inductive MultiRecipientHybridError where
  | invalidKeySize
  | ciphertextTooShort
  | trialDecryptFailed
  | decapFailed
deriving DecidableEq

/-- One KEM ciphertext and one DEK per recipient, and the sealed payload. -/
structure Ciphertext (KEMCiphertext : Type) where
  kemCiphertexts : List KEMCiphertext
  deks : List ByteArray
  envelope : ByteArray

/-- The ciphertext with only recipient `i`'s KEM ciphertext and DEK. -/
def Ciphertext.forRecipient {KEMCiphertext : Type} (ct : Ciphertext KEMCiphertext) (i : Nat) :
    Ciphertext KEMCiphertext :=
  { ct with
    kemCiphertexts := (ct.kemCiphertexts[i]?).toList
    deks := (ct.deks[i]?).toList }

structure MultiRecipientHybrid where
  PrivateKey : Type
  PublicKey : Type
  KEMCiphertext : Type
  [ctI : Inhabited KEMCiphertext]

  State : Type
  [stateI : Inhabited State]

  name : String

  publicKeySize : Nat
  kemCiphertextSize : Nat
  dekSize : Nat
  envelopeOverhead : Nat

  derivePublicKey : PrivateKey → PublicKey
  encodePublicKey : PublicKey → Vector UInt8 publicKeySize
  decodePublicKey : Vector UInt8 publicKeySize → Option PublicKey

  stateFromSeed : Vector UInt8 32 → State

  /-- States from which no recipient's encapsulation fails, as `KEM.Reliable`. -/
  Reliable : State → Prop := fun _ => True

  generate : EStateM MultiRecipientHybridError State (PublicKey × PrivateKey)

  /-- Also returns the per-recipient derived keys, in order, for reading replies. -/
  encapsulate : List PublicKey → ByteArray →
    EStateM MultiRecipientHybridError State (List ByteArray × Ciphertext KEMCiphertext)

  /-- Returns the derived key and the payload. -/
  decapsulate : PrivateKey → Ciphertext KEMCiphertext → Except MultiRecipientHybridError (ByteArray × ByteArray)

  /-- A reply sealed under a derived key. -/
  envelopeReply : ByteArray → ByteArray → EStateM MultiRecipientHybridError State ByteArray

  decryptEnvelope : ByteArray → ByteArray → Except MultiRecipientHybridError ByteArray

  decode_encode_pub : ∀ pk, decodePublicKey (encodePublicKey pk) = some pk

  /-- One KEM ciphertext, one `dekSize` DEK and one derived key per recipient, and an envelope
  `envelopeOverhead` longer than the payload. -/
  encapsulate_shape : ∀ keys payload s derivedKeys ct s',
    encapsulate keys payload s = .ok (derivedKeys, ct) s' →
      ct.kemCiphertexts.length = keys.length ∧ ct.deks.length = keys.length ∧
        derivedKeys.length = keys.length ∧ (∀ d ∈ ct.deks, d.size = dekSize) ∧
        ct.envelope.size = payload.size + envelopeOverhead

  /-- From a `Reliable` state, recipient `i` recovers the payload and the sender's derived key `k`
  from `ct.forRecipient i`. -/
  decapsulate_encapsulate : ∀ keys payload s, Reliable s → ∀ derivedKeys ct s',
    encapsulate keys payload s = .ok (derivedKeys, ct) s' →
      ∀ i (hi : i < keys.length) sk k,
        keys[i] = derivePublicKey sk → derivedKeys[i]? = some k →
          decapsulate sk (ct.forRecipient i) = .ok (k, payload)

  /-- Replies round-trip under the same key. -/
  decryptEnvelope_envelopeReply : ∀ key pt s env s',
    envelopeReply key pt s = .ok env s' → decryptEnvelope key env = .ok pt

attribute [instance] MultiRecipientHybrid.ctI MultiRecipientHybrid.stateI

end Cryptlib.Primitives.MultiRecipientHybrid.MultiRecipientHybrid

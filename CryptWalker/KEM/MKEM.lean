/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # Multi-recipient KEM

The same shape as `NIKE`, `KEM`, `AEAD` and `Signature`: a plain structure whose operations are
fields and whose laws are proposition fields, so no instance can exist without discharging them.
Models `hpqc/kem/mkem` (`mkem.go`, `ciphertext.go`); the generic construction from a NIKE, an AEAD
and a hash is `MKEMAdapter.mkemOfNike`.

## What it is

One payload, several recipients. The sender makes an ephemeral key pair, derives one shared key per
recipient, encrypts the payload once under a fresh message key, and encrypts that message key to
each recipient (a *DEK*). The ciphertext is `(ephemeral public key, DEKs, envelope)`. A recipient
opens its DEK and then the envelope. A recipient can also *reply* under the same shared key, so the
sender, who kept the ephemeral private key, reads the reply with no further key exchange.

## Why correctness is stated per recipient

`hpqc` never gives a recipient the whole ciphertext. `TestMKEMProtocol` hands each replica a
ciphertext carrying **only its own DEK**, and in Pigeonhole the courier makes that split
(`courier_envelope` carries `dek1` and `dek2`). `Ciphertext.forRecipient` is that split.

Decapsulating the *whole* ciphertext tries the DEKs in order and takes the first that opens, so it
is correct only if no earlier DEK opens under this recipient's key. That is authenticity of the
underlying AEAD, which is computational, so it cannot be a field (see `AEAD`). For the per-recipient
ciphertext the question does not arise, so `decapsulate_encapsulate` is unconditional.

## What cannot be a law here

IND-CCA2 of the ciphertext, and recipient anonymity (a recipient learns nothing about who else was
addressed), quantify over adversaries and negligible functions, so, as for `AEAD` and `Hash`,
attempting to state them would produce a proposition no instance could discharge.

Randomness lives in `State` and `EStateM`, as `KEM.encap` does; the deterministic operations return
`Except`.

**Not modelled:** the ciphertext's byte encoding (`hpqc` marshals it as CBOR; Pigeonhole's
`courier_envelope` carries the pieces as separate fixed-size fields), so there is no ciphertext
codec here. -/

namespace CryptWalker.KEM.MKEM

/-- What can go wrong, following `hpqc`'s sentinel errors plus the `Safe` gate `NIKE` carries. -/
inductive MKEMError where
  | unsafePublicKey
  | degenerateSharedSecret
  | invalidKeySize
  | ciphertextTooShort
  | trialDecryptFailed
deriving DecidableEq

/-- An MKEM ciphertext, exactly `hpqc`'s: the sender's ephemeral public key, one DEK per recipient,
and the payload sealed under the message key. -/
structure Ciphertext (PublicKey : Type) where
  ephPub : PublicKey
  deks : List ByteArray
  envelope : ByteArray

/-- The ciphertext a single recipient is handed: everything, but only DEK `i`. -/
def Ciphertext.forRecipient {PublicKey : Type} (ct : Ciphertext PublicKey) (i : Nat) :
    Ciphertext PublicKey :=
  { ct with deks := (ct.deks[i]?).toList }

structure MKEM where
  PrivateKey : Type
  PublicKey : Type

  /-- Public keys the scheme will compute with, as for `NIKE`: right subgroup, non-degenerate. -/
  Safe : PublicKey → Prop
  [decSafe : DecidablePred Safe]

  /-- The randomness the scheme draws from. As for `KEM`, a state a scheme is actually run against
  carries its randomness and must be supplied by the caller. -/
  State : Type
  [stateI : Inhabited State]

  name : String

  publicKeySize : Nat
  /-- The width of one DEK. `hpqc`'s `DEKSize`, 60 for ChaCha20-Poly1305: a 12-byte nonce, a
  32-byte message key, a 16-byte tag. Pigeonhole's wire format fixes it. -/
  dekSize : Nat
  /-- How much longer the envelope is than the payload. -/
  envelopeOverhead : Nat

  derivePublicKey : PrivateKey → PublicKey
  encodePublicKey : PublicKey → Vector UInt8 publicKeySize
  decodePublicKey : Vector UInt8 publicKeySize → Option PublicKey

  /-- Seed the scheme's randomness deterministically, as `KEM.stateFromSeed`. -/
  stateFromSeed : Vector UInt8 32 → State

  generate : EStateM MKEMError State (PublicKey × PrivateKey)

  /-- Encrypt one payload to every recipient. Returns the ephemeral private key, which the sender
  keeps to read replies. -/
  encapsulate : List {pk : PublicKey // Safe pk} → ByteArray →
    EStateM MKEMError State (PrivateKey × Ciphertext PublicKey)

  decapsulate : PrivateKey → Ciphertext PublicKey → Except MKEMError ByteArray

  /-- A recipient's reply, sealed under the key it shares with the sender's ephemeral key. -/
  envelopeReply : PrivateKey → {pk : PublicKey // Safe pk} → ByteArray →
    EStateM MKEMError State ByteArray

  decryptEnvelope : PrivateKey → {pk : PublicKey // Safe pk} → ByteArray →
    Except MKEMError ByteArray

  derive_safe : ∀ sk, Safe (derivePublicKey sk)

  decode_encode_pub : ∀ pk, decodePublicKey (encodePublicKey pk) = some pk

  generate_derive : ∀ s pk sk s', generate s = .ok (pk, sk) s' → pk = derivePublicKey sk

  /-- The ciphertext carries the public half of the private key `encapsulate` returns. -/
  encapsulate_ephPub : ∀ keys payload s eph ct s',
    encapsulate keys payload s = .ok (eph, ct) s' → ct.ephPub = derivePublicKey eph

  /-- The shape of a ciphertext: one DEK per recipient, each exactly `dekSize`, and an envelope
  `envelopeOverhead` longer than the payload. Ciphertext length therefore leaks the payload length
  and the number of recipients, and nothing else, which is what lets Pigeonhole fix its packet
  size. -/
  encapsulate_shape : ∀ keys payload s eph ct s',
    encapsulate keys payload s = .ok (eph, ct) s' →
      ct.deks.length = keys.length ∧ (∀ d ∈ ct.deks, d.size = dekSize) ∧
        ct.envelope.size = payload.size + envelopeOverhead

  /-- **A recipient recovers the payload.** If `encapsulate` succeeded, recipient `i`, holding the
  private key of the `i`-th public key, decapsulates the ciphertext it is handed, the one carrying
  only its own DEK. -/
  decapsulate_encapsulate : ∀ keys payload s eph ct s',
    encapsulate keys payload s = .ok (eph, ct) s' →
      ∀ i (hi : i < keys.length) sk,
        keys[i] = ⟨derivePublicKey sk, derive_safe sk⟩ →
          decapsulate sk (ct.forRecipient i) = .ok payload

  /-- **Replies round-trip.** The sender, who kept the ephemeral private key `eph`, reads what
  recipient `sk` sealed for it. -/
  decryptEnvelope_envelopeReply : ∀ sk eph pt s env s',
    envelopeReply sk ⟨derivePublicKey eph, derive_safe eph⟩ pt s = .ok env s' →
      decryptEnvelope eph ⟨derivePublicKey sk, derive_safe sk⟩ env = .ok pt

attribute [instance] MKEM.decSafe MKEM.stateI

end CryptWalker.KEM.MKEM

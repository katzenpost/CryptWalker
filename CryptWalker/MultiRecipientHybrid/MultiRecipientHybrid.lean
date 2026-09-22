/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # Multi-recipient hybrid encryption, over a KEM

The same shape as `MKEM`, `NIKE`, `KEM`, `AEAD` and `Hash`: a plain structure whose operations are
fields and whose laws are proposition fields. The generic construction from a `KEM`, an `AEAD` and
a `Hash` is `Adapter.hybridOfKEM`.

## Why this is not `MKEM`

`MKEM` is built over a `NIKE`, and its `envelopeReply`/`decryptEnvelope` take a private key
*together with an arbitrary other party's public key* — a NIKE's symmetric `combine(myPriv,
theirPub)` operation. A `KEM` has no such operation: `encap` binds its ciphertext to one specific
public key, and `decap` only recovers a secret from a ciphertext produced for the matching key
pair. There is nothing to combine a private key with a second, different party's public key. So a
`KEM` cannot instantiate `MKEM`, and building a genuinely KEM-based multi-recipient scheme needs a
different shape, this one.

## The construction

One payload, several recipients, as in `MKEM`, but the key-establishment step can't be shared: a
NIKE lets one ephemeral private key be combined against every recipient's public key in turn, so
the ciphertext carries one ephemeral public key regardless of recipient count; a KEM's `encap`
produces a ciphertext bound to exactly the one public key it was run against, so **there is one KEM
ciphertext per recipient**, not one shared value.

What doesn't change: the payload is still encrypted exactly once. `encapsulate` draws a random
message key, seals the payload under it (the `envelope`), then independently KEM-encapsulates to
each recipient and wraps the message key under each recipient's own derived key (a `dek`, exactly
`MKEM`'s DEK). A recipient decapsulates its own ciphertext, opens its own `dek`, then the shared
`envelope`.

Replies need no combine operation at all: `encapsulate` hands the sender the list of derived keys
it used, one per recipient (in the same order as the input keys), which the sender must retain to
read that recipient's reply. `decapsulate` hands the recipient back that same derived key, recovered
independently, alongside the payload. Both sides now hold identical raw bytes, so `envelopeReply`/
`decryptEnvelope` are a plain symmetric round trip under that key — simpler than `MKEM`'s version of
the same law, which has to go via `derivePublicKey`/`Safe` on both ends.

## What cannot be a law here

As for `MKEM`: IND-CCA2 of the ciphertext and recipient anonymity are computational, so neither can
be a field.

**Not modelled:** the ciphertext's byte encoding, as for `MKEM`. -/

namespace CryptWalker.MultiRecipientHybrid.MultiRecipientHybrid

/-- What can go wrong. `decapFailed` covers the underlying `KEM`'s own `decap` erroring (a
`badCiphertext`/`unsafePublicKey` from `KEM.KEMError`), folded into one case here since a caller of
`MultiRecipientHybrid` never needs to distinguish which. -/
inductive MultiRecipientHybridError where
  | invalidKeySize
  | ciphertextTooShort
  | trialDecryptFailed
  | decapFailed
deriving DecidableEq

/-- A ciphertext addressed to several recipients: one KEM ciphertext per recipient (no shared
ephemeral value is possible, see the module doc), one DEK per recipient, and the payload sealed
once under the message key. -/
structure Ciphertext (KEMCiphertext : Type) where
  kemCiphertexts : List KEMCiphertext
  deks : List ByteArray
  envelope : ByteArray

/-- The ciphertext a single recipient is handed: everything, but only its own KEM ciphertext and
DEK — the courier's split, exactly `MKEM.Ciphertext.forRecipient`. -/
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

  /-- The randomness the scheme draws from, as for `MKEM.State`. -/
  State : Type
  [stateI : Inhabited State]

  name : String

  publicKeySize : Nat
  kemCiphertextSize : Nat
  /-- The width of one DEK, as `MKEM.dekSize`. -/
  dekSize : Nat
  /-- How much longer the envelope is than the payload. -/
  envelopeOverhead : Nat

  derivePublicKey : PrivateKey → PublicKey
  encodePublicKey : PublicKey → Vector UInt8 publicKeySize
  decodePublicKey : Vector UInt8 publicKeySize → Option PublicKey

  stateFromSeed : Vector UInt8 32 → State

  /-- Which pre-`encapsulate` states are guaranteed not to trigger the underlying `KEM`'s rare
  decoding failure — `KEM.Reliable` lifted here, since `encapsulate` runs that `KEM`'s `encap`
  once per recipient. Defaults to `True`, right for a Diffie-Hellman-based `KEM` (`kemOfNike`,
  whose own `Reliable` is already trivial). An instance built over a lattice `KEM` (ML-KEM)
  inherits that `KEM`'s real, non-trivial condition instead, since `decapsulate_encapsulate` below
  can only hold for a draw the underlying `KEM` itself would decode correctly. -/
  Reliable : State → Prop := fun _ => True

  /-- A fresh keypair, for a caller that wants one (as `MKEM.generate`). No `generate_derive`-style
  law connects its result to `derivePublicKey`, unlike `MKEM`: the underlying `KEM.generate`'s
  returned public key is only proved paired with its own private key through an existential
  witness folded into its dependent return type, not exposed as a standalone equation — so this
  cannot be proved generically over an arbitrary `KEM`, only over one construction's own
  `generate`. Nothing here needs it: `encapsulate`/`decapsulate` never go through `generate`. -/
  generate : EStateM MultiRecipientHybridError State (PublicKey × PrivateKey)

  /-- Encrypt one payload to every recipient. Returns the list of per-recipient derived keys, in
  the same order as `keys`, which the sender must retain to read that recipient's reply — there is
  no compact reusable secret the way `MKEM.encapsulate`'s ephemeral private key is one. -/
  encapsulate : List PublicKey → ByteArray →
    EStateM MultiRecipientHybridError State (List ByteArray × Ciphertext KEMCiphertext)

  /-- Decrypt the ciphertext this recipient was handed. Returns the derived key it recovered
  alongside the payload — the recipient needs that key back to seal a reply. -/
  decapsulate : PrivateKey → Ciphertext KEMCiphertext → Except MultiRecipientHybridError (ByteArray × ByteArray)

  /-- A recipient's reply, sealed directly under the raw derived key both sides already hold — no
  combine operation, unlike `MKEM.envelopeReply`. -/
  envelopeReply : ByteArray → ByteArray → EStateM MultiRecipientHybridError State ByteArray

  decryptEnvelope : ByteArray → ByteArray → Except MultiRecipientHybridError ByteArray

  decode_encode_pub : ∀ pk, decodePublicKey (encodePublicKey pk) = some pk

  /-- The shape of a ciphertext: one KEM ciphertext and one DEK per recipient, each DEK exactly
  `dekSize`, an envelope `envelopeOverhead` longer than the payload, and one derived key retained
  per recipient. -/
  encapsulate_shape : ∀ keys payload s derivedKeys ct s',
    encapsulate keys payload s = .ok (derivedKeys, ct) s' →
      ct.kemCiphertexts.length = keys.length ∧ ct.deks.length = keys.length ∧
        derivedKeys.length = keys.length ∧ (∀ d ∈ ct.deks, d.size = dekSize) ∧
        ct.envelope.size = payload.size + envelopeOverhead

  /-- **A recipient recovers the payload, and the derived key the sender used for it** — given
  `encapsulate`'s state was `Reliable`. Per-recipient, with no cross-recipient hypothesis, since
  each recipient's KEM ciphertext is independent (unlike `MKEM`, this needs `Reliable`: unlike a
  NIKE's Diffie-Hellman, a general `KEM`'s decapsulation is not unconditionally correct).
  `derivedKeys[i]? = some k` rather than indexing `derivedKeys` directly, so the law needs no proof
  of `i < derivedKeys.length` folded into its own statement (that fact is `encapsulate_shape`'s, a
  separate field). -/
  decapsulate_encapsulate : ∀ keys payload s, Reliable s → ∀ derivedKeys ct s',
    encapsulate keys payload s = .ok (derivedKeys, ct) s' →
      ∀ i (hi : i < keys.length) sk k,
        keys[i] = derivePublicKey sk → derivedKeys[i]? = some k →
          decapsulate sk (ct.forRecipient i) = .ok (k, payload)

  /-- **Replies round-trip.** A plain symmetric round trip under a raw key both sides hold — no
  `derivePublicKey`/`Safe` involved, unlike `MKEM.decryptEnvelope_envelopeReply`. -/
  decryptEnvelope_envelopeReply : ∀ key pt s env s',
    envelopeReply key pt s = .ok env s' → decryptEnvelope key env = .ok pt

attribute [instance] MultiRecipientHybrid.ctI MultiRecipientHybrid.stateI

end CryptWalker.MultiRecipientHybrid.MultiRecipientHybrid

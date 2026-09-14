/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/
namespace CryptWalker.NIKE.NIKE


structure NIKE where
  PrivateKey   : Type
  PublicKey    : Type
  SharedSecret : Type

  name : String

  privateKeySize   : Nat
  publicKeySize    : Nat
  sharedSecretSize : Nat

  -- Elements the group action is defined on: right subgroup, non-degenerate.
  Safe : PublicKey → Prop
  [decSafe : DecidablePred Safe]

  privateKeyFromSeed : Vector UInt8 32 → PrivateKey
  derivePublicKey    : PrivateKey → PublicKey

  -- Cannot be called without a safety proof.
  groupAction : PrivateKey → (pk : PublicKey) → Safe pk → SharedSecret

  encodePrivateKey   : PrivateKey   → Vector UInt8 privateKeySize
  decodePrivateKey   : Vector UInt8 privateKeySize → Option PrivateKey
  encodePublicKey    : PublicKey    → Vector UInt8 publicKeySize
  decodePublicKey    : Vector UInt8 publicKeySize  → Option PublicKey
  encodeSharedSecret : SharedSecret → Vector UInt8 sharedSecretSize

  -- Laws.
  derive_safe : ∀ sk, Safe (derivePublicKey sk)
  decode_encode_priv : ∀ sk, decodePrivateKey (encodePrivateKey sk) = some sk
  decode_encode_pub  : ∀ pk, decodePublicKey  (encodePublicKey  pk) = some pk

  -- Encodings are canonical: no two byte strings decode to the same key.
  encode_decode_pub : ∀ v pk, decodePublicKey v = some pk → encodePublicKey pk = v

  commutes : ∀ sk₁ sk₂,
    groupAction sk₁ (derivePublicKey sk₂) (derive_safe sk₂)
      = groupAction sk₂ (derivePublicKey sk₁) (derive_safe sk₁)

  -- Re-blinding chain: what makes Sphinx's iterated group-element blinding telescope, generic
  -- over any Diffie-Hellman-style NIKE.

  /-- Reinterpret a shared secret as a public key: the operation Sphinx's blinding chain performs
  at each hop after the first (re-decoding an already-blinded group element's bytes). Not
  meaningful for a non-DH NIKE, but nothing here requires a scheme registered as `NIKE` to support
  Sphinx's blinding chain in the first place — a scheme that never needs it may implement this
  however it likes, so long as it satisfies the two laws below. -/
  reinterpret : SharedSecret → PublicKey

  /-- Acting on a safe public key with `groupAction`, then reinterpreting the result, stays safe —
  what lets the chain apply a *further* group action to it. -/
  reinterpret_safe : ∀ sk pk (h : Safe pk), Safe (reinterpret (groupAction sk pk h))

  /-- **The Diffie-Hellman identity, generalized to a re-blinded chain**: acting with a further
  private key on a *reinterpreted* shared secret gives the same result regardless of which of two
  private keys was applied first. `commutes` above only covers a single hop (two honestly-derived
  public keys); this is what `createHeader`'s *iterated* blinding chain needs beyond that, once
  later hops act on a previously-blinded (not freshly-derived) element. -/
  groupAction_comm : ∀ sk₁ sk₂ pk (h : Safe pk),
    groupAction sk₁ (reinterpret (groupAction sk₂ pk h)) (reinterpret_safe sk₂ pk h)
      = groupAction sk₂ (reinterpret (groupAction sk₁ pk h)) (reinterpret_safe sk₁ pk h)

attribute [instance] NIKE.decSafe


end CryptWalker.NIKE.NIKE

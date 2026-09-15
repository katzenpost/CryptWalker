/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/
import CryptWalker.Util.Bytes

namespace CryptWalker.NIKE.NIKE

open CryptWalker.Util.Bytes (ofVector)


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

  /-- `decodePrivateKey` never fails on a well-formed-width byte string. Rules out a pathological
  instance where some private-key-sized byte strings fail to decode (falling back to raw bytes as
  a stand-in "public key," per `NIKESphinx.nikeSelfPublicKeyBytes`'s documented fallback) while
  still satisfying every other law here — free for both concrete instances this project builds
  (`decodePrivateKey := fun v => some ⟨v⟩`). `KEM.Adapter.kemOfNike` reuses this directly for its
  own `KEM.decodePrivateKey_total`. -/
  decodePrivateKey_total : ∀ v, ∃ sk, decodePrivateKey v = some sk

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

  /-- A Diffie-Hellman-style NIKE's public keys and shared secrets are the same kind of group
  element, just tagged by type — what actually lets `reinterpret` make sense as "the bytes are
  already the right shape, just re-decode them." True for both `NIKE`s this project builds
  (`32 = 32`/`keySize = keySize`), by `rfl` for each. -/
  publicKeySize_eq_sharedSecretSize : publicKeySize = sharedSecretSize

  /-- **`reinterpret`, at the byte level**: encoding a reinterpreted shared secret gives the same
  bytes as encoding the shared secret directly. `NIKESphinx.nikeBlind` never actually calls
  `reinterpret` (a typed operation) — it only ever has raw bytes in hand, so it re-blinds by
  encoding the DH output and reinterpreting *those bytes* directly as a public-key-shaped byte
  string (`ofVector (toVecN pk.size ...)`, sized to `publicKeySize`, matching
  `publicKeySize_eq_sharedSecretSize` above). This law is what proves that byte-level maneuver
  actually computes the same thing `reinterpret` does — true for both `NIKE`s this project builds
  (`reinterpret := id`/`fun ss => ⟨ss.data⟩`, and `encodePublicKey`/`encodeSharedSecret` are
  literally the same extraction either way), by `rfl` for each. -/
  encodePublicKey_reinterpret : ∀ ss : SharedSecret,
    ofVector (encodePublicKey (reinterpret ss)) = ofVector (encodeSharedSecret ss)

attribute [instance] NIKE.decSafe

/-! ## The re-blinding chain telescopes

The fact `NIKESphinx.createHeader`'s iterated blinding and `NIKESphinx.unwrapNIKE`'s iterated
peeling rely on: a target key's shared secret with a client's ephemeral key, re-blinded hop by
hop, is recovered exactly whether the target key acts once at the end (the sender's view,
building the header) or the *later* hops act on an already-blinded element while the target acts
on its own turn (the receiver's view, unwrapping one layer at a time). `commutes` handles zero
re-blindings (the first hop); `groupAction_comm` handles peeling one more — this is the whole
group-theoretic content `wrapNIKE_unwrapNIKE_complete` needs; everything else is byte-level
bookkeeping (MAC agreement, routing-info decryption, the payload cipher) already proved the same
way for KEM-Sphinx. -/

/-- The group element a client's ephemeral key becomes after `n` rounds of blinding by
`f 0, f 1, ..., f (n-1)` in order — `NIKESphinx.nikeBlind` applied `n` times, abstractly. Paired
with a proof it's always `Safe`, needed to apply the next round. -/
def telescopeElem (nike : NIKE) (baseSk : nike.PrivateKey) (f : Nat → nike.PrivateKey) :
    Nat → {pk : nike.PublicKey // nike.Safe pk}
  | 0 => ⟨nike.derivePublicKey baseSk, nike.derive_safe baseSk⟩
  | n + 1 =>
    let prev := telescopeElem nike baseSk f n
    ⟨nike.reinterpret (nike.groupAction (f n) prev.1 prev.2),
      nike.reinterpret_safe (f n) prev.1 prev.2⟩

/-- The shared secret a `target` key and the client's ephemeral key agree on, from the *sender's*
side: DH with the target's own public key, then re-blinded by the same `n` factors in the same
order — `NIKESphinx.createHeader`'s own `sharedSecret` loop, abstractly. Paired with a proof its
reinterpretation is `Safe`, needed to apply the next round the same way `telescopeElem` does. -/
def telescopeSecret (nike : NIKE) (baseSk targetSk : nike.PrivateKey) (f : Nat → nike.PrivateKey) :
    Nat → {ss : nike.SharedSecret // nike.Safe (nike.reinterpret ss)}
  | 0 =>
    ⟨nike.groupAction baseSk (nike.derivePublicKey targetSk) (nike.derive_safe targetSk),
      nike.reinterpret_safe baseSk (nike.derivePublicKey targetSk) (nike.derive_safe targetSk)⟩
  | n + 1 =>
    let prev := telescopeSecret nike baseSk targetSk f n
    ⟨nike.groupAction (f n) (nike.reinterpret prev.1) prev.2,
      nike.reinterpret_safe (f n) (nike.reinterpret prev.1) prev.2⟩

/-- **The re-blinding chain telescopes.** After `n` rounds, `targetSk` acting on the re-blinded
element agrees exactly with the sender's own re-blinded DH secret — regardless of `n`. `n = 0` is
exactly `commutes`; each further round is exactly `groupAction_comm`, folding the induction
hypothesis one layer deeper. -/
theorem telescope_agree (nike : NIKE) (baseSk targetSk : nike.PrivateKey) (f : Nat → nike.PrivateKey)
    (n : Nat) :
    nike.groupAction targetSk (telescopeElem nike baseSk f n).1 (telescopeElem nike baseSk f n).2
      = (telescopeSecret nike baseSk targetSk f n).1 := by
  induction n with
  | zero => exact nike.commutes targetSk baseSk
  | succ n ih =>
    have h := nike.groupAction_comm targetSk (f n) (telescopeElem nike baseSk f n).1
      (telescopeElem nike baseSk f n).2
    refine h.trans ?_
    congr 1
    exact congrArg nike.reinterpret ih

end CryptWalker.NIKE.NIKE

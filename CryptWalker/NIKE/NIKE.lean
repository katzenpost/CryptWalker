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

  -- Public keys the group action is defined on.
  Safe : PublicKey → Prop
  [decSafe : DecidablePred Safe]

  privateKeyFromSeed : Vector UInt8 32 → PrivateKey
  derivePublicKey    : PrivateKey → PublicKey

  -- Requires a proof that the peer public key is `Safe`.
  groupAction : PrivateKey → {pk : PublicKey // Safe pk} → SharedSecret

  encodePrivateKey   : PrivateKey   → Vector UInt8 privateKeySize
  decodePrivateKey   : Vector UInt8 privateKeySize → Option PrivateKey
  encodePublicKey    : PublicKey    → Vector UInt8 publicKeySize
  decodePublicKey    : Vector UInt8 publicKeySize  → Option PublicKey
  encodeSharedSecret : SharedSecret → Vector UInt8 sharedSecretSize

  -- Laws.
  derive_safe : ∀ sk, Safe (derivePublicKey sk)
  decode_encode_priv : ∀ sk, decodePrivateKey (encodePrivateKey sk) = some sk
  decode_encode_pub  : ∀ pk, decodePublicKey  (encodePublicKey  pk) = some pk

  /-- Every byte string of the right width decodes to a private key. -/
  decodePrivateKey_total : ∀ v, ∃ sk, decodePrivateKey v = some sk

  -- Encodings are canonical: no two byte strings decode to the same key.
  encode_decode_pub : ∀ v pk, decodePublicKey v = some pk → encodePublicKey pk = v

  commutes : ∀ sk₁ sk₂,
    groupAction sk₁ ⟨derivePublicKey sk₂, derive_safe sk₂⟩
      = groupAction sk₂ ⟨derivePublicKey sk₁, derive_safe sk₁⟩

  -- Iterated group action: a shared secret is itself a group element and can be acted on again.

  /-- Reinterpret a shared secret as a public key. -/
  reinterpret : SharedSecret → PublicKey

  /-- The group action maps safe elements to safe elements. -/
  reinterpret_safe : ∀ sk (spk : {pk : PublicKey // Safe pk}), Safe (reinterpret (groupAction sk spk))

  /-- Group actions by two private keys commute on any safe element, not only on derived public
  keys as in `commutes`. -/
  groupAction_comm : ∀ sk₁ sk₂ (spk : {pk : PublicKey // Safe pk}),
    groupAction sk₁ ⟨reinterpret (groupAction sk₂ spk), reinterpret_safe sk₂ spk⟩
      = groupAction sk₂ ⟨reinterpret (groupAction sk₁ spk), reinterpret_safe sk₁ spk⟩

  /-- Public keys and shared secrets have the same encoded size. -/
  publicKeySize_eq_sharedSecretSize : publicKeySize = sharedSecretSize

  /-- `reinterpret` preserves the encoding. -/
  encodePublicKey_reinterpret : ∀ ss : SharedSecret,
    ofVector (encodePublicKey (reinterpret ss)) = ofVector (encodeSharedSecret ss)

attribute [instance] NIKE.decSafe

/-! ## Iterated group action

Acting on a base public key with `f 0, ..., f (n-1)` and then `targetSk` gives the same result as
acting on `targetSk`'s public key with the base key and then `f 0, ..., f (n-1)`. -/

/-- The base public key after `n` group actions by `f 0, ..., f (n-1)`. -/
def telescopeElem (nike : NIKE) (baseSk : nike.PrivateKey) (f : Nat → nike.PrivateKey) :
    Nat → {pk : nike.PublicKey // nike.Safe pk}
  | 0 => ⟨nike.derivePublicKey baseSk, nike.derive_safe baseSk⟩
  | n + 1 =>
    let prev := telescopeElem nike baseSk f n
    ⟨nike.reinterpret (nike.groupAction (f n) prev), nike.reinterpret_safe (f n) prev⟩

/-- The base key's shared secret with `targetSk`, then `n` group actions by `f 0, ..., f (n-1)`. -/
def telescopeSecret (nike : NIKE) (baseSk targetSk : nike.PrivateKey) (f : Nat → nike.PrivateKey) :
    Nat → {ss : nike.SharedSecret // nike.Safe (nike.reinterpret ss)}
  | 0 =>
    ⟨nike.groupAction baseSk ⟨nike.derivePublicKey targetSk, nike.derive_safe targetSk⟩,
      nike.reinterpret_safe baseSk ⟨nike.derivePublicKey targetSk, nike.derive_safe targetSk⟩⟩
  | n + 1 =>
    let prev := telescopeSecret nike baseSk targetSk f n
    ⟨nike.groupAction (f n) ⟨nike.reinterpret prev.1, prev.2⟩,
      nike.reinterpret_safe (f n) ⟨nike.reinterpret prev.1, prev.2⟩⟩

/-- `targetSk` acting on `telescopeElem n` equals `telescopeSecret n`. -/
theorem telescope_agree (nike : NIKE) (baseSk targetSk : nike.PrivateKey) (f : Nat → nike.PrivateKey)
    (n : Nat) :
    nike.groupAction targetSk (telescopeElem nike baseSk f n)
      = (telescopeSecret nike baseSk targetSk f n).1 := by
  induction n with
  | zero => exact nike.commutes targetSk baseSk
  | succ n ih =>
    have h := nike.groupAction_comm targetSk (f n) (telescopeElem nike baseSk f n)
    refine h.trans ?_
    congr 1
    exact Subtype.ext (congrArg nike.reinterpret ih)

end CryptWalker.NIKE.NIKE

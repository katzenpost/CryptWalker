/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

import CryptWalker.KEM.KEM
import CryptWalker.NIKE.NIKE

/-!
# NIKE to KEM adapter: hashed ElGamal

```
ENCAPSULATE(pk_static):
    eph_sk, eph_pk := GEN_KEYPAIR(RNG)
    ss             := DH(eph_sk, pk_static)
    ct             := ENCODE_PUBKEY(eph_pk)
    shared_key     := KEYED(deriveKey(ss), ENCODE(pk_static) || ENCODE(eph_pk))
    return ct, shared_key

DECAPSULATE(sk_static, ct):
    eph_pk     := DECODE_PUBKEY(ct)
    ss         := DH(sk_static, eph_pk)
    shared_key := KEYED(deriveKey(ss), ENCODE(pub(sk_static)) || ENCODE(eph_pk))
    return shared_key
```

The key is a PRF keyed by `ss` over the static key then the ephemeral key.
Encapsulation and decapsulation reject public keys that are not `NIKE.Safe`.
-/

namespace CryptWalker.KEM.Adapter

open CryptWalker.NIKE.NIKE
open CryptWalker.KEM.KEM

abbrev Bytes32 := Vector UInt8 32

def toBytes {n} (v : Vector UInt8 n) : ByteArray := ⟨v.toArray⟩

/-- Shared-key derivation: `derive ss pkStatic pkEph outLen` returns `outLen` bytes. -/
structure PRF where
  /-- Identifier used in test vectors, e.g. `"sha256-v1"`. -/
  name : String
  derive : ByteArray → ByteArray → ByteArray → (outLen : Nat) → Vector UInt8 outLen

variable (F : PRF) (nike : NIKE)

/-- Counter plus an inexhaustible seed stream. -/
abbrev St := Nat × (Nat → Bytes32)

def nextSeed : EStateM KEMError St Bytes32 :=
  fun (i, str) => .ok (str i) (i + 1, str)

/-- Initial state over a caller-supplied seed stream, which must be unpredictable. -/
def initWith (str : Nat → Bytes32) : St := (0, str)

/-- The shared key: the PRF over the static then ephemeral public key, at the NIKE's
shared-secret width. -/
def derive (ss : Vector UInt8 nike.sharedSecretSize)
    (staticPk ephPk : Vector UInt8 nike.publicKeySize) :
    Vector UInt8 nike.sharedSecretSize :=
  F.derive (toBytes ss) (toBytes staticPk) (toBytes ephPk) nike.sharedSecretSize

def encapM (pk : nike.PublicKey) :
    EStateM KEMError St (nike.PublicKey × Vector UInt8 nike.sharedSecretSize) := do
  let seed ← nextSeed
  let eph := nike.privateKeyFromSeed seed
  if h : nike.Safe pk then
    pure (nike.derivePublicKey eph,
          derive F nike (nike.encodeSharedSecret (nike.groupAction eph ⟨pk, h⟩))
            (nike.encodePublicKey pk)
            (nike.encodePublicKey (nike.derivePublicKey eph)))
  else
    EStateM.throw .unsafePublicKey

def decapM (sk : nike.PrivateKey) (ct : nike.PublicKey) :
    EStateM KEMError St (Vector UInt8 nike.sharedSecretSize) :=
  if h : nike.Safe ct then
    pure (derive F nike (nike.encodeSharedSecret (nike.groupAction sk ⟨ct, h⟩))
            (nike.encodePublicKey (nike.derivePublicKey sk))
            (nike.encodePublicKey ct))
  else
    EStateM.throw .unsafePublicKey

/-- `nextSeed` advances the counter by exactly one and leaves the stream alone. -/
theorem nextSeed_consumes (i : Nat) (str : Nat → Bytes32) :
    nextSeed (i, str) = .ok (str i) (i + 1, str) := rfl

theorem encapM_consumes (pk : nike.PublicKey) (i : Nat) (str : Nat → Bytes32) :
    (∃ r, encapM F nike pk (i, str) = .ok r (i + 1, str))
      ∨ encapM F nike pk (i, str) = .error .unsafePublicKey (i + 1, str) := by
  simp only [encapM, nextSeed, bind, EStateM.bind, pure]
  split
  · exact Or.inl ⟨_, rfl⟩
  · exact Or.inr rfl

/-- Consecutive encapsulations use different seeds if the stream is injective. -/
theorem encap_seeds_distinct (i : Nat) (str : Nat → Bytes32)
    (hinj : ∀ m n, m ≠ n → str m ≠ str n) :
    str i ≠ str (i + 1) :=
  hinj i (i + 1) (Nat.ne_of_lt (Nat.lt_succ_self i))

/-- Decapsulation recovers the encapsulated key for `derivePublicKey sk`. The `True`
hypothesis is `kemOfNike`'s `Reliable`. -/
theorem roundTrip (sk : nike.PrivateKey) :
    ∀ s, True → ∀ c k s', encapM F nike (nike.derivePublicKey sk) s = .ok (c, k) s' →
      ∀ t, ∃ t', decapM F nike sk c t = .ok k t' := by
  rintro ⟨i, str⟩ - c k s' hEnc t
  simp only [encapM, nextSeed, bind, EStateM.bind, pure, EStateM.pure,
             dif_pos (nike.derive_safe sk)] at hEnc
  injection hEnc with hval _
  injection hval with hc hk
  subst hc; subst hk
  simp only [decapM, dif_pos (nike.derive_safe _)]
  refine ⟨t, ?_⟩
  simp only [pure, EStateM.pure]
  rw [nike.commutes sk (nike.privateKeyFromSeed (str i))]

def kemOfNike : KEM where
  State        := St
  PublicKey    := nike.PublicKey
  PrivateKey   := nike.PrivateKey
  Ciphertext   := nike.PublicKey
  Plaintext    := Vector UInt8 nike.sharedSecretSize

  pubI  := ⟨nike.derivePublicKey (nike.privateKeyFromSeed (Vector.replicate 32 0))⟩
  privI := ⟨nike.privateKeyFromSeed (Vector.replicate 32 0)⟩
  ctI   := ⟨nike.derivePublicKey (nike.privateKeyFromSeed (Vector.replicate 32 0))⟩
  ptI   := ⟨Vector.replicate nike.sharedSecretSize 0⟩

  publicKeySize  := nike.publicKeySize
  privateKeySize := nike.privateKeySize
  ciphertextSize := nike.publicKeySize
  plaintextSize  := nike.sharedSecretSize

  encodePublicKey  := nike.encodePublicKey
  decodePublicKey  := nike.decodePublicKey
  encodePrivateKey := nike.encodePrivateKey
  decodePrivateKey := nike.decodePrivateKey
  encodeCiphertext := nike.encodePublicKey
  decodeCiphertext := nike.decodePublicKey
  encodePlaintext  := id

  encap := encapM F nike
  decap := decapM F nike
  stateFromSeed := fun seed => initWith (fun _ => seed)
  derivePublicKey := nike.derivePublicKey
  honestRoundTrip := roundTrip F nike
  decodePrivateKey_total := nike.decodePrivateKey_total

  -- Inhabitance only: a degenerate constant stream. Honest runs start from `initWith`.
  stateI := ⟨(0, fun _ => Vector.replicate 32 0)⟩

  generate := do
    let seed ← nextSeed
    let sk := nike.privateKeyFromSeed seed
    pure ⟨nike.derivePublicKey sk, sk, roundTrip F nike sk⟩

  decode_encode_pub  := nike.decode_encode_pub
  decode_encode_priv := nike.decode_encode_priv
  decode_encode_ct   := nike.decode_encode_pub

end CryptWalker.KEM.Adapter

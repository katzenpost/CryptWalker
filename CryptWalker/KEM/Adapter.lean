/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

-- NIKE to KEM adapter: a hashed ElGamal construction
/-
Here's pseudo code of what we are implementing here:

func ENCAPSULATE(their_pubkey publickey) ([]byte, []byte) {
        my_privkey, my_pubkey = GEN_KEYPAIR(RNG)
        ss = DH(my_privkey, their_pubkey)
        ciphertext = ENCODE_PUBKEY(my_pubkey)
        shared_secret = HASH(ENCODE_PUBKEY(ss))
        return ciphertext, shared_secret
}

func DECAPSULATE(my_privkey privatekey, ciphertext []byte) []byte {
        their_pubkey = DECODE_PUBKEY(ciphertext)
        ss = DH(my_privkey, their_pubkey)
        return HASH(ENCODE_PUBKEY(ss))
}
-/

import CryptWalker.KEM.KEM
import CryptWalker.NIKE.NIKE

namespace CryptWalker.KEM.Adapter

open CryptWalker.NIKE.NIKE
open CryptWalker.KEM.KEM

abbrev Bytes32 := Vector UInt8 32

variable (hash : ByteArray → Bytes32) (nike : NIKE)

/-- Counter plus an inexhaustible seed stream. -/
abbrev St := Nat × (Nat → Bytes32)

def nextSeed : EStateM KEMError St Bytes32 :=
  fun (i, str) => .ok (str i) (i + 1, str)

def toBytes {n} (v : Vector UInt8 n) : ByteArray := ⟨v.toArray⟩

def encapM (pk : nike.PublicKey) :
    EStateM KEMError St (nike.PublicKey × Bytes32) := do
  let seed ← nextSeed
  let eph := nike.privateKeyFromSeed seed
  if h : nike.Safe pk then
    pure (nike.derivePublicKey eph,
          hash (toBytes (nike.encodeSharedSecret (nike.groupAction eph pk h))))
  else
    EStateM.throw .unsafePublicKey

def decapM (sk : nike.PrivateKey) (ct : nike.PublicKey) :
    EStateM KEMError St Bytes32 :=
  if h : nike.Safe ct then
    pure (hash (toBytes (nike.encodeSharedSecret (nike.groupAction sk ct h))))
  else
    EStateM.throw .unsafePublicKey

/-- `nextSeed` advances the counter by exactly one and leaves the stream alone. -/
theorem nextSeed_consumes (i : Nat) (str : Nat → Bytes32) :
    nextSeed (i, str) = .ok (str i) (i + 1, str) := rfl

theorem encapM_consumes (pk : nike.PublicKey) (i : Nat) (str : Nat → Bytes32) :
    (∃ r, encapM hash nike pk (i, str) = .ok r (i + 1, str))
      ∨ encapM hash nike pk (i, str) = .error .unsafePublicKey (i + 1, str) := by
  simp only [encapM, nextSeed, bind, EStateM.bind, pure]
  split
  · exact Or.inl ⟨_, rfl⟩
  · exact Or.inr rfl


/-- Two encapsulations in sequence use different seeds. -/
theorem encap_seeds_distinct (i : Nat) (str : Nat → Bytes32)
    (hinj : ∀ m n, m ≠ n → str m ≠ str n) :
    str i ≠ str (i + 1) :=
  hinj i (i + 1) (Nat.ne_of_lt (Nat.lt_succ_self i))

-- Add to CryptWalker/KEM/Adapter.lean, after the freshness theorems.

/-- Decapsulation recovers what encapsulation produced, for honestly generated keys. -/
theorem roundTrip (sk : nike.PrivateKey) :
    ∀ s c k s', encapM hash nike (nike.derivePublicKey sk) s = .ok (c, k) s' →
      ∀ t, ∃ t', decapM hash nike sk c t = .ok k t' := by
  rintro ⟨i, str⟩ c k s' hEnc t
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
  Plaintext    := Bytes32

  pubI  := ⟨nike.derivePublicKey (nike.privateKeyFromSeed (Vector.replicate 32 0))⟩
  privI := ⟨nike.privateKeyFromSeed (Vector.replicate 32 0)⟩
  ctI   := ⟨nike.derivePublicKey (nike.privateKeyFromSeed (Vector.replicate 32 0))⟩
  ptI   := ⟨Vector.replicate 32 0⟩

  publicKeySize  := nike.publicKeySize
  privateKeySize := nike.privateKeySize
  ciphertextSize := nike.publicKeySize
  plaintextSize  := 32

  encodePublicKey  := nike.encodePublicKey
  decodePublicKey  := nike.decodePublicKey
  encodePrivateKey := nike.encodePrivateKey
  decodePrivateKey := nike.decodePrivateKey
  encodeCiphertext := nike.encodePublicKey
  decodeCiphertext := nike.decodePublicKey
  encodePlaintext  := id

  encap := encapM hash nike
  decap := decapM hash nike
  init  := (0, fun _ => Vector.replicate 32 0)

  generate := do
    let seed ← nextSeed
    let sk := nike.privateKeyFromSeed seed
    pure ⟨nike.derivePublicKey sk, sk, roundTrip hash nike sk⟩

  decode_encode_pub  := nike.decode_encode_pub
  decode_encode_priv := nike.decode_encode_priv
  decode_encode_ct   := nike.decode_encode_pub

end CryptWalker.KEM.Adapter

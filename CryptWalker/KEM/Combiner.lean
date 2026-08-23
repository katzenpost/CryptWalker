/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

import CryptWalker.KEM.KEM

namespace CryptWalker.KEM.Combiner
open CryptWalker.KEM.KEM

-- Security preserving KEM combiner

/-
SplitPRF can be used with any number of KEMs
and it implement split PRF KEM combiner as:

  cct := cct1 || cct2 || cct3 || ...
       return H(ss1 || cct) XOR H(ss2 || cct) XOR H(ss3 || cct)

in order to retain IND-CCA2 security
as described in KEM Combiners  https://eprint.iacr.org/2018/024.pdf
by Federico Giacon, Felix Heuer, and Bertram Poettering
-/

abbrev Bytes32 := Vector UInt8 32

def toBytes {n} (v : Vector UInt8 n) : ByteArray := ⟨v.toArray⟩

def xorBytes (a b : Bytes32) : Bytes32 :=
  Vector.ofFn (fun i => a[i] ^^^ b[i])

variable (hash : ByteArray → Bytes32) (k₁ k₂ : KEM)

/-- Run a `k₁` action against the left half of a product state. -/
def liftFst {α} (x : EStateM KEMError k₁.State α) :
    EStateM KEMError (k₁.State × k₂.State) α :=
  fun (s₁, s₂) => match x s₁ with
    | .ok a s₁'    => .ok a (s₁', s₂)
    | .error e s₁' => .error e (s₁', s₂)

def liftSnd {α} (x : EStateM KEMError k₂.State α) :
    EStateM KEMError (k₁.State × k₂.State) α :=
  fun (s₁, s₂) => match x s₂ with
    | .ok a s₂'    => .ok a (s₁, s₂')
    | .error e s₂' => .error e (s₁, s₂')

/-- The combined shared secret, as a pure function of both secrets and both ciphertexts. -/
def combine (p₁ : k₁.Plaintext) (p₂ : k₂.Plaintext)
    (c₁ : k₁.Ciphertext) (c₂ : k₂.Ciphertext) : Bytes32 :=
  let cct := toBytes (k₁.encodeCiphertext c₁) ++ toBytes (k₂.encodeCiphertext c₂)
  xorBytes (hash (toBytes (k₁.encodePlaintext p₁) ++ cct))
           (hash (toBytes (k₂.encodePlaintext p₂) ++ cct))

def encapM (pk : k₁.PublicKey × k₂.PublicKey) :
    EStateM KEMError (k₁.State × k₂.State)
      ((k₁.Ciphertext × k₂.Ciphertext) × Bytes32) := do
  let (c₁, p₁) ← liftFst k₁ k₂ (k₁.encap pk.1)
  let (c₂, p₂) ← liftSnd k₁ k₂ (k₂.encap pk.2)
  pure ((c₁, c₂), combine hash k₁ k₂ p₁ p₂ c₁ c₂)

def decapM (sk : k₁.PrivateKey × k₂.PrivateKey)
    (ct : k₁.Ciphertext × k₂.Ciphertext) :
    EStateM KEMError (k₁.State × k₂.State) Bytes32 := do
  let p₁ ← liftFst k₁ k₂ (k₁.decap sk.1 ct.1)
  let p₂ ← liftSnd k₁ k₂ (k₂.decap sk.2 ct.2)
  pure (combine hash k₁ k₂ p₁ p₂ ct.1 ct.2)


theorem combinedRoundTrip
    (pk₁ : k₁.PublicKey) (pk₂ : k₂.PublicKey)
    (sk₁ : k₁.PrivateKey) (sk₂ : k₂.PrivateKey)
    (h₁ : ∀ s c p s', k₁.encap pk₁ s = .ok (c, p) s' →
            ∀ t, ∃ t', k₁.decap sk₁ c t = .ok p t')
    (h₂ : ∀ s c p s', k₂.encap pk₂ s = .ok (c, p) s' →
            ∀ t, ∃ t', k₂.decap sk₂ c t = .ok p t') :
    ∀ s c k s', encapM hash k₁ k₂ (pk₁, pk₂) s = .ok (c, k) s' →
      ∀ t, ∃ t', decapM hash k₁ k₂ (sk₁, sk₂) c t = .ok k t' := by
  sorry

def splitL {a b : Nat} (v : Vector UInt8 (a + b)) : Vector UInt8 a :=
  (v.take a).cast (by omega)

def splitR {a b : Nat} (v : Vector UInt8 (a + b)) : Vector UInt8 b :=
  (v.drop a).cast (by omega)

def combineKEM : KEM where
  State      := k₁.State × k₂.State
  PublicKey  := k₁.PublicKey × k₂.PublicKey
  PrivateKey := k₁.PrivateKey × k₂.PrivateKey
  Ciphertext := k₁.Ciphertext × k₂.Ciphertext
  Plaintext  := Bytes32

  pubI  := ⟨(k₁.pubI.default,  k₂.pubI.default)⟩
  privI := ⟨(k₁.privI.default, k₂.privI.default)⟩
  ctI   := ⟨(k₁.ctI.default,   k₂.ctI.default)⟩
  ptI   := ⟨Vector.replicate 32 0⟩

  publicKeySize  := k₁.publicKeySize  + k₂.publicKeySize
  privateKeySize := k₁.privateKeySize + k₂.privateKeySize
  ciphertextSize := k₁.ciphertextSize + k₂.ciphertextSize
  plaintextSize  := 32

  decodePublicKey  := fun v => do
    let a ← k₁.decodePublicKey (splitL v)
    let b ← k₂.decodePublicKey (splitR v)
    pure (a, b)
  decodePrivateKey := fun v => do
    let a ← k₁.decodePrivateKey (splitL v)
    let b ← k₂.decodePrivateKey (splitR v)
    pure (a, b)
  decodeCiphertext := fun v => do
    let a ← k₁.decodeCiphertext (splitL v)
    let b ← k₂.decodeCiphertext (splitR v)
    pure (a, b)

  encodePublicKey  := fun p => k₁.encodePublicKey p.1 ++ k₂.encodePublicKey p.2
  encodePrivateKey := fun p => k₁.encodePrivateKey p.1 ++ k₂.encodePrivateKey p.2
  encodeCiphertext := fun c => k₁.encodeCiphertext c.1 ++ k₂.encodeCiphertext c.2
  encodePlaintext  := id

  encap := encapM hash k₁ k₂
  decap := decapM hash k₁ k₂
  init  := (k₁.init, k₂.init)

  generate := do
    let ⟨pk₁, sk₁, h₁⟩ ← liftFst k₁ k₂ k₁.generate
    let ⟨pk₂, sk₂, h₂⟩ ← liftSnd k₁ k₂ k₂.generate
    pure ⟨(pk₁, pk₂), (sk₁, sk₂),
      combinedRoundTrip hash k₁ k₂ pk₁ pk₂ sk₁ sk₂ h₁ h₂⟩


  decode_encode_pub  := by sorry
  decode_encode_priv := by sorry
  decode_encode_ct   := by sorry



end CryptWalker.KEM.Combiner

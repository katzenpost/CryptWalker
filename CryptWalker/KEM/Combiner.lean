/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

import CryptWalker.KEM.KEM

namespace CryptWalker.KEM.Combiner
open CryptWalker.KEM.KEM

/-!
# Security preserving KEM combiner

`splitPRF` is the standard-model PRF-then-XOR core function of Giacon, Heuer &
Poettering (Lemma 8 of "KEM Combiners", https://eprint.iacr.org/2018/024.pdf).
It works for any number of KEMs. Instantiated with BLAKE2b-256 in keyed mode as
the per-component PRF `F`:

```
  key_i  := BLAKE2b-256(unkeyed)(ss_i)
  hash_i := BLAKE2b-256(
               key = key_i,
               msg = "splitprf-v1" || u32be(n) ||
                     u32be(len(cct_1)) || cct_1 ||
                     ...                ||
                     u32be(len(cct_n)) || cct_n
           )
  return hash_1 XOR hash_2 XOR ... XOR hash_n
```

Two properties matter, and both differ from the naive `H(ss_i || cct)`:

* **Key binding.** Each shared secret is used as the *key* of the PRF, never as
  a message prefix. The pre-hash key derivation (`PRF.deriveKey`) handles
  BLAKE2b's 64-byte keyed-mode cap, so shared secrets of any length work.
* **Transcript binding.** The full ciphertext vector is bound into every
  component hash under a length-prefixed, count-prefixed, domain-separated
  encoding. Concatenating raw ciphertexts is ambiguous whenever a sub-KEM has a
  variable-length ciphertext; the length prefixes make the transcript
  unambiguous regardless of sub-KEM ciphertext sizes.

By Theorem 1 of the paper the combined KEM retains IND-CCA2 security as long as
at least one ingredient KEM is IND-CCA2 secure.
-/

abbrev Bytes32 := Vector UInt8 32

def toBytes {n} (v : Vector UInt8 n) : ByteArray := ⟨v.toArray⟩

def zero32 : Bytes32 := Vector.replicate 32 0

def xorBytes (a b : Bytes32) : Bytes32 :=
  Vector.ofFn (fun i => a[i] ^^^ b[i])

theorem zero_xorBytes (a : Bytes32) : xorBytes zero32 a = a := by
  apply Vector.ext; intro i hi; simp [xorBytes, zero32]

theorem xorBytes_zero (a : Bytes32) : xorBytes a zero32 = a := by
  apply Vector.ext; intro i hi; simp [xorBytes, zero32]

theorem xorBytes_comm (a b : Bytes32) : xorBytes a b = xorBytes b a := by
  simp [xorBytes, UInt8.xor_comm]

theorem xorBytes_self (a : Bytes32) : xorBytes a a = zero32 := by
  apply Vector.ext; intro i hi; simp [xorBytes, zero32]

theorem xorBytes_assoc (a b c : Bytes32) :
    xorBytes (xorBytes a b) c = xorBytes a (xorBytes b c) := by
  apply Vector.ext; intro i hi; simp [xorBytes, UInt8.xor_assoc]

/-! ### Split PRF -/

/-- Domain-separation tag for this PRF construction. -/
def splitPRFLabel : String := "splitprf-v1"

def splitPRFLabelBytes : ByteArray := splitPRFLabel.toUTF8

/-- Length in bytes of the value `splitPRF` returns. -/
def splitPRFOutputSize : Nat := 32

/-- Big-endian `u32`. Mirrors Go's `binary.BigEndian.PutUint32`, including the
truncation of lengths at 2^32; no ciphertext is anywhere near that size. -/
def u32be (v : UInt32) : ByteArray :=
  ⟨#[(v >>> 24).toUInt8, (v >>> 16).toUInt8, (v >>> 8).toUInt8, v.toUInt8]⟩

/-- The pair of hash functions the construction needs: an unkeyed hash for key
derivation, and a keyed hash used as the per-component PRF. Instantiate both
with BLAKE2b-256 to match hpqc. -/
structure PRF where
  /-- Unkeyed hash, e.g. `BLAKE2b-256(nil)`. -/
  hash : ByteArray → Bytes32
  /-- Keyed hash, e.g. `BLAKE2b-256(key, ·)`. -/
  keyed : Bytes32 → ByteArray → Bytes32

/-- Shrink an arbitrary-length shared secret to a 32-byte PRF key. Required
because BLAKE2b's keyed mode caps the key at 64 bytes and sub-KEM shared
secrets are not constrained to that. -/
def PRF.deriveKey (F : PRF) (ss : ByteArray) : Bytes32 := F.hash ss

/-- The message portion of the transcript: label, component count, then every
ciphertext under a big-endian 32-bit length prefix. -/
def transcript (cct : List ByteArray) : ByteArray :=
  cct.foldl (fun acc c => acc ++ u32be c.size.toUInt32 ++ c)
    (splitPRFLabelBytes ++ u32be cct.length.toUInt32)

/-- XOR of the per-component keyed hashes. On the empty list this is `zero32`,
which is why `splitPRF` below takes the first component separately. -/
def splitPRFCore (F : PRF) (parts : List (ByteArray × ByteArray)) : Bytes32 :=
  let msg := transcript (parts.map Prod.snd)
  parts.foldl (fun acc p => xorBytes acc (F.keyed (F.deriveKey p.1) msg)) zero32

/-- Split PRF over one or more `(shared secret, ciphertext)` components.

Non-emptiness and the pairing of secrets with ciphertexts are enforced by the
type, so this total function has no error cases: Go's `ErrNoInputs` and
`ErrMismatchedSlices` are unrepresentable here. -/
def splitPRF (F : PRF) (p : ByteArray × ByteArray)
    (ps : List (ByteArray × ByteArray) := []) : Bytes32 :=
  splitPRFCore F (p :: ps)

inductive SplitPRFError where
  | noInputs
  | mismatchedSlices
  | emptyComponent
deriving Repr, DecidableEq

/-- Checked wrapper matching the Go signature `SplitPRF(ss, cct [][]byte)`, for
callers that build the component lists dynamically. -/
def splitPRF? (F : PRF) (ss cct : List ByteArray) :
    Except SplitPRFError Bytes32 := do
  if ss.length ≠ cct.length then throw .mismatchedSlices
  match ss.zip cct with
  | [] => throw .noInputs
  | p :: ps =>
    if (p :: ps).any (fun q => q.1.size == 0 || q.2.size == 0) then
      throw .emptyComponent
    pure (splitPRF F p ps)

/-- Unfolding lemma for the two-component case used by the combiner below. -/
theorem splitPRF_pair (F : PRF) (s₁ c₁ s₂ c₂ : ByteArray) :
    splitPRF F (s₁, c₁) [(s₂, c₂)] =
      xorBytes (F.keyed (F.deriveKey s₁) (transcript [c₁, c₂]))
               (F.keyed (F.deriveKey s₂) (transcript [c₁, c₂])) := by
  simp [splitPRF, splitPRFCore, zero_xorBytes]

/-! ### The combined KEM -/

variable (F : PRF) (k₁ k₂ : KEM)

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

/-- The combined shared secret, as a pure function of both secrets and both
ciphertexts. Both ciphertexts enter *both* component hashes. -/
def combine (p₁ : k₁.Plaintext) (p₂ : k₂.Plaintext)
    (c₁ : k₁.Ciphertext) (c₂ : k₂.Ciphertext) : Bytes32 :=
  splitPRF F
    (toBytes (k₁.encodePlaintext p₁), toBytes (k₁.encodeCiphertext c₁))
    [(toBytes (k₂.encodePlaintext p₂), toBytes (k₂.encodeCiphertext c₂))]

def encapM (pk : k₁.PublicKey × k₂.PublicKey) :
    EStateM KEMError (k₁.State × k₂.State)
      ((k₁.Ciphertext × k₂.Ciphertext) × Bytes32) := do
  let (c₁, p₁) ← liftFst k₁ k₂ (k₁.encap pk.1)
  let (c₂, p₂) ← liftSnd k₁ k₂ (k₂.encap pk.2)
  pure ((c₁, c₂), combine F k₁ k₂ p₁ p₂ c₁ c₂)

def decapM (sk : k₁.PrivateKey × k₂.PrivateKey)
    (ct : k₁.Ciphertext × k₂.Ciphertext) :
    EStateM KEMError (k₁.State × k₂.State) Bytes32 := do
  let p₁ ← liftFst k₁ k₂ (k₁.decap sk.1 ct.1)
  let p₂ ← liftSnd k₁ k₂ (k₂.decap sk.2 ct.2)
  pure (combine F k₁ k₂ p₁ p₂ ct.1 ct.2)

/-- Correctness: if both ingredient KEMs round-trip, so does the combination.
`combine` is a pure function of the plaintexts and ciphertexts, so both sides
derive the same shared secret from the same inputs. -/
theorem combinedRoundTrip
    (pk₁ : k₁.PublicKey) (pk₂ : k₂.PublicKey)
    (sk₁ : k₁.PrivateKey) (sk₂ : k₂.PrivateKey)
    (h₁ : ∀ s c p s', k₁.encap pk₁ s = .ok (c, p) s' →
            ∀ t, ∃ t', k₁.decap sk₁ c t = .ok p t')
    (h₂ : ∀ s c p s', k₂.encap pk₂ s = .ok (c, p) s' →
            ∀ t, ∃ t', k₂.decap sk₂ c t = .ok p t') :
    ∀ s c k s', encapM F k₁ k₂ (pk₁, pk₂) s = .ok (c, k) s' →
      ∀ t, ∃ t', decapM F k₁ k₂ (sk₁, sk₂) c t = .ok k t' := by
  rintro ⟨s₁, s₂⟩ c k s' hEnc ⟨t₁, t₂⟩
  simp only [encapM, decapM, bind, EStateM.bind, liftFst, liftSnd] at hEnc ⊢
  cases hE1 : k₁.encap pk₁ s₁ with
  | error e sa => rw [hE1] at hEnc; simp at hEnc
  | ok a sa =>
    obtain ⟨c₁, p₁⟩ := a
    rw [hE1] at hEnc
    simp only at hEnc
    cases hE2 : k₂.encap pk₂ s₂ with
    | error e sb => rw [hE2] at hEnc; simp at hEnc
    | ok b sb =>
      obtain ⟨c₂, p₂⟩ := b
      rw [hE2] at hEnc
      simp only at hEnc
      obtain ⟨t₁', hd₁⟩ := h₁ s₁ c₁ p₁ sa hE1 t₁
      obtain ⟨t₂', hd₂⟩ := h₂ s₂ c₂ p₂ sb hE2 t₂
      cases hEnc
      simp only [hd₁, hd₂]
      exact ⟨_, rfl⟩

def splitL {a b : Nat} (v : Vector UInt8 (a + b)) : Vector UInt8 a :=
  (v.take a).cast (by omega)

def splitR {a b : Nat} (v : Vector UInt8 (a + b)) : Vector UInt8 b :=
  (v.drop a).cast (by omega)

theorem splitL_append {a b : Nat} (v : Vector UInt8 a) (w : Vector UInt8 b) :
    splitL (v ++ w) = v := by
  apply Vector.ext; intro i hi; simp [splitL, hi]

theorem splitR_append {a b : Nat} (v : Vector UInt8 a) (w : Vector UInt8 b) :
    splitR (v ++ w) = w := by
  apply Vector.ext; intro i hi; simp [splitR]

def combineKEM : KEM where
  State      := k₁.State × k₂.State
  PublicKey  := k₁.PublicKey × k₂.PublicKey
  PrivateKey := k₁.PrivateKey × k₂.PrivateKey
  Ciphertext := k₁.Ciphertext × k₂.Ciphertext
  Plaintext  := Bytes32

  pubI  := ⟨(k₁.pubI.default,  k₂.pubI.default)⟩
  privI := ⟨(k₁.privI.default, k₂.privI.default)⟩
  ctI   := ⟨(k₁.ctI.default,   k₂.ctI.default)⟩
  ptI   := ⟨zero32⟩

  publicKeySize  := k₁.publicKeySize  + k₂.publicKeySize
  privateKeySize := k₁.privateKeySize + k₂.privateKeySize
  ciphertextSize := k₁.ciphertextSize + k₂.ciphertextSize
  plaintextSize  := splitPRFOutputSize

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

  encap := encapM F k₁ k₂
  decap := decapM F k₁ k₂
  -- Inhabitance only, inherited from the components. A real combined state is
  -- the pair of the components' own caller-supplied states.
  stateI := ⟨(k₁.stateI.default, k₂.stateI.default)⟩

  generate := do
    let ⟨pk₁, sk₁, h₁⟩ ← liftFst k₁ k₂ k₁.generate
    let ⟨pk₂, sk₂, h₂⟩ ← liftSnd k₁ k₂ k₂.generate
    pure ⟨(pk₁, pk₂), (sk₁, sk₂),
      combinedRoundTrip F k₁ k₂ pk₁ pk₂ sk₁ sk₂ h₁ h₂⟩

  decode_encode_pub := by
    intro p
    simp [splitL_append, splitR_append, k₁.decode_encode_pub, k₂.decode_encode_pub]

  decode_encode_priv := by
    intro p
    simp [splitL_append, splitR_append, k₁.decode_encode_priv, k₂.decode_encode_priv]

  decode_encode_ct := by
    intro c
    simp [splitL_append, splitR_append, k₁.decode_encode_ct, k₂.decode_encode_ct]


end CryptWalker.KEM.Combiner

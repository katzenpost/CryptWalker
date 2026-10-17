/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

import Cryptlib.Primitives.KEM.KEM
import Cryptlib.Util.Bytes

namespace Cryptlib.Primitives.KEM.Combiner
open Cryptlib.Primitives.KEM.KEM

/-!
# Security preserving KEM combiner

`splitPRF` is the PRF-then-XOR core function of Giacon, Heuer & Poettering
("KEM Combiners", https://eprint.iacr.org/2018/024.pdf, Lemma 8), for any number
of KEMs. With BLAKE2b-256 as the PRF:

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

Each shared secret keys the PRF, and every component hash binds the full,
unambiguously encoded ciphertext vector. By Theorem 1 of the paper the combined
KEM is IND-CCA2 if at least one component is.
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

/-- Domain-separation tag. -/
def splitPRFLabel : String := "splitprf-v1"

def splitPRFLabelBytes : ByteArray := splitPRFLabel.toUTF8

/-- Length in bytes of the value `splitPRF` returns. -/
def splitPRFOutputSize : Nat := 32

/-- Big-endian `u32`. -/
def u32be (v : UInt32) : ByteArray :=
  ⟨#[(v >>> 24).toUInt8, (v >>> 16).toUInt8, (v >>> 8).toUInt8, v.toUInt8]⟩

/-- An unkeyed hash for key derivation and a keyed hash as the per-component PRF. -/
structure PRF where
  hash : ByteArray → Bytes32
  keyed : Bytes32 → ByteArray → Bytes32

/-- Hash a shared secret of any length to a 32-byte PRF key. -/
def PRF.deriveKey (F : PRF) (ss : ByteArray) : Bytes32 := F.hash ss

/-- Label, component count, then each ciphertext with a 32-bit length prefix. -/
def transcript (cct : List ByteArray) : ByteArray :=
  cct.foldl (fun acc c => acc ++ u32be c.size.toUInt32 ++ c)
    (splitPRFLabelBytes ++ u32be cct.length.toUInt32)

/-- XOR of the per-component keyed hashes; `zero32` on the empty list. -/
def splitPRFCore (F : PRF) (parts : List (ByteArray × ByteArray)) : Bytes32 :=
  let msg := transcript (parts.map Prod.snd)
  parts.foldl (fun acc p => xorBytes acc (F.keyed (F.deriveKey p.1) msg)) zero32

/-- Split PRF over one or more `(shared secret, ciphertext)` components. -/
def splitPRF (F : PRF) (p : ByteArray × ByteArray)
    (ps : List (ByteArray × ByteArray) := []) : Bytes32 :=
  splitPRFCore F (p :: ps)

inductive SplitPRFError where
  | noInputs
  | mismatchedSlices
  | emptyComponent
deriving Repr, DecidableEq

/-- `splitPRF` over separate secret and ciphertext lists, rejecting malformed input. -/
def splitPRF? (F : PRF) (ss cct : List ByteArray) :
    Except SplitPRFError Bytes32 := do
  if ss.length ≠ cct.length then throw .mismatchedSlices
  match ss.zip cct with
  | [] => throw .noInputs
  | p :: ps =>
    if (p :: ps).any (fun q => q.1.size == 0 || q.2.size == 0) then
      throw .emptyComponent
    pure (splitPRF F p ps)

/-- `splitPRF` on two components. -/
theorem splitPRF_pair (F : PRF) (s₁ c₁ s₂ c₂ : ByteArray) :
    splitPRF F (s₁, c₁) [(s₂, c₂)] =
      xorBytes (F.keyed (F.deriveKey s₁) (transcript [c₁, c₂]))
               (F.keyed (F.deriveKey s₂) (transcript [c₁, c₂])) := by
  simp [splitPRF, splitPRFCore, zero_xorBytes]

/-! ### The combined KEM

`combineKEM F k₀ ks` combines a head KEM with a possibly empty list of more. Combined keys,
ciphertexts and states for `ks` are nested products ending in `PUnit`. -/

open Cryptlib.Util.Bytes (ofVector toVecN size_ofVector ofVector_toVecN toVecN_ofVector
  extract_append_left extract_append_right)

def CombinedState : List KEM → Type
  | [] => PUnit
  | k :: ks => k.State × CombinedState ks

def CombinedPublicKey : List KEM → Type
  | [] => PUnit
  | k :: ks => k.PublicKey × CombinedPublicKey ks

def CombinedPrivateKey : List KEM → Type
  | [] => PUnit
  | k :: ks => k.PrivateKey × CombinedPrivateKey ks

def CombinedCiphertext : List KEM → Type
  | [] => PUnit
  | k :: ks => k.Ciphertext × CombinedCiphertext ks

def defaultState : (ks : List KEM) → CombinedState ks
  | [] => ⟨⟩
  | k :: ks => (k.stateI.default, defaultState ks)

def defaultPublicKey : (ks : List KEM) → CombinedPublicKey ks
  | [] => ⟨⟩
  | k :: ks => (k.pubI.default, defaultPublicKey ks)

def defaultPrivateKey : (ks : List KEM) → CombinedPrivateKey ks
  | [] => ⟨⟩
  | k :: ks => (k.privI.default, defaultPrivateKey ks)

def defaultCiphertext : (ks : List KEM) → CombinedCiphertext ks
  | [] => ⟨⟩
  | k :: ks => (k.ctI.default, defaultCiphertext ks)

def sumPublicKeySize : List KEM → Nat
  | [] => 0
  | k :: ks => k.publicKeySize + sumPublicKeySize ks

def sumPrivateKeySize : List KEM → Nat
  | [] => 0
  | k :: ks => k.privateKeySize + sumPrivateKeySize ks

def sumCiphertextSize : List KEM → Nat
  | [] => 0
  | k :: ks => k.ciphertextSize + sumCiphertextSize ks

def stateFromSeedN : (ks : List KEM) → Vector UInt8 32 → CombinedState ks
  | [], _ => ⟨⟩
  | k :: ks, seed => (k.stateFromSeed seed, stateFromSeedN ks seed)

def derivePublicKeyN : (ks : List KEM) → CombinedPrivateKey ks → CombinedPublicKey ks
  | [], _ => ⟨⟩
  | k :: ks, (sk, sks) => (k.derivePublicKey sk, derivePublicKeyN ks sks)

def ReliableN : (ks : List KEM) → CombinedState ks → Prop
  | [], _ => True
  | k :: ks, (s, ss) => k.Reliable s ∧ ReliableN ks ss

/-! #### Wire encoding

Components are concatenated as `ByteArray`s and converted to `Vector` only in `combineKEM`. -/

def encodePublicKeyN : (ks : List KEM) → CombinedPublicKey ks → ByteArray
  | [], _ => ByteArray.empty
  | k :: ks, (pk, pks) => ofVector (k.encodePublicKey pk) ++ encodePublicKeyN ks pks

def decodePublicKeyN : (ks : List KEM) → ByteArray → Option (CombinedPublicKey ks)
  | [], _ => some ⟨⟩
  | k :: ks, buf => do
      let pk ← k.decodePublicKey (toVecN k.publicKeySize (buf.extract 0 k.publicKeySize))
      let pks ← decodePublicKeyN ks (buf.extract k.publicKeySize buf.size)
      pure (pk, pks)

def encodePrivateKeyN : (ks : List KEM) → CombinedPrivateKey ks → ByteArray
  | [], _ => ByteArray.empty
  | k :: ks, (sk, sks) => ofVector (k.encodePrivateKey sk) ++ encodePrivateKeyN ks sks

def decodePrivateKeyN : (ks : List KEM) → ByteArray → Option (CombinedPrivateKey ks)
  | [], _ => some ⟨⟩
  | k :: ks, buf => do
      let sk ← k.decodePrivateKey (toVecN k.privateKeySize (buf.extract 0 k.privateKeySize))
      let sks ← decodePrivateKeyN ks (buf.extract k.privateKeySize buf.size)
      pure (sk, sks)

def encodeCiphertextN : (ks : List KEM) → CombinedCiphertext ks → ByteArray
  | [], _ => ByteArray.empty
  | k :: ks, (c, cs) => ofVector (k.encodeCiphertext c) ++ encodeCiphertextN ks cs

def decodeCiphertextN : (ks : List KEM) → ByteArray → Option (CombinedCiphertext ks)
  | [], _ => some ⟨⟩
  | k :: ks, buf => do
      let c ← k.decodeCiphertext (toVecN k.ciphertextSize (buf.extract 0 k.ciphertextSize))
      let cs ← decodeCiphertextN ks (buf.extract k.ciphertextSize buf.size)
      pure (c, cs)

theorem encodePublicKeyN_size : ∀ (ks : List KEM) (pk : CombinedPublicKey ks),
    (encodePublicKeyN ks pk).size = sumPublicKeySize ks
  | [], _ => rfl
  | k :: ks, (pk, pks) => by
      show (ofVector (k.encodePublicKey pk) ++ encodePublicKeyN ks pks).size
        = k.publicKeySize + sumPublicKeySize ks
      rw [ByteArray.size_append, size_ofVector, encodePublicKeyN_size ks pks]

theorem encodePrivateKeyN_size : ∀ (ks : List KEM) (sk : CombinedPrivateKey ks),
    (encodePrivateKeyN ks sk).size = sumPrivateKeySize ks
  | [], _ => rfl
  | k :: ks, (sk, sks) => by
      show (ofVector (k.encodePrivateKey sk) ++ encodePrivateKeyN ks sks).size
        = k.privateKeySize + sumPrivateKeySize ks
      rw [ByteArray.size_append, size_ofVector, encodePrivateKeyN_size ks sks]

theorem encodeCiphertextN_size : ∀ (ks : List KEM) (c : CombinedCiphertext ks),
    (encodeCiphertextN ks c).size = sumCiphertextSize ks
  | [], _ => rfl
  | k :: ks, (c, cs) => by
      show (ofVector (k.encodeCiphertext c) ++ encodeCiphertextN ks cs).size
        = k.ciphertextSize + sumCiphertextSize ks
      rw [ByteArray.size_append, size_ofVector, encodeCiphertextN_size ks cs]

theorem decode_encode_pub_N : ∀ (ks : List KEM) (pk : CombinedPublicKey ks),
    decodePublicKeyN ks (encodePublicKeyN ks pk) = some pk
  | [], ⟨⟩ => rfl
  | k :: ks, (pk, pks) => by
      have hleft : (ofVector (k.encodePublicKey pk) ++ encodePublicKeyN ks pks).extract 0
          k.publicKeySize = ofVector (k.encodePublicKey pk) := by
        have h := extract_append_left (ofVector (k.encodePublicKey pk)) (encodePublicKeyN ks pks)
        rwa [size_ofVector] at h
      have hright : (ofVector (k.encodePublicKey pk) ++ encodePublicKeyN ks pks).extract
          k.publicKeySize (ofVector (k.encodePublicKey pk) ++ encodePublicKeyN ks pks).size
          = encodePublicKeyN ks pks := by
        have h := extract_append_right (ofVector (k.encodePublicKey pk)) (encodePublicKeyN ks pks)
        rwa [← ByteArray.size_append, size_ofVector] at h
      show decodePublicKeyN (k :: ks)
        (ofVector (k.encodePublicKey pk) ++ encodePublicKeyN ks pks) = some (pk, pks)
      unfold decodePublicKeyN
      rw [hleft, hright, toVecN_ofVector, k.decode_encode_pub pk, decode_encode_pub_N ks pks]
      rfl

theorem decode_encode_priv_N : ∀ (ks : List KEM) (sk : CombinedPrivateKey ks),
    decodePrivateKeyN ks (encodePrivateKeyN ks sk) = some sk
  | [], ⟨⟩ => rfl
  | k :: ks, (sk, sks) => by
      have hleft : (ofVector (k.encodePrivateKey sk) ++ encodePrivateKeyN ks sks).extract 0
          k.privateKeySize = ofVector (k.encodePrivateKey sk) := by
        have h := extract_append_left (ofVector (k.encodePrivateKey sk)) (encodePrivateKeyN ks sks)
        rwa [size_ofVector] at h
      have hright : (ofVector (k.encodePrivateKey sk) ++ encodePrivateKeyN ks sks).extract
          k.privateKeySize (ofVector (k.encodePrivateKey sk) ++ encodePrivateKeyN ks sks).size
          = encodePrivateKeyN ks sks := by
        have h := extract_append_right (ofVector (k.encodePrivateKey sk)) (encodePrivateKeyN ks sks)
        rwa [← ByteArray.size_append, size_ofVector] at h
      show decodePrivateKeyN (k :: ks)
        (ofVector (k.encodePrivateKey sk) ++ encodePrivateKeyN ks sks) = some (sk, sks)
      unfold decodePrivateKeyN
      rw [hleft, hright, toVecN_ofVector, k.decode_encode_priv sk, decode_encode_priv_N ks sks]
      rfl

theorem decode_encode_ct_N : ∀ (ks : List KEM) (c : CombinedCiphertext ks),
    decodeCiphertextN ks (encodeCiphertextN ks c) = some c
  | [], ⟨⟩ => rfl
  | k :: ks, (c, cs) => by
      have hleft : (ofVector (k.encodeCiphertext c) ++ encodeCiphertextN ks cs).extract 0
          k.ciphertextSize = ofVector (k.encodeCiphertext c) := by
        have h := extract_append_left (ofVector (k.encodeCiphertext c)) (encodeCiphertextN ks cs)
        rwa [size_ofVector] at h
      have hright : (ofVector (k.encodeCiphertext c) ++ encodeCiphertextN ks cs).extract
          k.ciphertextSize (ofVector (k.encodeCiphertext c) ++ encodeCiphertextN ks cs).size
          = encodeCiphertextN ks cs := by
        have h := extract_append_right (ofVector (k.encodeCiphertext c)) (encodeCiphertextN ks cs)
        rwa [← ByteArray.size_append, size_ofVector] at h
      show decodeCiphertextN (k :: ks)
        (ofVector (k.encodeCiphertext c) ++ encodeCiphertextN ks cs) = some (c, cs)
      unfold decodeCiphertextN
      rw [hleft, hright, toVecN_ofVector, k.decode_encode_ct c, decode_encode_ct_N ks cs]
      rfl

/-! #### Encapsulation and decapsulation over the tail list -/

def liftHead {k : KEM} {ks : List KEM} {α} (x : EStateM KEMError k.State α) :
    EStateM KEMError (k.State × CombinedState ks) α :=
  fun (s, rest) => match x s with
    | .ok a s'    => .ok a (s', rest)
    | .error e s' => .error e (s', rest)

def liftTail {k : KEM} {ks : List KEM} {α} (x : EStateM KEMError (CombinedState ks) α) :
    EStateM KEMError (k.State × CombinedState ks) α :=
  fun (s, rest) => match x rest with
    | .ok a rest'    => .ok a (s, rest')
    | .error e rest' => .error e (s, rest')

/-- Each tail component's encoded `(shared secret, ciphertext)`. -/
def encapAllM : (ks : List KEM) → CombinedPublicKey ks →
    EStateM KEMError (CombinedState ks) (CombinedCiphertext ks × List (ByteArray × ByteArray))
  | [], _ => pure (⟨⟩, [])
  | k :: ks, (pk, pks) => do
      let (c, p) ← liftHead (k.encap pk)
      let (cs, comps) ← liftTail (encapAllM ks pks)
      pure ((c, cs), (ofVector (k.encodePlaintext p), ofVector (k.encodeCiphertext c)) :: comps)

def decapAllM : (ks : List KEM) → CombinedPrivateKey ks → CombinedCiphertext ks →
    EStateM KEMError (CombinedState ks) (List (ByteArray × ByteArray))
  | [], _, _ => pure []
  | k :: ks, (sk, sks), (c, cs) => do
      let p ← liftHead (k.decap sk c)
      let comps ← liftTail (decapAllM ks sks cs)
      pure ((ofVector (k.encodePlaintext p), ofVector (k.encodeCiphertext c)) :: comps)

variable (F : PRF)

def encapM (k₀ : KEM) (ks : List KEM) (pk : k₀.PublicKey × CombinedPublicKey ks) :
    EStateM KEMError (k₀.State × CombinedState ks)
      ((k₀.Ciphertext × CombinedCiphertext ks) × Bytes32) := do
  let (c₀, p₀) ← liftHead (k₀.encap pk.1)
  let (cs, comps) ← liftTail (encapAllM ks pk.2)
  pure ((c₀, cs), splitPRF F (ofVector (k₀.encodePlaintext p₀), ofVector (k₀.encodeCiphertext c₀)) comps)

def decapM (k₀ : KEM) (ks : List KEM) (sk : k₀.PrivateKey × CombinedPrivateKey ks)
    (ct : k₀.Ciphertext × CombinedCiphertext ks) :
    EStateM KEMError (k₀.State × CombinedState ks) Bytes32 := do
  let p₀ ← liftHead (k₀.decap sk.1 ct.1)
  let comps ← liftTail (decapAllM ks sk.2 ct.2)
  pure (splitPRF F (ofVector (k₀.encodePlaintext p₀), ofVector (k₀.encodeCiphertext ct.1)) comps)

/-! #### Correctness -/

/-- Every tail component round-trips for its `(pk, sk)` pair. -/
def AllHonestFor : (ks : List KEM) → CombinedPublicKey ks → CombinedPrivateKey ks → Prop
  | [], _, _ => True
  | k :: ks, (pk, pks), (sk, sks) =>
      (∀ s, k.Reliable s → ∀ c p s', k.encap pk s = .ok (c, p) s' →
        ∀ t, ∃ t', k.decap sk c t = .ok p t') ∧ AllHonestFor ks pks sks

theorem allHonestFor_derivePublicKey :
    ∀ (ks : List KEM) (sks : CombinedPrivateKey ks), AllHonestFor ks (derivePublicKeyN ks sks) sks
  | [], _ => trivial
  | k :: ks, (sk, sks) => ⟨k.honestRoundTrip sk, allHonestFor_derivePublicKey ks sks⟩

/-- `decapAllM` recovers the `(shared secret, ciphertext)` list `encapAllM` produced. -/
theorem encapAllM_decapAllM :
    ∀ (ks : List KEM) (pks : CombinedPublicKey ks) (sks : CombinedPrivateKey ks),
      AllHonestFor ks pks sks →
      ∀ s, ReliableN ks s → ∀ ct comps s',
        encapAllM ks pks s = .ok (ct, comps) s' →
        ∀ t, ∃ t', decapAllM ks sks ct t = .ok comps t'
  | [], _, _, _, s, _, ct, comps, s', hEnc, t => by
      simp only [encapAllM, pure, EStateM.pure] at hEnc
      injection hEnc with h1 h2
      injection h1 with _ hcomps
      subst hcomps
      exact ⟨t, by simp [decapAllM, pure, EStateM.pure]⟩
  | k :: ks, (pk, pks), (sk, sks), ⟨hk, hks⟩, (s0, srest), ⟨hrelk, hrelks⟩, ct, comps, s', hEnc,
      (t0, trest) => by
      simp only [encapAllM, liftHead, liftTail, bind, EStateM.bind] at hEnc
      cases hE0 : k.encap pk s0 with
      | error e sa => rw [hE0] at hEnc; simp at hEnc
      | ok a sa =>
        obtain ⟨c0, p0⟩ := a
        rw [hE0] at hEnc
        simp only at hEnc
        cases hEr : encapAllM ks pks srest with
        | error e sb => rw [hEr] at hEnc; simp at hEnc
        | ok b sb =>
          obtain ⟨cs, comps'⟩ := b
          rw [hEr] at hEnc
          simp only at hEnc
          injection hEnc with h1 h2
          injection h1 with hct hcomps
          obtain ⟨t0', hd0⟩ := hk s0 hrelk c0 p0 sa hE0 t0
          obtain ⟨trest', hdRest⟩ :=
            encapAllM_decapAllM ks pks sks hks srest hrelks cs comps' sb hEr trest
          refine ⟨(t0', trest'), ?_⟩
          show decapAllM (k :: ks) (sk, sks) ct (t0, trest) = .ok comps (t0', trest')
          obtain rfl : ct = (c0, cs) := hct.symm
          simp only [decapAllM, liftHead, liftTail, bind, EStateM.bind]
          rw [hd0]
          simp only
          rw [hdRest]
          simp only
          rw [← hcomps]
          rfl

/-- If the head and every tail KEM round-trip for the given `(pk, sk)` pairs, so does the
combination. -/
theorem combinedRoundTrip (k₀ : KEM) (ks : List KEM)
    (pk₀ : k₀.PublicKey) (pks : CombinedPublicKey ks)
    (sk₀ : k₀.PrivateKey) (sks : CombinedPrivateKey ks)
    (h₀ : ∀ s, k₀.Reliable s → ∀ c p s', k₀.encap pk₀ s = .ok (c, p) s' →
            ∀ t, ∃ t', k₀.decap sk₀ c t = .ok p t')
    (hs : AllHonestFor ks pks sks) :
    ∀ s, k₀.Reliable s.1 ∧ ReliableN ks s.2 → ∀ ct key s',
      encapM F k₀ ks (pk₀, pks) s = .ok (ct, key) s' →
      ∀ t, ∃ t', decapM F k₀ ks (sk₀, sks) ct t = .ok key t' := by
  rintro ⟨s0, srest⟩ ⟨hrel0, hrelrest⟩ ct key s' hEnc ⟨t0, trest⟩
  simp only [encapM, liftHead, liftTail, bind, EStateM.bind] at hEnc
  cases hE0 : k₀.encap pk₀ s0 with
  | error e sa => rw [hE0] at hEnc; simp at hEnc
  | ok a sa =>
    obtain ⟨c0, p0⟩ := a
    rw [hE0] at hEnc
    simp only at hEnc
    cases hEr : encapAllM ks pks srest with
    | error e sb => rw [hEr] at hEnc; simp at hEnc
    | ok b sb =>
      obtain ⟨cs, comps⟩ := b
      rw [hEr] at hEnc
      simp only at hEnc
      injection hEnc with h1 h2
      injection h1 with hct hkey
      obtain ⟨t0', hd0⟩ := h₀ s0 hrel0 c0 p0 sa hE0 t0
      obtain ⟨trest', hdRest⟩ :=
        encapAllM_decapAllM ks pks sks hs srest hrelrest cs comps sb hEr trest
      refine ⟨(t0', trest'), ?_⟩
      show decapM F k₀ ks (sk₀, sks) ct (t0, trest) = .ok key (t0', trest')
      obtain rfl : ct = (c0, cs) := hct.symm
      simp only [decapM, liftHead, liftTail, bind, EStateM.bind]
      rw [hd0]
      simp only
      rw [hdRest]
      simp only
      rw [← hkey]
      rfl

/-- Key pairs for the tail list, with their `AllHonestFor` witness. -/
def generateN : (ks : List KEM) → EStateM KEMError (CombinedState ks)
    (Σ' (pk : CombinedPublicKey ks), {sk : CombinedPrivateKey ks // AllHonestFor ks pk sk})
  | [] => pure ⟨⟨⟩, ⟨⟩, trivial⟩
  | k :: ks => do
      let ⟨pk, sk, h⟩ ← liftHead k.generate
      let ⟨pks, sks, hs⟩ ← liftTail (generateN ks)
      pure ⟨(pk, pks), (sk, sks), h, hs⟩

theorem decodePrivateKeyN_total : ∀ (ks : List KEM) (b : ByteArray), ∃ sk, decodePrivateKeyN ks b = some sk
  | [], _ => ⟨⟨⟩, rfl⟩
  | k :: ks, b => by
      obtain ⟨sk, hsk⟩ := k.decodePrivateKey_total
        (toVecN k.privateKeySize (b.extract 0 k.privateKeySize))
      obtain ⟨sks, hsks⟩ := decodePrivateKeyN_total ks (b.extract k.privateKeySize b.size)
      refine ⟨(sk, sks), ?_⟩
      show decodePrivateKeyN (k :: ks) b = some (sk, sks)
      unfold decodePrivateKeyN
      rw [hsk, hsks]
      rfl

/-- One KEM plus a possibly empty list of more, combined with the split PRF. -/
def combineKEM (k₀ : KEM) (ks : List KEM) : KEM where
  State      := k₀.State × CombinedState ks
  PublicKey  := k₀.PublicKey × CombinedPublicKey ks
  PrivateKey := k₀.PrivateKey × CombinedPrivateKey ks
  Ciphertext := k₀.Ciphertext × CombinedCiphertext ks
  Plaintext  := Bytes32

  pubI  := ⟨(k₀.pubI.default, defaultPublicKey ks)⟩
  privI := ⟨(k₀.privI.default, defaultPrivateKey ks)⟩
  ctI   := ⟨(k₀.ctI.default, defaultCiphertext ks)⟩
  ptI   := ⟨zero32⟩
  stateI := ⟨(k₀.stateI.default, defaultState ks)⟩

  publicKeySize  := k₀.publicKeySize  + sumPublicKeySize ks
  privateKeySize := k₀.privateKeySize + sumPrivateKeySize ks
  ciphertextSize := k₀.ciphertextSize + sumCiphertextSize ks
  plaintextSize  := splitPRFOutputSize

  encodePublicKey := fun (pk0, pks) =>
    toVecN _ (ofVector (k₀.encodePublicKey pk0) ++ encodePublicKeyN ks pks)
  decodePublicKey := fun v => do
    let b := ofVector v
    let pk0 ← k₀.decodePublicKey (toVecN k₀.publicKeySize (b.extract 0 k₀.publicKeySize))
    let pks ← decodePublicKeyN ks (b.extract k₀.publicKeySize b.size)
    pure (pk0, pks)
  encodePrivateKey := fun (sk0, sks) =>
    toVecN _ (ofVector (k₀.encodePrivateKey sk0) ++ encodePrivateKeyN ks sks)
  decodePrivateKey := fun v => do
    let b := ofVector v
    let sk0 ← k₀.decodePrivateKey (toVecN k₀.privateKeySize (b.extract 0 k₀.privateKeySize))
    let sks ← decodePrivateKeyN ks (b.extract k₀.privateKeySize b.size)
    pure (sk0, sks)
  encodeCiphertext := fun (c0, cs) =>
    toVecN _ (ofVector (k₀.encodeCiphertext c0) ++ encodeCiphertextN ks cs)
  decodeCiphertext := fun v => do
    let b := ofVector v
    let c0 ← k₀.decodeCiphertext (toVecN k₀.ciphertextSize (b.extract 0 k₀.ciphertextSize))
    let cs ← decodeCiphertextN ks (b.extract k₀.ciphertextSize b.size)
    pure (c0, cs)
  encodePlaintext := id

  encap := encapM F k₀ ks
  decap := decapM F k₀ ks
  -- All components share one seed, which correlates them if two are the same scheme.
  stateFromSeed := fun seed => (k₀.stateFromSeed seed, stateFromSeedN ks seed)
  derivePublicKey := fun (sk0, sks) => (k₀.derivePublicKey sk0, derivePublicKeyN ks sks)

  Reliable := fun (s0, ss) => k₀.Reliable s0 ∧ ReliableN ks ss

  honestRoundTrip := fun (sk0, sks) =>
    combinedRoundTrip F k₀ ks (k₀.derivePublicKey sk0) (derivePublicKeyN ks sks) sk0 sks
      (k₀.honestRoundTrip sk0) (allHonestFor_derivePublicKey ks sks)

  decodePrivateKey_total := fun v => by
    obtain ⟨a, ha⟩ := k₀.decodePrivateKey_total (toVecN k₀.privateKeySize
      ((ofVector v).extract 0 k₀.privateKeySize))
    obtain ⟨b, hb⟩ := decodePrivateKeyN_total ks ((ofVector v).extract k₀.privateKeySize
      (ofVector v).size)
    refine ⟨(a, b), ?_⟩
    show (do
      let sk0 ← k₀.decodePrivateKey (toVecN k₀.privateKeySize
        ((ofVector v).extract 0 k₀.privateKeySize))
      let sks ← decodePrivateKeyN ks ((ofVector v).extract k₀.privateKeySize (ofVector v).size)
      pure (sk0, sks) : Option _) = some (a, b)
    rw [ha, hb]
    rfl

  generate := do
    let ⟨pk0, sk0, h0⟩ ← liftHead k₀.generate
    let ⟨pks, sks, hs⟩ ← liftTail (generateN ks)
    pure ⟨(pk0, pks), (sk0, sks), combinedRoundTrip F k₀ ks pk0 pks sk0 sks h0 hs⟩

  decode_encode_pub := by
    intro (pk0, pks)
    dsimp only
    rw [ofVector_toVecN _ (by simp [ByteArray.size_append, size_ofVector, encodePublicKeyN_size])]
    have hleft : (ofVector (k₀.encodePublicKey pk0) ++ encodePublicKeyN ks pks).extract 0
        k₀.publicKeySize = ofVector (k₀.encodePublicKey pk0) := by
      have h := extract_append_left (ofVector (k₀.encodePublicKey pk0)) (encodePublicKeyN ks pks)
      rwa [size_ofVector] at h
    have hright : (ofVector (k₀.encodePublicKey pk0) ++ encodePublicKeyN ks pks).extract
        k₀.publicKeySize (ofVector (k₀.encodePublicKey pk0) ++ encodePublicKeyN ks pks).size
        = encodePublicKeyN ks pks := by
      have h := extract_append_right (ofVector (k₀.encodePublicKey pk0)) (encodePublicKeyN ks pks)
      rwa [← ByteArray.size_append, size_ofVector] at h
    rw [hleft, hright, toVecN_ofVector, k₀.decode_encode_pub pk0, decode_encode_pub_N ks pks]
    rfl

  decode_encode_priv := by
    intro (sk0, sks)
    dsimp only
    rw [ofVector_toVecN _ (by simp [ByteArray.size_append, size_ofVector, encodePrivateKeyN_size])]
    have hleft : (ofVector (k₀.encodePrivateKey sk0) ++ encodePrivateKeyN ks sks).extract 0
        k₀.privateKeySize = ofVector (k₀.encodePrivateKey sk0) := by
      have h := extract_append_left (ofVector (k₀.encodePrivateKey sk0)) (encodePrivateKeyN ks sks)
      rwa [size_ofVector] at h
    have hright : (ofVector (k₀.encodePrivateKey sk0) ++ encodePrivateKeyN ks sks).extract
        k₀.privateKeySize (ofVector (k₀.encodePrivateKey sk0) ++ encodePrivateKeyN ks sks).size
        = encodePrivateKeyN ks sks := by
      have h := extract_append_right (ofVector (k₀.encodePrivateKey sk0)) (encodePrivateKeyN ks sks)
      rwa [← ByteArray.size_append, size_ofVector] at h
    rw [hleft, hright, toVecN_ofVector, k₀.decode_encode_priv sk0, decode_encode_priv_N ks sks]
    rfl

  decode_encode_ct := by
    intro (c0, cs)
    dsimp only
    rw [ofVector_toVecN _ (by simp [ByteArray.size_append, size_ofVector, encodeCiphertextN_size])]
    have hleft : (ofVector (k₀.encodeCiphertext c0) ++ encodeCiphertextN ks cs).extract 0
        k₀.ciphertextSize = ofVector (k₀.encodeCiphertext c0) := by
      have h := extract_append_left (ofVector (k₀.encodeCiphertext c0)) (encodeCiphertextN ks cs)
      rwa [size_ofVector] at h
    have hright : (ofVector (k₀.encodeCiphertext c0) ++ encodeCiphertextN ks cs).extract
        k₀.ciphertextSize (ofVector (k₀.encodeCiphertext c0) ++ encodeCiphertextN ks cs).size
        = encodeCiphertextN ks cs := by
      have h := extract_append_right (ofVector (k₀.encodeCiphertext c0)) (encodeCiphertextN ks cs)
      rwa [← ByteArray.size_append, size_ofVector] at h
    rw [hleft, hright, toVecN_ofVector, k₀.decode_encode_ct c0, decode_encode_ct_N ks cs]
    rfl

end Cryptlib.Primitives.KEM.Combiner

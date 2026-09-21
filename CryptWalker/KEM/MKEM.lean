/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.NIKE.NIKE
import CryptWalker.Cipher.AEAD
import CryptWalker.Hash.Hash
import CryptWalker.Util.Bytes

/-! # MKEM: one message, several recipients, built from a NIKE

Mirrors `hpqc/kem/mkem`. To send one payload to several recipients, the sender:

1. makes an ephemeral NIKE key pair,
2. derives one shared key per recipient (`hash` of the Diffie-Hellman output),
3. encrypts the payload once under a fresh random *message key*,
4. encrypts that message key to each recipient under their shared key (a "DEK").

The ciphertext is `(ephemeral public key, DEKs, envelope)`. A recipient derives its shared key from
its own private key and the ephemeral public key, tries the DEKs one after another until one opens,
and uses the message key to open the envelope. The recipient can also *reply* under the same shared
key, so the sender, holding the ephemeral private key, reads the reply without any extra key
exchange (`envelopeReply` / `decryptEnvelope`).

This is a construction over any `NIKE`, `AEAD` and `Hash`, so it needs no particular curve:
`hpqc` runs it over the CTIDH1024-X25519 hybrid, and here any NIKE with the `NIKE` laws works. The
only law used is `NIKE.commutes` (both sides derive the same Diffie-Hellman output).

**What is not stated.** Two recipients' DEKs must not open under each other's key: the trial
decryption takes the first DEK that opens. That is AEAD authenticity, a computational property no
field of `AEAD` can express, so `decapsulate_encapsulate` takes it as an explicit hypothesis
(`hcross`). Randomness (ephemeral seed, message key, nonces) is an explicit argument, as in `AEAD`.
-/

namespace CryptWalker.KEM.MKEM

open CryptWalker.NIKE.NIKE (NIKE)
open CryptWalker.Cipher.AEAD (AEAD)
open CryptWalker.Hash.Hash (Hash)
open CryptWalker.Util.Bytes (ofVector toVecN)

structure Scheme where
  nike : NIKE
  aead : AEAD
  hash : Hash
  /-- The hash of a shared secret is used directly as an AEAD key. -/
  digest_eq_key : hash.digestSize = aead.keySize

/-- An MKEM ciphertext: the sender's ephemeral public key, one DEK per recipient, and the payload
sealed under the message key. A reply has no DEKs. -/
structure Ciphertext (S : Scheme) where
  ephPub : S.nike.PublicKey
  deks : List ByteArray
  envelope : ByteArray

/-- The sender's randomness, explicit so the whole construction is a function. -/
structure Rand (S : Scheme) where
  seed : Vector UInt8 32
  msgKey : Vector UInt8 S.aead.keySize
  envNonce : Vector UInt8 S.aead.nonceSize
  dekNonces : List (Vector UInt8 S.aead.nonceSize)

/-! ### Two list lemmas the correctness proof needs -/

theorem mapM_getElem {α β : Type} (f : α → Option β) :
    ∀ (l : List α) (r : List β), l.mapM f = some r →
      ∃ h : r.length = l.length, ∀ i (hi : i < l.length), f l[i] = some (r[i]'(h ▸ hi))
  | [], r, h => by
    simp at h; subst h; exact ⟨rfl, fun i hi => absurd hi (by simp)⟩
  | a :: l, r, h => by
    simp only [List.mapM_cons] at h
    cases hfa : f a with
    | none => rw [hfa] at h; simp at h
    | some b =>
      rw [hfa] at h
      cases hl : l.mapM f with
      | none => rw [hl] at h; simp at h
      | some rs =>
        rw [hl] at h
        simp at h
        subst h
        obtain ⟨hlen, hget⟩ := mapM_getElem f l rs hl
        refine ⟨by simp [hlen], fun i hi => ?_⟩
        cases i with
        | zero => simpa using hfa
        | succ i => simpa using hget i (by simpa using hi)

theorem findSome?_of_index {α β : Type} (f : α → Option β) :
    ∀ (l : List α) (i : Nat) (hi : i < l.length) (x : β),
      (∀ j (hj : j < i), f (l[j]'(by omega)) = none) → f l[i] = some x → l.findSome? f = some x
  | [], i, hi, _, _, _ => absurd hi (by simp)
  | a :: l, 0, hi, x, _, h => by
    have h' : f a = some x := by simpa using h
    simp [List.findSome?_cons, h']
  | a :: l, i + 1, hi, x, hnone, h => by
    have ha : f a = none := by simpa using hnone 0 (by omega)
    simp only [List.findSome?_cons, ha]
    exact findSome?_of_index f l i (by simpa using hi) x
      (fun j hj => by simpa using hnone (j + 1) (by omega)) (by simpa using h)

namespace Scheme

variable (S : Scheme)

/-- A raw byte string as an AEAD key, if it is the right length. -/
def keyOfBytes (b : ByteArray) : Option S.aead.Key :=
  if b.size = S.aead.keySize then some (S.aead.keyFromBytes (toVecN _ b)) else none

/-- The key two parties share: the hash of their Diffie-Hellman output. `none` for the degenerate
all-zero output, which `hpqc` rejects. -/
def deriveKey (sk : S.nike.PrivateKey) (pk : {pk : S.nike.PublicKey // S.nike.Safe pk}) :
    Option S.aead.Key :=
  let raw := S.nike.encodeSharedSecret (S.nike.groupAction sk pk)
  if raw.toList.all (· == 0) then none
  else some (S.aead.keyFromBytes (Vector.cast S.digest_eq_key (S.hash.hash (ofVector raw))))

/-- Both parties derive the same key: `NIKE.commutes`. -/
theorem deriveKey_comm (sk₁ sk₂ : S.nike.PrivateKey) :
    S.deriveKey sk₁ ⟨S.nike.derivePublicKey sk₂, S.nike.derive_safe sk₂⟩
      = S.deriveKey sk₂ ⟨S.nike.derivePublicKey sk₁, S.nike.derive_safe sk₁⟩ := by
  unfold deriveKey
  rw [S.nike.commutes sk₁ sk₂]

/-! ### Sealing under a key: nonce, then AEAD ciphertext -/

def sealUnder (key : S.aead.Key) (nonce : Vector UInt8 S.aead.nonceSize) (pt : ByteArray) :
    ByteArray :=
  ofVector nonce ++ S.aead.encrypt key nonce ByteArray.empty pt

def unsealUnder (key : S.aead.Key) (ct : ByteArray) : Option ByteArray :=
  if S.aead.nonceSize ≤ ct.size then
    S.aead.decrypt key (toVecN S.aead.nonceSize ct) ByteArray.empty
      (ct.extract S.aead.nonceSize ct.size)
  else none

theorem get!_eq_getElem (x : ByteArray) (i : Nat) (h : i < x.size) : x.get! i = x[i]'h := by
  obtain ⟨bs⟩ := x
  show bs[i]! = (⟨bs⟩ : ByteArray)[i]'h
  rw [getElem!_pos bs i h]
  rfl

theorem toVecN_append {n : Nat} (v : Vector UInt8 n) (c : ByteArray) :
    toVecN n (ofVector v ++ c) = v := by
  apply Vector.ext
  intro i hi
  simp only [toVecN, Vector.getElem_ofFn]
  have hsz : i < (ofVector v).size := by simpa using hi
  have hlt : i < (ofVector v ++ c).size := by simp [ByteArray.size_append]; omega
  rw [get!_eq_getElem _ _ hlt, ByteArray.getElem_append_left hsz]
  rfl

/-- What was sealed opens. -/
theorem unsealUnder_sealUnder (key : S.aead.Key) (nonce : Vector UInt8 S.aead.nonceSize)
    (pt : ByteArray) : S.unsealUnder key (S.sealUnder key nonce pt) = some pt := by
  unfold unsealUnder sealUnder
  generalize hc : S.aead.encrypt key nonce ByteArray.empty pt = c
  have hsize : (ofVector nonce ++ c).size = S.aead.nonceSize + c.size := by
    simp [ByteArray.size_append]
  have hle : S.aead.nonceSize ≤ (ofVector nonce ++ c).size := by omega
  rw [if_pos hle, toVecN_append]
  have hext := CryptWalker.Util.Bytes.extract_append_right (ofVector nonce) c
  simp only [CryptWalker.Util.Bytes.size_ofVector] at hext
  rw [hsize, hext]
  rw [← hc]
  exact S.aead.decrypt_encrypt _ _ _ _

/-! ### Encapsulation and decapsulation -/

/-- Encrypt `payload` to every recipient. `none` if any Diffie-Hellman output is degenerate. -/
def encapsulate (rand : Rand S) (keys : List {pk : S.nike.PublicKey // S.nike.Safe pk})
    (payload : ByteArray) : Option (S.nike.PrivateKey × Ciphertext S) := do
  let ephPriv := S.nike.privateKeyFromSeed rand.seed
  let secrets ← keys.mapM (S.deriveKey ephPriv)
  let msgKey := S.aead.keyFromBytes rand.msgKey
  pure (ephPriv,
    { ephPub := S.nike.derivePublicKey ephPriv
      deks := (secrets.zip rand.dekNonces).map
        (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey))
      envelope := S.sealUnder msgKey rand.envNonce payload })

/-- Open a ciphertext with a recipient's private key: derive the shared key with the ephemeral
public key, take the first DEK that opens, and open the envelope with the message key it holds. -/
def decapsulate (sk : S.nike.PrivateKey) (ct : Ciphertext S) : Option ByteArray :=
  if h : S.nike.Safe ct.ephPub then
    match S.deriveKey sk ⟨ct.ephPub, h⟩ with
    | none => none
    | some k =>
      match ct.deks.findSome? (fun d => S.unsealUnder k d) with
      | none => none
      | some msgKeyBytes =>
        match S.keyOfBytes msgKeyBytes with
        | none => none
        | some msgKey => S.unsealUnder msgKey ct.envelope
  else none

/-! ### Replies -/

/-- A recipient's reply, readable only by the holder of the sender's ephemeral private key. -/
def envelopeReply (sk : S.nike.PrivateKey) (pub : {pk : S.nike.PublicKey // S.nike.Safe pk})
    (nonce : Vector UInt8 S.aead.nonceSize) (pt : ByteArray) : Option ByteArray := do
  let k ← S.deriveKey sk pub
  pure (S.sealUnder k nonce pt)

def decryptEnvelope (sk : S.nike.PrivateKey) (pub : {pk : S.nike.PublicKey // S.nike.Safe pk})
    (envelope : ByteArray) : Option ByteArray := do
  let k ← S.deriveKey sk pub
  S.unsealUnder k envelope

/-- **Replies round-trip.** The sender, who kept the ephemeral private key `eph`, reads what
recipient `sk` sealed under `eph`'s public key. -/
theorem decryptEnvelope_envelopeReply (eph sk : S.nike.PrivateKey)
    (nonce : Vector UInt8 S.aead.nonceSize) (pt env : ByteArray)
    (h : S.envelopeReply sk ⟨S.nike.derivePublicKey eph, S.nike.derive_safe eph⟩ nonce pt = some env) :
    S.decryptEnvelope eph ⟨S.nike.derivePublicKey sk, S.nike.derive_safe sk⟩ env = some pt := by
  unfold envelopeReply at h
  unfold decryptEnvelope
  rw [deriveKey_comm S eph sk]
  cases hk : S.deriveKey sk ⟨S.nike.derivePublicKey eph, S.nike.derive_safe eph⟩ with
  | none => rw [hk] at h; simp at h
  | some k =>
    rw [hk] at h
    simp at h
    subst h
    simp [S.unsealUnder_sealUnder]

/-- **A recipient recovers the payload.** If `encapsulate` succeeded with ephemeral key `eph`, then
recipient `i`, holding the private key `sk` of the `i`-th public key, decapsulates to `payload`.

`hcross` is the one thing assumed: no earlier recipient's DEK opens under recipient `i`'s shared key
(trial decryption takes the first DEK that opens). That is AEAD authenticity, a computational
property no field of `AEAD` can state. -/
theorem decapsulate_encapsulate (rand : Rand S)
    (keys : List {pk : S.nike.PublicKey // S.nike.Safe pk}) (payload : ByteArray)
    (eph : S.nike.PrivateKey) (ct : Ciphertext S)
    (henc : S.encapsulate rand keys payload = some (eph, ct))
    (hlen : rand.dekNonces.length = keys.length)
    (i : Nat) (hi : i < keys.length) (sk : S.nike.PrivateKey)
    (hsk : keys[i] = ⟨S.nike.derivePublicKey sk, S.nike.derive_safe sk⟩)
    (hcross : ∀ k, S.deriveKey eph keys[i] = some k →
      ∀ j (hj : j < i) (hj' : j < ct.deks.length), S.unsealUnder k ct.deks[j] = none) :
    S.decapsulate sk ct = some payload := by
  unfold encapsulate at henc
  cases hm : keys.mapM (S.deriveKey (S.nike.privateKeyFromSeed rand.seed)) with
  | none => simp [hm] at henc
  | some secrets =>
    simp [hm] at henc
    obtain ⟨heph, hct⟩ := henc
    subst heph
    subst hct
    obtain ⟨hlenS, hget⟩ := mapM_getElem _ keys secrets hm
    have hsecret := hget i hi
    have hsi : i < secrets.length := hlenS ▸ hi
    have hzip : (secrets.zip rand.dekNonces).length = secrets.length := by
      simp [List.length_zip, hlenS, hlen]
    have hdek : ∀ (hj : i < ((secrets.zip rand.dekNonces).map
          (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey))).length),
        ((secrets.zip rand.dekNonces).map
          (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey)))[i]'hj
          = S.sealUnder secrets[i] rand.dekNonces[i] (ofVector rand.msgKey) := by
      intro hj
      simp
    have hkey : S.deriveKey sk ⟨S.nike.derivePublicKey (S.nike.privateKeyFromSeed rand.seed),
        S.nike.derive_safe _⟩ = some secrets[i] := by
      rw [S.deriveKey_comm sk, ← hsk]; exact hsecret
    unfold decapsulate
    rw [dif_pos (S.nike.derive_safe _)]
    simp only []
    rw [hkey]
    simp only []
    have hlt : i < ((secrets.zip rand.dekNonces).map
        (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey))).length := by
      simp [hzip, hsi]
    rw [findSome?_of_index (fun d => S.unsealUnder secrets[i] d) _ i hlt (ofVector rand.msgKey)
      (fun j hj => hcross _ hsecret j hj (Nat.lt_trans hj hlt))
      (by rw [hdek hlt]; exact S.unsealUnder_sealUnder _ _ _)]
    have hk : S.keyOfBytes (ofVector rand.msgKey) = some (S.aead.keyFromBytes rand.msgKey) := by
      unfold keyOfBytes
      rw [if_pos (by simp), CryptWalker.Util.Bytes.toVecN_ofVector]
    simp only [hk, S.unsealUnder_sealUnder]

/-- The ciphertext carries the ephemeral public key of the private key `encapsulate` returns. -/
theorem encapsulate_ephPub (rand : Rand S) (keys : List {pk : S.nike.PublicKey // S.nike.Safe pk})
    (payload : ByteArray) (eph : S.nike.PrivateKey) (ct : Ciphertext S)
    (h : S.encapsulate rand keys payload = some (eph, ct)) :
    ct.ephPub = S.nike.derivePublicKey eph := by
  unfold encapsulate at h
  cases hm : keys.mapM (S.deriveKey (S.nike.privateKeyFromSeed rand.seed)) with
  | none => simp [hm] at h
  | some secrets =>
    simp [hm] at h
    obtain ⟨rfl, rfl⟩ := h
    rfl

/-- If decapsulation succeeds, the recipient did derive a shared key with the ephemeral key. -/
theorem decapsulate_key (sk : S.nike.PrivateKey) (ct : Ciphertext S) (pt : ByteArray)
    (h : S.decapsulate sk ct = some pt) :
    ∃ hs : S.nike.Safe ct.ephPub, ∃ k, S.deriveKey sk ⟨ct.ephPub, hs⟩ = some k := by
  unfold decapsulate at h
  by_cases hs : S.nike.Safe ct.ephPub
  · rw [dif_pos hs] at h
    cases hk : S.deriveKey sk ⟨ct.ephPub, hs⟩ with
    | none => rw [hk] at h; simp at h
    | some k => exact ⟨hs, k, hk⟩
  · rw [dif_neg hs] at h; simp at h

end Scheme

end CryptWalker.KEM.MKEM

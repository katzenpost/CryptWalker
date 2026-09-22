/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.MKEM.MKEM
import CryptWalker.KEM.Adapter
import CryptWalker.NIKE.NIKE
import CryptWalker.Cipher.AEAD
import CryptWalker.Hash.Hash
import CryptWalker.Util.Bytes

/-! # MKEM from a NIKE, an AEAD and a hash

Builds an `MKEM` the way `hpqc/kem/mkem/mkem.go` does, over any `NIKE`, `AEAD` and `Hash`; no
particular curve is assumed (`hpqc` runs it over the CTIDH1024-X25519 hybrid). The only law about
the NIKE that is used is `NIKE.commutes`: both parties derive the same Diffie-Hellman output.

```
ENCAPSULATE(keys, payload):
    eph            := GEN_KEYPAIR()
    secret_i       := HASH(DH(eph, keys[i]))            -- error if DH output is all zero
    msgKey         := RANDOM(32)
    envelope       := nonce ‖ AEAD_seal(msgKey, payload)
    dek_i          := nonce_i ‖ AEAD_seal(secret_i, msgKey)
    return eph, (eph_pub, [dek_i], envelope)

DECAPSULATE(sk, ct):
    secret         := HASH(DH(sk, ct.eph_pub))
    for dek in ct.deks: first one that opens under secret gives msgKey
    return open(msgKey, ct.envelope)
```

Randomness is drawn from `Adapter.St` (a counter over a seed stream), in `hpqc`'s order: ephemeral
seed, message key, envelope nonce, then one nonce per recipient. The pure functions take an explicit
`Rand` and the state functions build one from the stream. **The stream must be unpredictable, which
nothing here can check.**

`decapsulateP_encapsulateP_full` is the correctness of decapsulating the *whole* multi-DEK
ciphertext. It needs `hcross`, that no earlier DEK opens under this recipient's key, which is AEAD
authenticity and so cannot be a law of `MKEM` (see there); the law that is a field is stated for the
per-recipient ciphertext. -/

namespace CryptWalker.MKEM.Adapter

open CryptWalker.MKEM.MKEM
open CryptWalker.NIKE.NIKE (NIKE)
open CryptWalker.Cipher.AEAD (AEAD)
open CryptWalker.Hash.Hash (Hash)
open CryptWalker.Util.Bytes (ofVector toVecN)
open CryptWalker.KEM.Adapter (St Bytes32)

/-- The three primitives, and the fact that lets a hash output be an AEAD key. -/
structure Base where
  nike : NIKE
  aead : AEAD
  hash : Hash
  digest_eq_key : hash.digestSize = aead.keySize

/-- The sender's randomness, explicit so the pure construction is a function. -/
structure Rand (S : Base) where
  seed : Vector UInt8 32
  msgKey : Vector UInt8 S.aead.keySize
  envNonce : Vector UInt8 S.aead.nonceSize
  dekNonces : List (Vector UInt8 S.aead.nonceSize)

/-! ### Two list lemmas the correctness proofs need -/

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
    simp [h']
  | a :: l, i + 1, hi, x, hnone, h => by
    have ha : f a = none := by simpa using hnone 0 (by omega)
    simp only [List.findSome?_cons, ha]
    exact findSome?_of_index f l i (by simpa using hi) x
      (fun j hj => by simpa using hnone (j + 1) (by omega)) (by simpa using h)

namespace Base

variable (S : Base)

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

theorem size_sealUnder (key : S.aead.Key) (nonce : Vector UInt8 S.aead.nonceSize) (pt : ByteArray) :
    (S.sealUnder key nonce pt).size = S.aead.nonceSize + (pt.size + S.aead.tagSize) := by
  unfold sealUnder
  simp [ByteArray.size_append, S.aead.size_encrypt]

/-! ### The construction, with explicit randomness -/

/-- Encrypt `payload` to every recipient. `none` if any Diffie-Hellman output is degenerate. -/
def encapsulateP (rand : Rand S) (keys : List {pk : S.nike.PublicKey // S.nike.Safe pk})
    (payload : ByteArray) : Option (S.nike.PrivateKey × Ciphertext S.nike.PublicKey) := do
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
def decapsulateP (sk : S.nike.PrivateKey) (ct : Ciphertext S.nike.PublicKey) : Option ByteArray :=
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

theorem encapsulateP_ephPub (rand : Rand S) (keys : List {pk : S.nike.PublicKey // S.nike.Safe pk})
    (payload : ByteArray) (eph : S.nike.PrivateKey) (ct : Ciphertext S.nike.PublicKey)
    (h : S.encapsulateP rand keys payload = some (eph, ct)) :
    ct.ephPub = S.nike.derivePublicKey eph := by
  unfold encapsulateP at h
  cases hm : keys.mapM (S.deriveKey (S.nike.privateKeyFromSeed rand.seed)) with
  | none => simp [hm] at h
  | some secrets =>
    simp [hm] at h
    obtain ⟨rfl, rfl⟩ := h
    rfl

/-- Unpack a successful encapsulation. -/
theorem encapsulateP_spec (rand : Rand S) (keys : List {pk : S.nike.PublicKey // S.nike.Safe pk})
    (payload : ByteArray) (eph : S.nike.PrivateKey) (ct : Ciphertext S.nike.PublicKey)
    (h : S.encapsulateP rand keys payload = some (eph, ct)) :
    eph = S.nike.privateKeyFromSeed rand.seed ∧ ∃ secrets : List S.aead.Key,
      keys.mapM (S.deriveKey eph) = some secrets ∧
      ct = { ephPub := S.nike.derivePublicKey eph
             deks := (secrets.zip rand.dekNonces).map
               (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey))
             envelope := S.sealUnder (S.aead.keyFromBytes rand.msgKey) rand.envNonce payload } := by
  unfold encapsulateP at h
  cases hm : keys.mapM (S.deriveKey (S.nike.privateKeyFromSeed rand.seed)) with
  | none => simp [hm] at h
  | some secrets =>
    simp [hm] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨rfl, secrets, hm, rfl⟩

/-- **Shape.** One DEK per recipient, each `nonce + key + tag` bytes, and an envelope `nonce + tag`
longer than the payload. -/
theorem encapsulateP_shape (rand : Rand S) (keys : List {pk : S.nike.PublicKey // S.nike.Safe pk})
    (payload : ByteArray) (eph : S.nike.PrivateKey) (ct : Ciphertext S.nike.PublicKey)
    (hlen : rand.dekNonces.length = keys.length)
    (h : S.encapsulateP rand keys payload = some (eph, ct)) :
    ct.deks.length = keys.length ∧
      (∀ d ∈ ct.deks, d.size = S.aead.nonceSize + S.aead.keySize + S.aead.tagSize) ∧
      ct.envelope.size = payload.size + (S.aead.nonceSize + S.aead.tagSize) := by
  obtain ⟨rfl, secrets, hm, rfl⟩ := S.encapsulateP_spec rand keys payload eph ct h
  obtain ⟨hlenS, _⟩ := mapM_getElem _ keys secrets hm
  refine ⟨?_, ?_, ?_⟩
  · simp [List.length_zip, hlenS, hlen]
  · intro d hd
    obtain ⟨p, _, rfl⟩ := List.mem_map.mp hd
    rw [S.size_sealUnder]
    simp only [CryptWalker.Util.Bytes.size_ofVector]
    omega
  · simp only []
    rw [S.size_sealUnder]
    omega

/-- **A recipient recovers the payload from the ciphertext it is handed**: the one carrying only its
own DEK, which is how `hpqc` and Pigeonhole use MKEM. Unconditional. -/
theorem decapsulateP_forRecipient (rand : Rand S)
    (keys : List {pk : S.nike.PublicKey // S.nike.Safe pk}) (payload : ByteArray)
    (eph : S.nike.PrivateKey) (ct : Ciphertext S.nike.PublicKey)
    (hlen : rand.dekNonces.length = keys.length)
    (henc : S.encapsulateP rand keys payload = some (eph, ct))
    (i : Nat) (hi : i < keys.length) (sk : S.nike.PrivateKey)
    (hsk : keys[i] = ⟨S.nike.derivePublicKey sk, S.nike.derive_safe sk⟩) :
    S.decapsulateP sk (ct.forRecipient i) = some payload := by
  obtain ⟨rfl, secrets, hm, rfl⟩ := S.encapsulateP_spec rand keys payload eph ct henc
  obtain ⟨hlenS, hget⟩ := mapM_getElem _ keys secrets hm
  have hsecret := hget i hi
  have hsi : i < secrets.length := hlenS ▸ hi
  have hzip : (secrets.zip rand.dekNonces).length = secrets.length := by
    simp [List.length_zip, hlenS, hlen]
  have hlt : i < ((secrets.zip rand.dekNonces).map
      (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey))).length := by
    simp [hzip, hsi]
  have hdek : ((secrets.zip rand.dekNonces).map
        (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey)))[i]'hlt
        = S.sealUnder secrets[i] rand.dekNonces[i] (ofVector rand.msgKey) := by
    simp
  have hkey : S.deriveKey sk ⟨S.nike.derivePublicKey (S.nike.privateKeyFromSeed rand.seed),
      S.nike.derive_safe _⟩ = some secrets[i] := by
    rw [S.deriveKey_comm sk, ← hsk]; exact hsecret
  unfold decapsulateP Ciphertext.forRecipient
  rw [dif_pos (S.nike.derive_safe _)]
  simp only []
  rw [hkey]
  simp only []
  have hget? : ((secrets.zip rand.dekNonces).map
        (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey)))[i]?
      = some (S.sealUnder secrets[i] rand.dekNonces[i] (ofVector rand.msgKey)) := by
    rw [List.getElem?_eq_getElem hlt, hdek]
  simp only [hget?, Option.toList_some, List.findSome?_cons, List.findSome?_nil]
  rw [S.unsealUnder_sealUnder]
  have hk : S.keyOfBytes (ofVector rand.msgKey) = some (S.aead.keyFromBytes rand.msgKey) := by
    unfold keyOfBytes
    rw [if_pos (by simp), CryptWalker.Util.Bytes.toVecN_ofVector]
  simp only [hk, S.unsealUnder_sealUnder]

/-- Decapsulating the *whole* multi-DEK ciphertext. Needs `hcross`: no earlier DEK opens under this
recipient's key (AEAD authenticity, which `AEAD` cannot state). -/
theorem decapsulateP_encapsulateP_full (rand : Rand S)
    (keys : List {pk : S.nike.PublicKey // S.nike.Safe pk}) (payload : ByteArray)
    (eph : S.nike.PrivateKey) (ct : Ciphertext S.nike.PublicKey)
    (hlen : rand.dekNonces.length = keys.length)
    (henc : S.encapsulateP rand keys payload = some (eph, ct))
    (i : Nat) (hi : i < keys.length) (sk : S.nike.PrivateKey)
    (hsk : keys[i] = ⟨S.nike.derivePublicKey sk, S.nike.derive_safe sk⟩)
    (hcross : ∀ k, S.deriveKey eph keys[i] = some k →
      ∀ j (hj : j < i) (hj' : j < ct.deks.length), S.unsealUnder k ct.deks[j] = none) :
    S.decapsulateP sk ct = some payload := by
  obtain ⟨rfl, secrets, hm, rfl⟩ := S.encapsulateP_spec rand keys payload eph ct henc
  obtain ⟨hlenS, hget⟩ := mapM_getElem _ keys secrets hm
  have hsecret := hget i hi
  have hsi : i < secrets.length := hlenS ▸ hi
  have hzip : (secrets.zip rand.dekNonces).length = secrets.length := by
    simp [List.length_zip, hlenS, hlen]
  have hlt : i < ((secrets.zip rand.dekNonces).map
      (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey))).length := by
    simp [hzip, hsi]
  have hdek : ((secrets.zip rand.dekNonces).map
        (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey)))[i]'hlt
        = S.sealUnder secrets[i] rand.dekNonces[i] (ofVector rand.msgKey) := by
    simp
  have hkey : S.deriveKey sk ⟨S.nike.derivePublicKey (S.nike.privateKeyFromSeed rand.seed),
      S.nike.derive_safe _⟩ = some secrets[i] := by
    rw [S.deriveKey_comm sk, ← hsk]; exact hsecret
  unfold decapsulateP
  rw [dif_pos (S.nike.derive_safe _)]
  simp only []
  rw [hkey]
  simp only []
  rw [findSome?_of_index (fun d => S.unsealUnder secrets[i] d) _ i hlt (ofVector rand.msgKey)
    (fun j hj => hcross _ hsecret j hj (Nat.lt_trans hj hlt))
    (by rw [hdek]; exact S.unsealUnder_sealUnder _ _ _)]
  have hk : S.keyOfBytes (ofVector rand.msgKey) = some (S.aead.keyFromBytes rand.msgKey) := by
    unfold keyOfBytes
    rw [if_pos (by simp), CryptWalker.Util.Bytes.toVecN_ofVector]
  simp only [hk, S.unsealUnder_sealUnder]

/-! ### Replies -/

def envelopeReplyP (sk : S.nike.PrivateKey) (pub : {pk : S.nike.PublicKey // S.nike.Safe pk})
    (nonce : Vector UInt8 S.aead.nonceSize) (pt : ByteArray) : Option ByteArray := do
  let k ← S.deriveKey sk pub
  pure (S.sealUnder k nonce pt)

def decryptEnvelopeP (sk : S.nike.PrivateKey) (pub : {pk : S.nike.PublicKey // S.nike.Safe pk})
    (envelope : ByteArray) : Option ByteArray := do
  let k ← S.deriveKey sk pub
  S.unsealUnder k envelope

theorem decryptEnvelopeP_envelopeReplyP (eph sk : S.nike.PrivateKey)
    (nonce : Vector UInt8 S.aead.nonceSize) (pt env : ByteArray)
    (h : S.envelopeReplyP sk ⟨S.nike.derivePublicKey eph, S.nike.derive_safe eph⟩ nonce pt
      = some env) :
    S.decryptEnvelopeP eph ⟨S.nike.derivePublicKey sk, S.nike.derive_safe sk⟩ env = some pt := by
  unfold envelopeReplyP at h
  unfold decryptEnvelopeP
  rw [deriveKey_comm S eph sk]
  cases hk : S.deriveKey sk ⟨S.nike.derivePublicKey eph, S.nike.derive_safe eph⟩ with
  | none => rw [hk] at h; simp at h
  | some k =>
    rw [hk] at h
    simp at h
    subst h
    simp [S.unsealUnder_sealUnder]

end Base

/-! ### The `MKEM` instance: randomness from a seed stream, errors as `Except` -/

section Instance

variable (S : Base)

/-- Big-endian-free counter bytes, so each block of the seed stream is a distinct hash input. -/
def counterBytes (i : Nat) : ByteArray :=
  ⟨(Array.range 8).map fun k => (i >>> (8 * k)).toUInt8⟩

/-- The randomness for one encapsulation to `n` recipients, drawn from the stream at position `i`,
in `hpqc`'s order: ephemeral seed, message key, envelope nonce, one nonce per recipient. -/
def randOf (i : Nat) (str : Nat → Bytes32) (n : Nat) : Rand S where
  seed := str i
  msgKey := toVecN _ (ofVector (str (i + 1)))
  envNonce := toVecN _ (ofVector (str (i + 2)))
  dekNonces := (List.range n).map fun j => toVecN _ (ofVector (str (i + 3 + j)))

theorem randOf_dekNonces_length (i : Nat) (str : Nat → Bytes32) (n : Nat) :
    (randOf S i str n).dekNonces.length = n := by
  simp [randOf]

def encapM (keys : List {pk : S.nike.PublicKey // S.nike.Safe pk}) (payload : ByteArray) :
    EStateM MKEMError St (S.nike.PrivateKey × Ciphertext S.nike.PublicKey) :=
  fun (i, str) =>
    match S.encapsulateP (randOf S i str keys.length) keys payload with
    | some r => EStateM.Result.ok r (i + 3 + keys.length, str)
    | none => EStateM.Result.error .degenerateSharedSecret (i + 3 + keys.length, str)

theorem encapM_ok (keys : List {pk : S.nike.PublicKey // S.nike.Safe pk}) (payload : ByteArray)
    (s : St) (r) (s' : St) (h : encapM S keys payload s = .ok r s') :
    ∃ rand : Rand S, rand.dekNonces.length = keys.length ∧
      S.encapsulateP rand keys payload = some r := by
  obtain ⟨i, str⟩ := s
  simp only [encapM] at h
  split at h
  · rename_i r' hr'
    injection h with h1 _
    subst h1
    exact ⟨_, randOf_dekNonces_length S i str keys.length, hr'⟩
  · cases h

def decapE (sk : S.nike.PrivateKey) (ct : Ciphertext S.nike.PublicKey) :
    Except MKEMError ByteArray :=
  match S.decapsulateP sk ct with
  | some p => .ok p
  | none => .error (if S.nike.Safe ct.ephPub then .trialDecryptFailed else .unsafePublicKey)

def replyM (sk : S.nike.PrivateKey) (pub : {pk : S.nike.PublicKey // S.nike.Safe pk})
    (pt : ByteArray) : EStateM MKEMError St ByteArray :=
  fun (i, str) =>
    match S.deriveKey sk pub with
    | none => EStateM.Result.error .degenerateSharedSecret (i + 1, str)
    | some k => EStateM.Result.ok (S.sealUnder k (toVecN _ (ofVector (str i))) pt) (i + 1, str)

def decryptE (sk : S.nike.PrivateKey) (pub : {pk : S.nike.PublicKey // S.nike.Safe pk})
    (env : ByteArray) : Except MKEMError ByteArray :=
  match S.deriveKey sk pub with
  | none => .error .degenerateSharedSecret
  | some k =>
    match S.unsealUnder k env with
    | some p => .ok p
    | none => .error .trialDecryptFailed

def generateM : EStateM MKEMError St (S.nike.PublicKey × S.nike.PrivateKey) :=
  fun (i, str) =>
    let sk := S.nike.privateKeyFromSeed (str i)
    EStateM.Result.ok (S.nike.derivePublicKey sk, sk) (i + 1, str)

/-- **MKEM over the given NIKE, AEAD and hash.** Every law of `MKEM` is discharged, so nothing is
assumed beyond the laws of the three primitives. -/
def ofBase : MKEM where
  PrivateKey := S.nike.PrivateKey
  PublicKey := S.nike.PublicKey
  Safe := S.nike.Safe
  State := St
  -- Inhabitance only: a constant stream. Honest runs start from `stateFromSeed`.
  stateI := ⟨(0, fun _ => Vector.replicate 32 0)⟩
  name := "MKEM-" ++ S.nike.name ++ "-" ++ S.aead.name
  publicKeySize := S.nike.publicKeySize
  dekSize := S.aead.nonceSize + S.aead.keySize + S.aead.tagSize
  envelopeOverhead := S.aead.nonceSize + S.aead.tagSize
  derivePublicKey := S.nike.derivePublicKey
  encodePublicKey := S.nike.encodePublicKey
  decodePublicKey := S.nike.decodePublicKey
  stateFromSeed := fun seed =>
    (0, fun i => toVecN 32 (ofVector (S.hash.hash (ofVector seed ++ counterBytes i))))
  generate := generateM S
  encapsulate := encapM S
  decapsulate := decapE S
  envelopeReply := replyM S
  decryptEnvelope := decryptE S
  derive_safe := S.nike.derive_safe
  decode_encode_pub := S.nike.decode_encode_pub
  generate_derive := by
    rintro ⟨i, str⟩ pk sk s' h
    simp only [generateM] at h
    injection h with h1 _
    injection h1 with h2 h3
    subst h2; subst h3; rfl
  encapsulate_ephPub := by
    intro keys payload s eph ct s' h
    obtain ⟨rand, _, hp⟩ := encapM_ok S keys payload s _ s' h
    exact S.encapsulateP_ephPub rand keys payload eph ct hp
  encapsulate_shape := by
    intro keys payload s eph ct s' h
    obtain ⟨rand, hlen, hp⟩ := encapM_ok S keys payload s _ s' h
    exact S.encapsulateP_shape rand keys payload eph ct hlen hp
  decapsulate_encapsulate := by
    intro keys payload s eph ct s' h i hi sk hsk
    obtain ⟨rand, hlen, hp⟩ := encapM_ok S keys payload s _ s' h
    have := S.decapsulateP_forRecipient rand keys payload eph ct hlen hp i hi sk hsk
    simp [decapE, this]
  decryptEnvelope_envelopeReply := by
    rintro sk eph pt ⟨i, str⟩ env s' h
    simp only [replyM] at h
    cases hk : S.deriveKey sk ⟨S.nike.derivePublicKey eph, S.nike.derive_safe eph⟩ with
    | none => rw [hk] at h; cases h
    | some k =>
      rw [hk] at h
      injection h with h1 _
      subst h1
      simp only [decryptE]
      rw [S.deriveKey_comm eph sk, hk]
      simp [S.unsealUnder_sealUnder]

end Instance

/-- `mkemOfNike nike aead hash h`: hpqc's MKEM over any NIKE, AEAD and hash whose digest is an AEAD
key. -/
def mkemOfNike (nike : NIKE) (aead : AEAD) (hash : Hash) (h : hash.digestSize = aead.keySize) :
    MKEM :=
  ofBase ⟨nike, aead, hash, h⟩

end CryptWalker.MKEM.Adapter

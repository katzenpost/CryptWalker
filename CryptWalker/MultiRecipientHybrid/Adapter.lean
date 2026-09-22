/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.MultiRecipientHybrid.MultiRecipientHybrid
import CryptWalker.KEM.KEM
import CryptWalker.KEM.Adapter
import CryptWalker.MKEM.Adapter
import CryptWalker.Cipher.AEAD
import CryptWalker.Hash.Hash
import CryptWalker.Util.Bytes

/-! # `MultiRecipientHybrid` from a KEM, an AEAD and a hash

Builds a `MultiRecipientHybrid` over any `KEM`, `AEAD` and `Hash`, no particular KEM assumed.

```
ENCAPSULATE(keys, payload):
    for pk in keys: ct_i, ss_i := KEM_ENCAP(pk)        -- independent per recipient
    secret_i       := HASH(ss_i)
    msgKey         := RANDOM(32)
    envelope       := nonce ‖ AEAD_seal(msgKey, payload)
    dek_i          := nonce_i ‖ AEAD_seal(secret_i, msgKey)
    return [secret_i], ([ct_i], [dek_i], envelope)

DECAPSULATE(sk, ct):                                    -- ct already filtered to one recipient
    ss             := KEM_DECAP(sk, ct.kemCiphertexts[0])
    secret         := HASH(ss)
    msgKey         := AEAD_open(secret, ct.deks[0])
    return secret, AEAD_open(msgKey, ct.envelope)
```

Randomness is drawn from `KEM.Adapter.St` (the same counter-over-a-seed-stream `MKEM.Adapter`
uses), in this order: message key, envelope nonce, then one DEK nonce and one 32-byte KEM seed per
recipient. The pure functions take an explicit `Rand`; the state functions build one from the
stream. **The stream must be unpredictable, which nothing here can check.**

## `Reliable`

A general `KEM`'s decapsulation is not unconditionally correct — `KEM.Reliable` exists precisely
because a lattice KEM's noise can (rarely) exceed its decoding margin. `RandReliable` lifts that
condition to every KEM seed a `Rand` draws; `Reliable` (on the state stream) lifts it again to
every draw a future `encapsulate` call could make from that state, whatever number of recipients
it turns out to have — the same operational style `MLKEM768.Reliable` already uses, just quantified
over the stream instead of one draw. -/

namespace CryptWalker.MultiRecipientHybrid.Adapter

open CryptWalker.MultiRecipientHybrid.MultiRecipientHybrid
open CryptWalker.KEM.KEM (KEM)
open CryptWalker.Cipher.AEAD (AEAD)
open CryptWalker.Hash.Hash (Hash)
open CryptWalker.Util.Bytes (ofVector toVecN)
open CryptWalker.KEM.Adapter (St Bytes32)

/-- The three primitives, and the fact that lets a hash output be an AEAD key. -/
structure Base where
  kem : KEM
  aead : AEAD
  hash : Hash
  digest_eq_key : hash.digestSize = aead.keySize

/-- The sender's randomness, explicit so the pure construction is a function. One `kemSeed` per
recipient, turned into a `kem.State` via `kem.stateFromSeed` — there is no shared ephemeral value
a `KEM` can supply, unlike `MKEM.Rand.seed`. -/
structure Rand (S : Base) where
  msgKey : Vector UInt8 S.aead.keySize
  envNonce : Vector UInt8 S.aead.nonceSize
  dekNonces : List (Vector UInt8 S.aead.nonceSize)
  kemSeeds : List (Vector UInt8 32)

namespace Base

variable (S : Base)

/-- A raw byte string as an AEAD key, if it is the right length — `MKEM.Adapter.Base.keyOfBytes`. -/
def keyOfBytes (b : ByteArray) : Option S.aead.Key :=
  if b.size = S.aead.keySize then some (S.aead.keyFromBytes (toVecN _ b)) else none

/-- A KEM's shared secret, hashed — the raw bytes exposed to the caller as the derived key. -/
def deriveKeyBytes (ss : S.kem.Plaintext) : ByteArray :=
  ofVector (S.hash.hash (ofVector (S.kem.encodePlaintext ss)))

/-- The same key, as an `AEAD.Key`, for sealing/unsealing internally. -/
def deriveKeyAead (ss : S.kem.Plaintext) : S.aead.Key :=
  S.aead.keyFromBytes (Vector.cast S.digest_eq_key (S.hash.hash (ofVector (S.kem.encodePlaintext ss))))

/-! ### Sealing under a key: nonce, then AEAD ciphertext — `MKEM.Adapter.Base`, verbatim -/

theorem get!_eq_getElem (x : ByteArray) (i : Nat) (h : i < x.size) : x.get! i = x[i]'h := by
  obtain ⟨bs⟩ := x
  show bs[i]! = (⟨bs⟩ : ByteArray)[i]'h
  rw [getElem!_pos bs i h]
  rfl

def sealUnder (key : S.aead.Key) (nonce : Vector UInt8 S.aead.nonceSize) (pt : ByteArray) :
    ByteArray :=
  ofVector nonce ++ S.aead.encrypt key nonce ByteArray.empty pt

def unsealUnder (key : S.aead.Key) (ct : ByteArray) : Option ByteArray :=
  if S.aead.nonceSize ≤ ct.size then
    S.aead.decrypt key (toVecN S.aead.nonceSize ct) ByteArray.empty
      (ct.extract S.aead.nonceSize ct.size)
  else none

theorem toVecN_append {n : Nat} (v : Vector UInt8 n) (c : ByteArray) :
    toVecN n (ofVector v ++ c) = v := by
  apply Vector.ext
  intro i hi
  simp only [toVecN, Vector.getElem_ofFn]
  have hsz : i < (ofVector v).size := by simpa using hi
  have hlt : i < (ofVector v ++ c).size := by simp [ByteArray.size_append]; omega
  rw [get!_eq_getElem _ _ hlt, ByteArray.getElem_append_left hsz]
  rfl

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

/-! ### One KEM encapsulation, wrapped as `Option` -/

/-- `kem.encap` against a seed-derived state, folding a `KEM.KEMError` into `none`. The resulting
state is discarded: `decap` will later be run against an arbitrary state too (`KEM.honestRoundTrip`
quantifies over any decap-side state), so nothing here depends on it. -/
def encapPair (pk : S.kem.PublicKey) (seed : Vector UInt8 32) :
    Option (S.kem.Ciphertext × S.kem.Plaintext) :=
  match S.kem.encap pk (S.kem.stateFromSeed seed) with
  | .ok r _ => some r
  | .error _ _ => none

/-- Every KEM seed a `Rand` draws lands on a `Reliable` state. -/
def RandReliable (rand : Rand S) : Prop :=
  ∀ seed ∈ rand.kemSeeds, S.kem.Reliable (S.kem.stateFromSeed seed)

/-! ### The construction, with explicit randomness -/

/-- Encrypt `payload` to every recipient. `none` if any recipient's `KEM.encap` fails. -/
def encapsulateP (rand : Rand S) (keys : List S.kem.PublicKey) (payload : ByteArray) :
    Option (List ByteArray × Ciphertext S.kem.Ciphertext) := do
  let pairs ← (keys.zip rand.kemSeeds).mapM (fun p => S.encapPair p.1 p.2)
  let msgKey := S.aead.keyFromBytes rand.msgKey
  pure (pairs.map (fun p => S.deriveKeyBytes p.2),
    { kemCiphertexts := pairs.map Prod.fst
      deks := ((pairs.map (fun p => S.deriveKeyAead p.2)).zip rand.dekNonces).map
        (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey))
      envelope := S.sealUnder msgKey rand.envNonce payload })

/-- Open a ciphertext already filtered to one recipient: decapsulate the KEM ciphertext, open the
one DEK it carries, then the envelope. -/
def decapsulateP (sk : S.kem.PrivateKey) (ct : Ciphertext S.kem.Ciphertext) :
    Option (ByteArray × ByteArray) :=
  match ct.kemCiphertexts.head?, ct.deks.head? with
  | some kc, some dek =>
    match S.kem.decap sk kc default with
    | .ok ss _ =>
      match S.unsealUnder (S.deriveKeyAead ss) dek with
      | none => none
      | some msgKeyBytes =>
        match S.keyOfBytes msgKeyBytes with
        | none => none
        | some msgKey =>
          match S.unsealUnder msgKey ct.envelope with
          | none => none
          | some payload => some (S.deriveKeyBytes ss, payload)
    | .error _ _ => none
  | _, _ => none

/-- Unpack a successful encapsulation. -/
theorem encapsulateP_spec (rand : Rand S) (keys : List S.kem.PublicKey) (payload : ByteArray)
    (derivedKeys : List ByteArray) (ct : Ciphertext S.kem.Ciphertext)
    (h : S.encapsulateP rand keys payload = some (derivedKeys, ct)) :
    ∃ pairs : List (S.kem.Ciphertext × S.kem.Plaintext),
      (keys.zip rand.kemSeeds).mapM (fun p => S.encapPair p.1 p.2) = some pairs ∧
      derivedKeys = pairs.map (fun p => S.deriveKeyBytes p.2) ∧
      ct = { kemCiphertexts := pairs.map Prod.fst
             deks := ((pairs.map (fun p => S.deriveKeyAead p.2)).zip rand.dekNonces).map
               (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey))
             envelope := S.sealUnder (S.aead.keyFromBytes rand.msgKey) rand.envNonce payload } := by
  unfold encapsulateP at h
  -- `cases`/`rcases` on this `Option` directly inside a proof whose goal is `∃ pairs, ... = some
  -- pairs ∧ ...` corrupts elaboration of the final `⟨pairs, ...⟩` (a reproducible quirk, isolated
  -- separately: providing the `cases`-bound variable as the existential witness makes the *first*
  -- conjunct's expected type collapse to `some pairs = some pairs` instead of the real equation).
  -- Isolating the `cases` inside a boring, non-existential `have` avoids it.
  have hsome : ((keys.zip rand.kemSeeds).mapM (fun p => S.encapPair p.1 p.2)).isSome := by
    rcases hm0 : (keys.zip rand.kemSeeds).mapM (fun p => S.encapPair p.1 p.2) with _ | pairs0
    · simp [hm0] at h
    · simp [hm0]
  generalize hv : Option.get _ hsome = pairs at h
  have hm : (keys.zip rand.kemSeeds).mapM (fun p => S.encapPair p.1 p.2) = some pairs := by
    rw [← hv]; exact (Option.some_get hsome).symm
  rw [hm] at h
  simp at h
  exact ⟨pairs, hm, h.1.symm, h.2.symm⟩

/-- **Shape.** One KEM ciphertext, one DEK and one derived key per recipient, each DEK exactly
`nonce + key + tag` bytes, and an envelope `nonce + tag` longer than the payload. -/
theorem encapsulateP_shape (rand : Rand S) (keys : List S.kem.PublicKey) (payload : ByteArray)
    (hlen : rand.kemSeeds.length = keys.length) (hlen' : rand.dekNonces.length = keys.length)
    (derivedKeys : List ByteArray) (ct : Ciphertext S.kem.Ciphertext)
    (h : S.encapsulateP rand keys payload = some (derivedKeys, ct)) :
    ct.kemCiphertexts.length = keys.length ∧ ct.deks.length = keys.length ∧
      derivedKeys.length = keys.length ∧
      (∀ d ∈ ct.deks, d.size = S.aead.nonceSize + S.aead.keySize + S.aead.tagSize) ∧
      ct.envelope.size = payload.size + (S.aead.nonceSize + S.aead.tagSize) := by
  obtain ⟨pairs, hm, hd, hc⟩ := S.encapsulateP_spec rand keys payload derivedKeys ct h
  subst hd; subst hc
  obtain ⟨hlenZ, _⟩ := CryptWalker.MKEM.Adapter.mapM_getElem _ (keys.zip rand.kemSeeds) pairs hm
  have hlenP : pairs.length = keys.length := by
    rw [hlenZ, List.length_zip, hlen]; omega
  refine ⟨by simp [hlenP], ?_, by simp [hlenP], ?_, ?_⟩
  · simp [List.length_zip, hlenP, hlen']
  · intro d hd
    obtain ⟨p, _, rfl⟩ := List.mem_map.mp hd
    rw [S.size_sealUnder]
    simp only [CryptWalker.Util.Bytes.size_ofVector]
    omega
  · simp only []
    rw [S.size_sealUnder]
    omega

/-- **A recipient recovers the payload, and the derived key the sender used for it**, from the
ciphertext carrying only its own KEM ciphertext and DEK. Needs `Reliable` on the KEM seed drawn for
this recipient — a general `KEM`'s decapsulation is not unconditionally correct. -/
theorem decapsulateP_forRecipient (rand : Rand S) (hrel : S.RandReliable rand)
    (keys : List S.kem.PublicKey) (payload : ByteArray)
    (hlen : rand.kemSeeds.length = keys.length) (hlen' : rand.dekNonces.length = keys.length)
    (derivedKeys : List ByteArray) (ct : Ciphertext S.kem.Ciphertext)
    (henc : S.encapsulateP rand keys payload = some (derivedKeys, ct))
    (i : Nat) (hi : i < keys.length) (sk : S.kem.PrivateKey)
    (hsk : keys[i] = S.kem.derivePublicKey sk) (k : ByteArray) (hk : derivedKeys[i]? = some k) :
    S.decapsulateP sk (ct.forRecipient i) = some (k, payload) := by
  obtain ⟨pairs, hm, hd, hc⟩ := S.encapsulateP_spec rand keys payload derivedKeys ct henc
  subst hd; subst hc
  obtain ⟨hlenZ, hget⟩ := CryptWalker.MKEM.Adapter.mapM_getElem _ (keys.zip rand.kemSeeds) pairs hm
  have hzip : (keys.zip rand.kemSeeds).length = keys.length := by
    rw [List.length_zip, hlen]; omega
  have hi' : i < (keys.zip rand.kemSeeds).length := by rw [hzip]; exact hi
  have hikem : i < rand.kemSeeds.length := by rw [hlen]; exact hi
  have hpair := hget i hi'
  have hzipget : (keys.zip rand.kemSeeds)[i]'hi' = (keys[i], (rand.kemSeeds[i]'hikem)) := by simp
  rw [hzipget, hsk] at hpair
  unfold encapPair at hpair
  have hlenP : pairs.length = keys.length := by rw [hlenZ, hzip]
  have hip : i < pairs.length := hlenP ▸ hi
  cases hcp : S.kem.encap (S.kem.derivePublicKey sk) (S.kem.stateFromSeed (rand.kemSeeds[i]'hikem))
      with
  | error e s' => rw [hcp] at hpair; cases hpair
  | ok r s' =>
    rw [hcp] at hpair
    injection hpair with hpair
    have hpi : pairs[i]'hip = r := hpair.symm
    have hrelI : S.kem.Reliable (S.kem.stateFromSeed (rand.kemSeeds[i]'hikem)) :=
      hrel _ (List.getElem_mem hikem)
    obtain ⟨t', ht'⟩ := S.kem.honestRoundTrip sk _ hrelI r.1 r.2 s' hcp default
    have hderiv : (pairs.map (fun p => S.deriveKeyBytes p.2))[i]? = some (S.deriveKeyBytes r.2) := by
      simp [List.getElem?_map, List.getElem?_eq_getElem hip, hpi]
    rw [hderiv] at hk
    injection hk with hk
    subst hk
    have hdek : (((pairs.map (fun p => S.deriveKeyAead p.2)).zip rand.dekNonces).map
          (fun p => S.sealUnder p.1 p.2 (ofVector rand.msgKey)))[i]?
        = some (S.sealUnder (S.deriveKeyAead r.2) (rand.dekNonces[i]'(hlen' ▸ hi))
            (ofVector rand.msgKey)) := by
      have hlm : (pairs.map (fun p => S.deriveKeyAead p.2)).length = keys.length := by
        simp [hlenP]
      have hz2 : ((pairs.map (fun p => S.deriveKeyAead p.2)).zip rand.dekNonces).length
          = keys.length := by rw [List.length_zip, hlm, hlen']; omega
      have hi2 : i < ((pairs.map (fun p => S.deriveKeyAead p.2)).zip rand.dekNonces).length := by
        rw [hz2]; exact hi
      rw [List.getElem?_map, List.getElem?_eq_getElem hi2]
      congr 2
      simp [List.getElem_zip, List.getElem_map, hpi]
    have hkc : (pairs.map Prod.fst)[i]? = some r.1 := by
      simp [List.getElem?_map, List.getElem?_eq_getElem hip, hpi]
    unfold decapsulateP Ciphertext.forRecipient
    simp only [hkc, hdek, Option.toList_some, List.head?_cons]
    rw [ht']
    dsimp only
    rw [S.unsealUnder_sealUnder]
    have hkey : S.keyOfBytes (ofVector rand.msgKey) = some (S.aead.keyFromBytes rand.msgKey) := by
      unfold keyOfBytes
      rw [if_pos (by simp), CryptWalker.Util.Bytes.toVecN_ofVector]
    simp only [hkey, S.unsealUnder_sealUnder]

/-! ### Replies -/

def envelopeReplyP (key : ByteArray) (nonce : Vector UInt8 S.aead.nonceSize) (pt : ByteArray) :
    Option ByteArray := do
  let k ← S.keyOfBytes key
  pure (S.sealUnder k nonce pt)

def decryptEnvelopeP (key : ByteArray) (envelope : ByteArray) : Option ByteArray := do
  let k ← S.keyOfBytes key
  S.unsealUnder k envelope

theorem decryptEnvelopeP_envelopeReplyP (key : ByteArray) (nonce : Vector UInt8 S.aead.nonceSize)
    (pt env : ByteArray) (h : S.envelopeReplyP key nonce pt = some env) :
    S.decryptEnvelopeP key env = some pt := by
  unfold envelopeReplyP at h
  unfold decryptEnvelopeP
  cases hk : S.keyOfBytes key with
  | none => rw [hk] at h; simp at h
  | some k =>
    rw [hk] at h
    simp at h
    subst h
    simp [S.unsealUnder_sealUnder]

end Base

/-! ### The `MultiRecipientHybrid` instance: randomness from a seed stream, errors as `Except` -/

section Instance

variable (S : Base)

/-- The randomness for one encapsulation to `n` recipients, drawn from the stream at position `i`:
message key, envelope nonce, then one DEK nonce and one KEM seed per recipient. -/
def randOf (i : Nat) (str : Nat → Bytes32) (n : Nat) : Rand S where
  msgKey := toVecN _ (ofVector (str i))
  envNonce := toVecN _ (ofVector (str (i + 1)))
  dekNonces := (List.range n).map fun j => toVecN _ (ofVector (str (i + 2 + j)))
  kemSeeds := (List.range n).map fun j => str (i + 2 + n + j)

theorem randOf_dekNonces_length (i : Nat) (str : Nat → Bytes32) (n : Nat) :
    (randOf S i str n).dekNonces.length = n := by simp [randOf]

theorem randOf_kemSeeds_length (i : Nat) (str : Nat → Bytes32) (n : Nat) :
    (randOf S i str n).kemSeeds.length = n := by simp [randOf]

/-- Every draw a future call from this stream position could make is `Reliable` — quantified over
every position, since the state doesn't know in advance how many recipients that call will have. -/
def Reliable (s : St) : Prop := ∀ j : Nat, S.kem.Reliable (S.kem.stateFromSeed (s.2 j))

theorem Reliable_randReliable (s : St) (h : Reliable S s) (n : Nat) :
    S.RandReliable (randOf S s.1 s.2 n) := by
  intro seed hseed
  simp only [randOf, List.mem_map, List.mem_range] at hseed
  obtain ⟨j, _, rfl⟩ := hseed
  exact h _

def encapM (keys : List S.kem.PublicKey) (payload : ByteArray) :
    EStateM MultiRecipientHybridError St (List ByteArray × Ciphertext S.kem.Ciphertext) :=
  fun (i, str) =>
    match S.encapsulateP (randOf S i str keys.length) keys payload with
    | some r => EStateM.Result.ok r (i + 2 + 2 * keys.length, str)
    | none => EStateM.Result.error .invalidKeySize (i + 2 + 2 * keys.length, str)

theorem encapM_ok (keys : List S.kem.PublicKey) (payload : ByteArray) (s : St) (r) (s' : St)
    (h : encapM S keys payload s = .ok r s') :
    ∃ rand : Rand S, rand.kemSeeds.length = keys.length ∧ rand.dekNonces.length = keys.length ∧
      (Reliable S s → S.RandReliable rand) ∧ S.encapsulateP rand keys payload = some r := by
  obtain ⟨i, str⟩ := s
  simp only [encapM] at h
  split at h
  · rename_i r' hr'
    injection h with h1 _
    subst h1
    exact ⟨_, randOf_kemSeeds_length S i str keys.length,
      randOf_dekNonces_length S i str keys.length,
      fun hrel => Reliable_randReliable S (i, str) hrel keys.length, hr'⟩
  · cases h

def decapE (sk : S.kem.PrivateKey) (ct : Ciphertext S.kem.Ciphertext) :
    Except MultiRecipientHybridError (ByteArray × ByteArray) :=
  match S.decapsulateP sk ct with
  | some r => .ok r
  | none => .error .trialDecryptFailed

def replyM (key : ByteArray) (pt : ByteArray) : EStateM MultiRecipientHybridError St ByteArray :=
  fun (i, str) =>
    match S.envelopeReplyP key (toVecN _ (ofVector (str i))) pt with
    | some env => EStateM.Result.ok env (i + 1, str)
    | none => EStateM.Result.error .invalidKeySize (i + 1, str)

def decryptE (key : ByteArray) (env : ByteArray) : Except MultiRecipientHybridError ByteArray :=
  match S.decryptEnvelopeP key env with
  | some pt => .ok pt
  | none => .error .trialDecryptFailed

def generateM : EStateM MultiRecipientHybridError St (S.kem.PublicKey × S.kem.PrivateKey) :=
  fun (i, str) =>
    match S.kem.generate (S.kem.stateFromSeed (str i)) with
    | .ok ⟨pk, sk, _⟩ _ => EStateM.Result.ok (pk, sk) (i + 1, str)
    | .error _ _ => EStateM.Result.error .invalidKeySize (i + 1, str)

/-- **`MultiRecipientHybrid` over the given `KEM`, `AEAD` and hash.** Every law is discharged, so
nothing is assumed beyond the laws of the three primitives (plus, for `decapsulate_encapsulate`,
the underlying `KEM`'s own `Reliable`). -/
def ofBase : MultiRecipientHybrid where
  PrivateKey := S.kem.PrivateKey
  PublicKey := S.kem.PublicKey
  KEMCiphertext := S.kem.Ciphertext
  ctI := S.kem.ctI
  State := St
  stateI := ⟨(0, fun _ => Vector.replicate 32 0)⟩
  name := "MultiRecipientHybrid-" ++ S.aead.name
  publicKeySize := S.kem.publicKeySize
  kemCiphertextSize := S.kem.ciphertextSize
  dekSize := S.aead.nonceSize + S.aead.keySize + S.aead.tagSize
  envelopeOverhead := S.aead.nonceSize + S.aead.tagSize
  derivePublicKey := S.kem.derivePublicKey
  encodePublicKey := S.kem.encodePublicKey
  decodePublicKey := S.kem.decodePublicKey
  stateFromSeed := fun seed =>
    (0, fun i => toVecN 32 (ofVector (S.hash.hash (ofVector seed ++
      CryptWalker.MKEM.Adapter.counterBytes i))))
  Reliable := Reliable S
  generate := generateM S
  encapsulate := encapM S
  decapsulate := decapE S
  envelopeReply := replyM S
  decryptEnvelope := decryptE S
  decode_encode_pub := S.kem.decode_encode_pub
  encapsulate_shape := by
    intro keys payload s derivedKeys ct s' h
    obtain ⟨rand, hlen, hlen', _, hp⟩ := encapM_ok S keys payload s _ s' h
    exact S.encapsulateP_shape rand keys payload hlen hlen' derivedKeys ct hp
  decapsulate_encapsulate := by
    intro keys payload s hrel derivedKeys ct s' h i hi sk k hsk hk
    obtain ⟨rand, hlen, hlen', hRandRel, hp⟩ := encapM_ok S keys payload s _ s' h
    have := S.decapsulateP_forRecipient rand (hRandRel hrel) keys payload hlen hlen' derivedKeys ct
      hp i hi sk hsk k hk
    simp [decapE, this]
  decryptEnvelope_envelopeReply := by
    rintro key pt ⟨i, str⟩ env s' h
    simp only [replyM] at h
    cases hr : S.envelopeReplyP key (toVecN _ (ofVector (str i))) pt with
    | none => rw [hr] at h; cases h
    | some env' =>
      rw [hr] at h
      injection h with h1 _
      subst h1
      simp only [decryptE]
      rw [S.decryptEnvelopeP_envelopeReplyP key _ pt env' hr]

end Instance

/-- `hybridOfKEM kem aead hash h`: `MultiRecipientHybrid` over any `KEM`, `AEAD` and hash whose
digest is an AEAD key. -/
def hybridOfKEM (kem : KEM) (aead : AEAD) (hash : Hash) (h : hash.digestSize = aead.keySize) :
    MultiRecipientHybrid :=
  ofBase ⟨kem, aead, hash, h⟩

end CryptWalker.MultiRecipientHybrid.Adapter

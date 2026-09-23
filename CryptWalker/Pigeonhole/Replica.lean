/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Tactic.SplitIfs
import CryptWalker.Sign.Sign

/-! # A Pigeonhole replica

A replica stores *boxes*: for each box ID, an encrypted payload and a signature. The box ID is a
public key, and the signature is over the payload under that key, so anyone can check a box is
genuine without knowing who wrote it. This file models the replica's request handling exactly as
`katzenpost/replica/handlers.go` does it, as a pure state machine `step : Store → Request →
Store × Reply`, and proves what the handlers guarantee.

* **Write** (non-empty payload): the payload must be exactly `boxSize` bytes, the signature must
  verify under the box ID, and the box must not already exist. Otherwise an error code, and the
  store is untouched. A second write to an existing box is `boxAlreadyExists`, not an overwrite.
* **Tombstone** (empty payload): the signature must verify over the empty payload; the box is then
  replaced by a tombstone, which is how a writer deletes a message.
* **Read**: not found, or the stored payload and signature, with a distinct code for a tombstone.

The replica never trusts the sender: `step_valid` shows that whatever requests arrive, in whatever
order, every stored box verifies under its own ID.

Not modelled: storage-full and database failures, box-ID unmarshalling, read repair between
replicas, and epochs. -/

namespace CryptWalker.Pigeonhole.Replica

open CryptWalker.Sign.Sign (Signature)

variable (Sg : Signature) [DecidableEq Sg.PublicKey]

/-- What is kept under a box ID: the encrypted payload and its signature. An empty payload is a
tombstone. -/
structure Entry where
  payload : ByteArray
  sig : Sg.Sig

/-- The replica's storage. -/
abbrev Store := Sg.PublicKey → Option (Entry Sg)

variable {Sg}

def Store.empty : Store Sg := fun _ => none

def Store.put (s : Store Sg) (id : Sg.PublicKey) (e : Entry Sg) : Store Sg :=
  fun x => if x = id then some e else s x

@[simp] theorem Store.put_same (s : Store Sg) (id : Sg.PublicKey) (e : Entry Sg) :
    s.put id e id = some e := by simp [Store.put]

theorem Store.put_other (s : Store Sg) {id x : Sg.PublicKey} (e : Entry Sg) (h : x ≠ id) :
    s.put id e x = s x := by simp [Store.put, h]

variable (Sg)

/-- A request as the replica receives it, after MKEM decryption. -/
inductive Request
  | write (id : Sg.PublicKey) (payload : ByteArray) (sig : Sg.Sig)
  | read (id : Sg.PublicKey)

/-- The result codes the handlers return (the ones this model reaches). -/
inductive Code
  | success | invalidPayload | invalidSignature | boxAlreadyExists | boxIDNotFound | tombstone
  deriving DecidableEq

inductive Reply
  | writeReply (code : Code)
  | readReply (code : Code) (entry : Option (Entry Sg))

variable {Sg}

/-- One request. `boxSize` is the exact ciphertext length a box must have. -/
def step (boxSize : Nat) (s : Store Sg) : Request Sg → Store Sg × Reply Sg
  | .write id payload sig =>
    if payload.size = 0 then
      if Sg.verify id ByteArray.empty sig then
        (s.put id ⟨ByteArray.empty, sig⟩, .writeReply .success)
      else (s, .writeReply .invalidSignature)
    else if payload.size ≠ boxSize then (s, .writeReply .invalidPayload)
    else if Sg.verify id payload sig = false then (s, .writeReply .invalidSignature)
    else
      match s id with
      | some _ => (s, .writeReply .boxAlreadyExists)
      | none => (s.put id ⟨payload, sig⟩, .writeReply .success)
  | .read id =>
    match s id with
    | none => (s, .readReply .boxIDNotFound none)
    | some e =>
      (s, .readReply (if e.payload.size = 0 then .tombstone else .success) (some e))

/-- Every stored box verifies under its own ID. -/
def Valid (s : Store Sg) : Prop :=
  ∀ id e, s id = some e → Sg.verify id e.payload e.sig = true

omit [DecidableEq Sg.PublicKey] in
theorem valid_empty : Valid (Store.empty : Store Sg) := by
  intro id e h; simp [Store.empty] at h

theorem valid_put {s : Store Sg} (hs : Valid s) (id : Sg.PublicKey) (e : Entry Sg)
    (h : Sg.verify id e.payload e.sig = true) : Valid (s.put id e) := by
  intro x e' hx
  by_cases hxid : x = id
  · subst hxid
    rw [Store.put_same] at hx
    cases hx
    exact h
  · rw [Store.put_other _ _ hxid] at hx
    exact hs x e' hx

/-- **The replica cannot be made to store a bad box.** Whatever request arrives, valid stores stay
valid. -/
theorem step_valid (boxSize : Nat) (s : Store Sg) (hs : Valid s) (r : Request Sg) :
    Valid (step boxSize s r).1 := by
  cases r with
  | read id =>
    simp only [step]
    cases s id <;> simpa
  | write id payload sig =>
    simp only [step]
    split_ifs with h0 hv hsz hbad
    · exact valid_put hs id ⟨ByteArray.empty, sig⟩ hv
    · exact hs
    · exact hs
    · exact hs
    · cases hsid : s id with
      | some e => simpa using hs
      | none => exact valid_put hs id ⟨payload, sig⟩ (by simpa using hbad)

/-- Run a list of requests in order. -/
def run (boxSize : Nat) : Store Sg → List (Request Sg) → Store Sg
  | s, [] => s
  | s, r :: rs => run boxSize (step boxSize s r).1 rs

theorem run_valid (boxSize : Nat) (rs : List (Request Sg)) :
    ∀ s : Store Sg, Valid s → Valid (run boxSize s rs) := by
  induction rs with
  | nil => intro s hs; exact hs
  | cons r rs ih => intro s hs; exact ih _ (step_valid boxSize s hs r)

/-- A write is accepted only if its signature verifies under the box ID (over the empty payload,
for a tombstone). -/
theorem write_success_verifies (boxSize : Nat) (s : Store Sg) (id : Sg.PublicKey)
    (payload : ByteArray) (sig : Sg.Sig)
    (h : (step boxSize s (.write id payload sig)).2 = .writeReply .success) :
    Sg.verify id (if payload.size = 0 then ByteArray.empty else payload) sig = true := by
  simp only [step] at h
  split_ifs at h with h0 hv hsz hbad
  · simpa [h0] using hv
  · simp at h
  · simp at h
  · simp at h
  · simp [h0]; simpa using hbad

/-- A write either leaves the store alone, or stores exactly the request under its own box ID, and
in that case the signature verified. -/
theorem step_write_cases (boxSize : Nat) (s : Store Sg) (id : Sg.PublicKey) (payload : ByteArray)
    (sig : Sg.Sig) :
    (step boxSize s (.write id payload sig)).1 = s ∨
      ∃ e, (step boxSize s (.write id payload sig)).1 = s.put id e ∧
        Sg.verify id (if payload.size = 0 then ByteArray.empty else payload) sig = true := by
  simp only [step]
  split_ifs with h0 hv hsz hbad
  · right; exact ⟨_, rfl, by simpa [h0] using hv⟩
  · left; rfl
  · left; rfl
  · left; rfl
  · cases hsid : s id with
    | some e => left; simp
    | none => right; exact ⟨_, rfl, by simpa [h0] using hbad⟩

/-- A well-formed, correctly signed write to a free box is accepted and stores the box. -/
theorem write_fresh (boxSize : Nat) (s : Store Sg) (id : Sg.PublicKey) (payload : ByteArray)
    (sig : Sg.Sig) (hne : payload.size ≠ 0) (hsz : payload.size = boxSize)
    (hv : Sg.verify id payload sig = true) (hfree : s id = none) :
    step boxSize s (.write id payload sig)
      = (s.put id ⟨payload, sig⟩, .writeReply .success) := by
  have hbad : ¬ (Sg.verify id payload sig = false) := by simp [hv]
  simp only [step]
  rw [if_neg hne, if_neg (fun h => h hsz), if_neg hbad]
  simp [hfree]

/-- **A box is written once.** A second correctly signed write to an existing box is refused and
changes nothing; only a tombstone can remove a message. -/
theorem write_existing (boxSize : Nat) (s : Store Sg) (id : Sg.PublicKey) (payload : ByteArray)
    (sig : Sg.Sig) (hne : payload.size ≠ 0) (hsz : payload.size = boxSize)
    (hv : Sg.verify id payload sig = true) (e : Entry Sg) (hex : s id = some e) :
    step boxSize s (.write id payload sig) = (s, .writeReply .boxAlreadyExists) := by
  have hbad : ¬ (Sg.verify id payload sig = false) := by simp [hv]
  simp only [step]
  rw [if_neg hne, if_neg (fun h => h hsz), if_neg hbad]
  simp [hex]

/-- A read leaves the store alone, and reports what is under the box ID. -/
theorem step_read_put (boxSize : Nat) (s : Store Sg) (id : Sg.PublicKey) (e : Entry Sg) :
    step boxSize (s.put id e) (.read id)
      = (s.put id e, .readReply (if e.payload.size = 0 then .tombstone else .success) (some e)) := by
  simp [step]

/-- Reading a box just written returns exactly what was written. -/
theorem read_after_write (boxSize : Nat) (s : Store Sg) (id : Sg.PublicKey) (payload : ByteArray)
    (sig : Sg.Sig) (hne : payload.size ≠ 0) :
    (step boxSize (s.put id ⟨payload, sig⟩) (.read id)).2
      = .readReply .success (some ⟨payload, sig⟩) := by
  simp [step, hne]

/-- A correctly signed tombstone replaces the box, and a read then reports a tombstone. -/
theorem tombstone_then_read (boxSize : Nat) (s : Store Sg) (id : Sg.PublicKey) (sig : Sg.Sig)
    (hv : Sg.verify id ByteArray.empty sig = true) :
    step boxSize s (.write id ByteArray.empty sig)
        = (s.put id ⟨ByteArray.empty, sig⟩, .writeReply .success) ∧
      (step boxSize (s.put id ⟨ByteArray.empty, sig⟩) (.read id)).2
        = .readReply .tombstone (some ⟨ByteArray.empty, sig⟩) := by
  constructor
  · simp [step, hv]
  · simp [step]

/-- **Only a signed write changes a box.** If a request changes what is stored under `x`, it was a
write to `x` whose signature verifies under `x` (over the empty payload for a tombstone). -/
theorem step_frame (boxSize : Nat) (s : Store Sg) (r : Request Sg) (x : Sg.PublicKey)
    (h : (step boxSize s r).1 x ≠ s x) :
    ∃ payload sig, r = .write x payload sig ∧
      Sg.verify x (if payload.size = 0 then ByteArray.empty else payload) sig = true := by
  cases r with
  | read id =>
    exfalso; apply h
    simp only [step]
    cases s id <;> rfl
  | write id payload sig =>
    rcases step_write_cases boxSize s id payload sig with hs | ⟨e, hs, hv⟩
    · exfalso; exact h (by rw [hs])
    · by_cases hxid : x = id
      · subst hxid; exact ⟨payload, sig, rfl, hv⟩
      · exfalso; apply h; rw [hs, Store.put_other _ _ hxid]

end CryptWalker.Pigeonhole.Replica

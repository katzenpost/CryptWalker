/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.BACAP.API

/-! # BACAP positions: a capability bound to one box on its stream

The Lean counterpart of `hpqc/bacap/position.go` and `hpqc/py/hpqc/bacap/positions.py`.

A box ID is derived from a cap's root key *and* an index's blinding factor, so a cap paired
with an index from another stream addresses a box nobody writes to, and nothing reports it.
Go and Python close that gap at run time: `Contains` walks the ratchet from the cap's index to
the one given, and the position types can only be built through it. Here a position carries a
proof instead: `Reaches cap.messageBoxIndex index`.

* `ReadCap.contains` / `WriteCap.contains` check an index is on the cap's stream, within the
  same walk bound as Go and Python (`maxContainsWalk`). `contains_ok_iff` says exactly which
  indices pass.
* `ReadPosition` / `WritePosition` with `start`, `positionAt`, `next`, `advanceTo`, `boxID`,
  `open`, `encrypt` and `tombstone`. `next_index` and `advanceTo_index` show they move exactly
  as `nextIndex` and `advanceIndexTo` do.
* `MessageBoxIndex.openForContext` checks the box is the one the cap and index derive before
  decrypting (`openForContext_box`). That check is what rejects a tombstone signed for another
  box, since a tombstone has no ciphertext to authenticate (`openForContext_tombstone`). -/

namespace CryptWalker.BACAP.Types

open CryptWalker.BACAP.Ratchet
open CryptWalker.BACAP.Impl
open CryptWalker.Hash.HKDF
open CryptWalker.Sign.Ed25519Blinded

deriving instance DecidableEq for MessageBoxIndex

/-! ## The ratchet as an iterate -/

/-- One ratchet step under BLAKE2b-512. -/
def ratchet (m : MessageBoxIndex) : MessageBoxIndex := advanceOne m blake2b512_hkdf

theorem ratchet_idx64_toNat (m : MessageBoxIndex) (h : m.idx64.toNat + 1 < 2 ^ 64) :
    (ratchet m).idx64.toNat = m.idx64.toNat + 1 := by
  rw [ratchet, advanceOne_increments_idx64, UInt64.toNat_add, UInt64.toNat_one]
  exact Nat.mod_eq_of_lt h

theorem iterate_idx64_toNat : ∀ (k : Nat) (m : MessageBoxIndex), m.idx64.toNat + k < 2 ^ 64 →
    (ratchet^[k] m).idx64.toNat = m.idx64.toNat + k
  | 0, _, _ => rfl
  | k + 1, m, h => by
    rw [Function.iterate_succ_apply,
      iterate_idx64_toNat k _ (by rw [ratchet_idx64_toNat m (by omega)]; omega),
      ratchet_idx64_toNat m (by omega)]
    omega

private theorem go_eq_iterate (target : UInt64) : ∀ (k : Nat) (cur : MessageBoxIndex),
    cur.idx64.toNat + k = target.toNat →
    advanceTo.go blake2b512_hkdf target k cur = ratchet^[k] cur
  | 0, _, _ => rfl
  | k + 1, cur, h => by
    have hlt : cur.idx64 < target := by rw [UInt64.lt_iff_toNat_lt]; omega
    have hb := target.toNat_lt
    rw [advanceTo.go, if_pos hlt, Function.iterate_succ_apply]
    exact go_eq_iterate target k (ratchet cur)
      (by show (ratchet cur).idx64.toNat + k = _; rw [ratchet_idx64_toNat cur (by omega)]; omega)

/-- `advanceIndexTo` is the ratchet iterated up to the target, or `none` going backwards. -/
theorem advanceIndexTo_eq (m : MessageBoxIndex) (target : UInt64) :
    m.advanceIndexTo target =
      if target < m.idx64 then none
      else some (ratchet^[target.toNat - m.idx64.toNat] m) := by
  unfold MessageBoxIndex.advanceIndexTo advanceTo
  split
  · rfl
  · rename_i h
    rw [UInt64.lt_iff_toNat_lt] at h
    have : (target - m.idx64).toNat = target.toNat - m.idx64.toNat := by
      rw [UInt64.toNat_sub_of_le]
      rw [UInt64.le_iff_toNat_le]
      omega
    simp only [this]
    rw [go_eq_iterate target _ m (by omega)]

/-! ## Streams -/

/-- `idx` is `k` ratchet steps on from `start`, for some `k` that does not overflow `idx64`. -/
def Reaches (start idx : MessageBoxIndex) : Prop :=
  ∃ k, start.idx64.toNat + k < 2 ^ 64 ∧ ratchet^[k] start = idx

theorem Reaches.refl (m : MessageBoxIndex) : Reaches m m := ⟨0, m.idx64.toNat_lt, rfl⟩

theorem Reaches.idx64 {start idx : MessageBoxIndex} (h : Reaches start idx) :
    ∃ k, idx.idx64.toNat = start.idx64.toNat + k ∧ ratchet^[k] start = idx := by
  obtain ⟨k, hk, rfl⟩ := h
  exact ⟨k, iterate_idx64_toNat k start hk, rfl⟩

theorem Reaches.iterate {start idx : MessageBoxIndex} (h : Reaches start idx) (j : Nat)
    (hj : idx.idx64.toNat + j < 2 ^ 64) : Reaches start (ratchet^[j] idx) := by
  obtain ⟨k, hk, rfl⟩ := h
  rw [iterate_idx64_toNat k start hk] at hj
  exact ⟨j + k, by omega, by rw [Function.iterate_add_apply]⟩

/-- The furthest `contains` walks, as in Go (`maxContainsWalk`) and Python
    (`MAX_CONTAINS_WALK`): 2^18 steps, about a second. -/
def maxContainsWalk : Nat := 2 ^ 18

/-- Why a BACAP operation refused its input. Go and Python use these errors' namesakes;
    `openFailed` covers both a bad signature and an AEAD failure, which
    `decryptForContext` does not tell apart. -/
inductive BACAPError where
  | indexNotInChannel
  | indexTooFar
  | emptyBox
  | boxMismatch
  | openFailed
  deriving DecidableEq, Repr

/-- `idx` with a proof it is on the stream from `start`, or why not. -/
def checkReaches (start idx : MessageBoxIndex) : Except BACAPError (PLift (Reaches start idx)) :=
  if idx.idx64 < start.idx64 then .error .indexNotInChannel
  else if maxContainsWalk < idx.idx64.toNat - start.idx64.toNat then .error .indexTooFar
  else if h : start.advanceIndexTo idx.idx64 = some idx then
    .ok ⟨by
      rw [advanceIndexTo_eq] at h
      split at h
      · cases h
      · rename_i hlt
        rw [UInt64.lt_iff_toNat_lt] at hlt
        exact ⟨_, by have := idx.idx64.toNat_lt; omega, Option.some.inj h⟩⟩
  else .error .indexNotInChannel

/-- `checkReaches` accepts exactly the indices a bounded number of ratchet steps on. -/
theorem checkReaches_ok_iff (start idx : MessageBoxIndex) :
    (∃ p, checkReaches start idx = .ok p) ↔
      ∃ k ≤ maxContainsWalk, start.idx64.toNat + k < 2 ^ 64 ∧ ratchet^[k] start = idx := by
  constructor
  · rintro ⟨p, hp⟩
    unfold checkReaches at hp
    split at hp
    · cases hp
    · rename_i hlt
      split at hp
      · cases hp
      · rename_i hfar
        obtain ⟨k, hk, hit⟩ := p.down.idx64
        exact ⟨k, by omega, by have := idx.idx64.toNat_lt; omega, hit⟩
  · rintro ⟨k, hle, hk, rfl⟩
    have hn := iterate_idx64_toNat k start hk
    have hlt : ¬ (ratchet^[k] start).idx64 < start.idx64 := by
      rw [UInt64.lt_iff_toNat_lt]; omega
    have hadv : start.advanceIndexTo (ratchet^[k] start).idx64 = some (ratchet^[k] start) := by
      rw [advanceIndexTo_eq, if_neg hlt, hn, Nat.add_sub_cancel_left]
    unfold checkReaches
    rw [if_neg hlt, if_neg (by omega), dif_pos hadv]
    exact ⟨_, rfl⟩

/-! ## Contains -/

/-- `.ok ()` if `idx` is on this cap's stream: its own index or one the ratchet reaches from it,
    within `maxContainsWalk` steps. Matches `ReadCap.Contains` in Go. -/
def ReadCap.contains (rc : ReadCap) (idx : MessageBoxIndex) : Except BACAPError Unit :=
  (checkReaches rc.messageBoxIndex idx).map fun _ => ()

/-- See `ReadCap.contains`; a write cap and its read cap share a stream. -/
def WriteCap.contains (wc : WriteCap) (idx : MessageBoxIndex) : Except BACAPError Unit :=
  wc.readCap.contains idx

/-- **`contains` is exact.** It accepts `idx` if and only if `idx` is the cap's own index ratcheted
    forward at most `maxContainsWalk` times. -/
theorem contains_ok_iff (rc : ReadCap) (idx : MessageBoxIndex) :
    rc.contains idx = .ok () ↔
      ∃ k ≤ maxContainsWalk, rc.messageBoxIndex.idx64.toNat + k < 2 ^ 64 ∧
        ratchet^[k] rc.messageBoxIndex = idx := by
  rw [← checkReaches_ok_iff, ReadCap.contains]
  cases checkReaches rc.messageBoxIndex idx <;> simp [Except.map]

/-- The same as `contains_ok_iff`, phrased with `advanceIndexTo`. -/
theorem contains_ok_iff_advanceIndexTo (rc : ReadCap) (idx : MessageBoxIndex) :
    rc.contains idx = .ok () ↔
      rc.messageBoxIndex.idx64 ≤ idx.idx64 ∧
        idx.idx64.toNat - rc.messageBoxIndex.idx64.toNat ≤ maxContainsWalk ∧
        rc.messageBoxIndex.advanceIndexTo idx.idx64 = some idx := by
  rw [contains_ok_iff]
  set start := rc.messageBoxIndex
  constructor
  · rintro ⟨k, hle, hk, rfl⟩
    have hn := iterate_idx64_toNat k start hk
    have hlt : ¬ (ratchet^[k] start).idx64 < start.idx64 := by
      rw [UInt64.lt_iff_toNat_lt]; omega
    refine ⟨by rw [UInt64.le_iff_toNat_le]; omega, by omega, ?_⟩
    rw [advanceIndexTo_eq, if_neg hlt, hn, Nat.add_sub_cancel_left]
  · rintro ⟨hle, hwalk, h⟩
    rw [advanceIndexTo_eq, if_neg (by rw [UInt64.lt_iff_toNat_lt, UInt64.le_iff_toNat_le] at *; omega)] at h
    rw [UInt64.le_iff_toNat_le] at hle
    exact ⟨_, hwalk, by have := idx.idx64.toNat_lt; omega, Option.some.inj h⟩

/-! ## Opening a box -/

/-- The all-zero box ID, which a reply carries when the box was empty. -/
def zeroBox : PubBytes := Vector.replicate 32 0

/-- Verify and decrypt the box at this index on `rc`'s stream, after checking the box is the one
    `rc` and this index derive under `ctx`. Matches `MessageBoxIndex.OpenForContext` in Go. -/
def MessageBoxIndex.openForContext (m : MessageBoxIndex) (rc : ReadCap) (ctx : ByteArray)
    (box : PubBytes) (ciphertext : ByteArray) (sig : SigBytes) : Except BACAPError ByteArray :=
  if box = zeroBox then .error .emptyBox
  else if box ≠ m.boxIDForContext rc ctx then .error .boxMismatch
  else match m.decryptForContext box ctx ciphertext sig with
    | some pt => .ok pt
    | none => .error .openFailed

/-- **`openForContext` checks the box.** It only returns a plaintext for the box the cap and
    index derive. -/
theorem openForContext_box {m : MessageBoxIndex} {rc : ReadCap} {ctx : ByteArray} {box : PubBytes}
    {ct : ByteArray} {sig : SigBytes} {pt : ByteArray}
    (h : m.openForContext rc ctx box ct sig = .ok pt) : box = m.boxIDForContext rc ctx := by
  unfold MessageBoxIndex.openForContext at h
  split at h
  · cases h
  · split at h
    · cases h
    · rename_i hne; exact not_not.mp hne

/-- An encrypted box opens to its plaintext at its own index, unless its box ID is all zeros. -/
theorem openForContext_encrypt (wc : WriteCap) (m : MessageBoxIndex) (ctx pt : ByteArray)
    (hz : (m.encryptForContext wc ctx pt).1 ≠ zeroBox) :
    m.openForContext wc.readCap ctx (m.encryptForContext wc ctx pt).1
      (m.encryptForContext wc ctx pt).2.1 (m.encryptForContext wc ctx pt).2.2 = .ok pt := by
  unfold MessageBoxIndex.openForContext
  have hbox : (m.encryptForContext wc ctx pt).1 = m.boxIDForContext wc.readCap ctx := by
    simp only [MessageBoxIndex.encryptForContext, implEncryptBox, MessageBoxIndex.boxIDForContext,
      WriteCap.readCap]
  rw [if_neg hz, if_neg (show ¬ (_ ≠ _) from not_not.mpr hbox), decrypt_encryptForContext]

/-- **Tombstones open as empty.** The signature `signBox` makes over the empty payload opens as
    the empty message at its own box, unless that box ID is all zeros. At any other index it is
    refused, by `openForContext_box`. -/
theorem openForContext_tombstone (wc : WriteCap) (m : MessageBoxIndex) (ctx : ByteArray)
    (hz : (m.signBox wc ctx ByteArray.empty).1 ≠ zeroBox) :
    m.openForContext wc.readCap ctx (m.signBox wc ctx ByteArray.empty).1 ByteArray.empty
      (m.signBox wc ctx ByteArray.empty).2 = .ok ByteArray.empty := by
  have hbox : (m.signBox wc ctx ByteArray.empty).1 = m.boxIDForContext wc.readCap ctx := by
    simp only [MessageBoxIndex.signBox, implSignBox, MessageBoxIndex.boxIDForContext,
      implDeriveBoxID, WriteCap.readCap, WriteCap.rootPublicKey]
  have hver : implVerifyBox (m.signBox wc ctx ByteArray.empty).1 ByteArray.empty
      (m.signBox wc ctx ByteArray.empty).2 = true := by
    simp only [MessageBoxIndex.signBox, implSignBox, implVerifyBox]
    rw [← blind_hom]
    exact verify_signNative _ _
  unfold MessageBoxIndex.openForContext
  rw [if_neg hz, if_neg (show ¬ (_ ≠ _) from not_not.mpr hbox)]
  simp only [MessageBoxIndex.decryptForContext, implDecryptBox, hver]
  rfl

/-! ## Positions -/

/-- A read cap and one box on its stream. -/
structure ReadPosition where
  cap : ReadCap
  index : MessageBoxIndex
  onStream : Reaches cap.messageBoxIndex index

/-- A write cap and one box on its stream. -/
structure WritePosition where
  cap : WriteCap
  index : MessageBoxIndex
  onStream : Reaches cap.messageBoxIndex index

/-- The position of the cap's own index. -/
def ReadCap.start (rc : ReadCap) : ReadPosition := ⟨rc, rc.messageBoxIndex, .refl _⟩

/-- The position of the cap's own index. -/
def WriteCap.start (wc : WriteCap) : WritePosition := ⟨wc, wc.messageBoxIndex, .refl _⟩

/-- The position of `idx`, after checking it is on this cap's stream. -/
def ReadCap.positionAt (rc : ReadCap) (idx : MessageBoxIndex) : Except BACAPError ReadPosition :=
  (checkReaches rc.messageBoxIndex idx).map fun h => ⟨rc, idx, h.down⟩

/-- The position of `idx`, after checking it is on this cap's stream. -/
def WriteCap.positionAt (wc : WriteCap) (idx : MessageBoxIndex) : Except BACAPError WritePosition :=
  (checkReaches wc.messageBoxIndex idx).map fun h => ⟨wc, idx, h.down⟩

private def stepNext (cap : MessageBoxIndex) (idx : MessageBoxIndex) (h : Reaches cap idx) :
    Option (Σ' i, Reaches cap i) :=
  if hn : idx.idx64.toNat + 1 < 2 ^ 64 then some ⟨ratchet idx, h.iterate 1 hn⟩ else none

private def stepTo (cap : MessageBoxIndex) (idx : MessageBoxIndex) (h : Reaches cap idx)
    (target : UInt64) : Option (Σ' i, Reaches cap i) :=
  if hlt : target < idx.idx64 then none
  else some ⟨ratchet^[target.toNat - idx.idx64.toNat] idx, h.iterate _ (by
    rw [UInt64.lt_iff_toNat_lt] at hlt; have := target.toNat_lt; omega)⟩

private theorem stepNext_index (cap idx : MessageBoxIndex) (h : Reaches cap idx) :
    (stepNext cap idx h).map (·.1) = idx.nextIndex := by
  unfold stepNext
  rw [MessageBoxIndex.nextIndex, CryptWalker.BACAP.Ratchet.nextIndex]
  change _ = idx.advanceIndexTo (idx.idx64 + 1)
  rw [advanceIndexTo_eq]
  split
  · rename_i hn
    have h1 : (idx.idx64 + 1).toNat = idx.idx64.toNat + 1 := by
      rw [UInt64.toNat_add, UInt64.toNat_one, Nat.mod_eq_of_lt hn]
    rw [if_neg (by rw [UInt64.lt_iff_toNat_lt]; omega), h1]
    simp
  · rename_i hn
    have hmax : idx.idx64.toNat = 2 ^ 64 - 1 := by have := idx.idx64.toNat_lt; omega
    rw [if_pos]
    · rfl
    · rw [UInt64.lt_iff_toNat_lt, UInt64.toNat_add, UInt64.toNat_one, hmax]
      decide

private theorem stepTo_index (cap idx : MessageBoxIndex) (h : Reaches cap idx) (target : UInt64) :
    (stepTo cap idx h target).map (·.1) = idx.advanceIndexTo target := by
  unfold stepTo
  rw [advanceIndexTo_eq]
  split <;> rfl

/-- The next box, or `none` at the end of the index space. -/
def ReadPosition.next (p : ReadPosition) : Option ReadPosition :=
  (stepNext _ p.index p.onStream).map fun s => ⟨p.cap, s.1, s.2⟩

/-- The box at `target`, or `none` if that is behind this one. -/
def ReadPosition.advanceTo (p : ReadPosition) (target : UInt64) : Option ReadPosition :=
  (stepTo _ p.index p.onStream target).map fun s => ⟨p.cap, s.1, s.2⟩

/-- The next box, or `none` at the end of the index space. -/
def WritePosition.next (p : WritePosition) : Option WritePosition :=
  (stepNext _ p.index p.onStream).map fun s => ⟨p.cap, s.1, s.2⟩

/-- The box at `target`, or `none` if that is behind this one. -/
def WritePosition.advanceTo (p : WritePosition) (target : UInt64) : Option WritePosition :=
  (stepTo _ p.index p.onStream target).map fun s => ⟨p.cap, s.1, s.2⟩

/-- `next` moves a position exactly as `nextIndex` moves its index. -/
theorem ReadPosition.next_index (p : ReadPosition) :
    p.next.map (·.index) = p.index.nextIndex := by
  rw [← stepNext_index _ _ p.onStream, ReadPosition.next, Option.map_map]; rfl

/-- `advanceTo` moves a position exactly as `advanceIndexTo` moves its index. -/
theorem ReadPosition.advanceTo_index (p : ReadPosition) (target : UInt64) :
    (p.advanceTo target).map (·.index) = p.index.advanceIndexTo target := by
  rw [← stepTo_index _ _ p.onStream, ReadPosition.advanceTo, Option.map_map]; rfl

theorem WritePosition.next_index (p : WritePosition) :
    p.next.map (·.index) = p.index.nextIndex := by
  rw [← stepNext_index _ _ p.onStream, WritePosition.next, Option.map_map]; rfl

theorem WritePosition.advanceTo_index (p : WritePosition) (target : UInt64) :
    (p.advanceTo target).map (·.index) = p.index.advanceIndexTo target := by
  rw [← stepTo_index _ _ p.onStream, WritePosition.advanceTo, Option.map_map]; rfl

/-- The read position of the same box. -/
def WritePosition.readPosition (p : WritePosition) : ReadPosition :=
  ⟨p.cap.readCap, p.index, p.onStream⟩

def ReadPosition.boxID (p : ReadPosition) (ctx : ByteArray) : PubBytes :=
  p.index.boxIDForContext p.cap ctx

def WritePosition.boxID (p : WritePosition) (ctx : ByteArray) : PubBytes :=
  p.index.boxIDForContext p.cap.readCap ctx

/-- Verify and decrypt the box at this position. See `MessageBoxIndex.openForContext`. -/
def ReadPosition.open (p : ReadPosition) (ctx : ByteArray) (box : PubBytes) (ciphertext : ByteArray)
    (sig : SigBytes) : Except BACAPError ByteArray :=
  p.index.openForContext p.cap ctx box ciphertext sig

/-- Encrypt and sign `plaintext` for this box: the box ID, ciphertext and signature. -/
def WritePosition.encrypt (p : WritePosition) (ctx plaintext : ByteArray) :
    PubBytes × ByteArray × SigBytes :=
  p.index.encryptForContext p.cap ctx plaintext

/-- Sign the empty payload for this box: the box ID and signature. Written with an empty payload,
    it deletes the box. -/
def WritePosition.tombstone (p : WritePosition) (ctx : ByteArray) : PubBytes × SigBytes :=
  p.index.signBox p.cap ctx ByteArray.empty

/-- A write position's tombstone opens as empty at its own read position. -/
theorem WritePosition.open_tombstone (p : WritePosition) (ctx : ByteArray)
    (hz : (p.tombstone ctx).1 ≠ zeroBox) :
    p.readPosition.open ctx (p.tombstone ctx).1 ByteArray.empty (p.tombstone ctx).2 =
      .ok ByteArray.empty :=
  openForContext_tombstone p.cap p.index ctx hz

/-- **Positions can't mismatch.** Every position addresses a box on its cap's stream. -/
theorem ReadPosition.reaches (p : ReadPosition) : Reaches p.cap.messageBoxIndex p.index :=
  p.onStream

theorem WritePosition.reaches (p : WritePosition) : Reaches p.cap.messageBoxIndex p.index :=
  p.onStream

/-! ## Serialization: the cap's bytes followed by the index's -/

def ReadPosition.toBytes (p : ReadPosition) : Vector UInt8 (ReadCapSize + MessageBoxIndexSize) :=
  marshalReadCap p.cap ++ marshalMessageBoxIndex p.index

def WritePosition.toBytes (p : WritePosition) : Vector UInt8 (WriteCapSize + MessageBoxIndexSize) :=
  marshalWriteCap p.cap ++ marshalMessageBoxIndex p.index

/-- Decode a position, checking its index is on its cap's stream. -/
def ReadPosition.ofBytes (data : Vector UInt8 (ReadCapSize + MessageBoxIndexSize)) :
    Option ReadPosition := do
  let rc ← unmarshalReadCap (Vector.ofFn fun i : Fin ReadCapSize => data[i.val]!)
  (rc.positionAt (unmarshalMessageBoxIndex
    (Vector.ofFn fun i : Fin MessageBoxIndexSize => data[i.val + ReadCapSize]!))).toOption

/-- Decode a position, checking its index is on its cap's stream. -/
def WritePosition.ofBytes (data : Vector UInt8 (WriteCapSize + MessageBoxIndexSize)) :
    Option WritePosition := do
  let wc ← unmarshalWriteCap (Vector.ofFn fun i : Fin WriteCapSize => data[i.val]!)
  (wc.positionAt (unmarshalMessageBoxIndex
    (Vector.ofFn fun i : Fin MessageBoxIndexSize => data[i.val + WriteCapSize]!))).toOption

end CryptWalker.BACAP.Types

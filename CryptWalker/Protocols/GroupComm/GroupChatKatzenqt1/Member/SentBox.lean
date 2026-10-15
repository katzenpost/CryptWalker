/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Protocols.GroupComm.Common.Dict
import CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member.Events

/-! # The boxes a member wrote to its own stream

What a member may still rewrite, and what retention lets it forget. See "Sent-box records" and
"Disappearing messages" in the group chat spec. -/

namespace CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member

open CryptWalker.Protocols.GroupComm.Common

structure Retention where
  /-- Epochs a Sent-box record is kept and backfilled; `none` keeps it for good. -/
  window : Option Nat := some 3
  /-- Drop plaintext every member still read has acknowledged. -/
  discardAcked : Bool := true
  /-- Epochs the policy keeps sent content. -/
  keepSent : Option Nat := none
  /-- Epochs the policy keeps received content. -/
  keepReceived : Option Nat := none
  deriving DecidableEq, Inhabited

structure Record where
  /-- The box's whole `MessageBoxIndex`. -/
  index : Index
  /-- `none` once the plaintext is gone, or if it was never handed over. -/
  plaintext : Option Payload
  control : Bool
  written : Nat
  /-- Written as a tombstone once every member acknowledged it. -/
  settled : Bool := false
  deriving DecidableEq, Inhabited

structure SentBox where
  /-- By the box's `Idx64`, which orders the boxes of the member's stream as it wrote them. -/
  records : Dict Nat Record := {}
  /-- The epoch last backfilled. -/
  backfilled : Option Nat := none
  deriving DecidableEq, Inhabited

namespace SentBox

def record (s : SentBox) (index : Index) (plaintext : Option Payload) (control : Bool) (epoch : Nat) :
    SentBox :=
  { s with records := s.records.set (counter index) ⟨index, plaintext, control, epoch, false⟩ }

/-- The Sent-box check: the `Idx64` of the box `index` names, or `none` if the member never wrote
it. -/
def check (s : SentBox) (index : Index) : Option Nat :=
  match s.records.get? (counter index) with
  | some r => if r.index = index then some (counter index) else none
  | none => none

/-- The Sent-box check for an acknowledgement, which names the box by its `Idx64`. -/
def checkAt (s : SentBox) (idx64 : Nat) : Bool := s.records.contains idx64

def retain (s : SentBox) (epoch : Nat) (policy : Retention) (everyoneAcked : Nat → Bool) : SentBox :=
  let records := s.records.filter fun _ r => match policy.window with
    | some window => epoch ≤ r.written + window
    | none => true
  let records := records.mapWithKey fun k r =>
    let expired := match policy.keepSent with
      | some keep => !r.control && r.written + keep ≤ epoch
      | none => false
    if expired || (policy.discardAcked && everyoneAcked k) then { r with plaintext := none } else r
  { s with records }

/-- Rewrite every record a member has yet to acknowledge, at most once per epoch, and write a
record every member has acknowledged as a tombstone once its plaintext is gone. Nothing when
nobody is behind. -/
def backfill (s : SentBox) (epoch : Nat) (everyoneAcked : Nat → Bool) : SentBox × List Effect :=
  if s.backfilled = some epoch then (s, [])
  else
    let ordered := s.records.pairs.mergeSort fun a b => a.1 ≤ b.1
    let effects := ordered.filterMap fun (k, r) =>
      if !everyoneAcked k then
        some (match r.plaintext with
          | some p => .writeBox r.index p
          | none => .writeTombstone r.index)
      else if r.plaintext.isNone && !r.settled then some (.writeTombstone r.index)
      else none
    let records := s.records.mapWithKey fun k r =>
      if everyoneAcked k && r.plaintext.isNone then { r with settled := true } else r
    ({ s with backfilled := some epoch, records }, effects)

end SentBox

end CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member

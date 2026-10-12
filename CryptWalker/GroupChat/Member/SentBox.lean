/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.GroupChat.Member.Dict
import CryptWalker.GroupChat.Member.Events

/-! # The boxes a member wrote to its own stream

See "Sent-box records" and "Disappearing messages" in the group chat spec, and katzenqt's
`groupchat/sentbox.py`: what a member may still rewrite, and what its retention policy lets it
forget. -/

namespace CryptWalker.GroupChat.Member

structure Retention where
  /-- Epochs a Sent-box record is kept and backfilled. -/
  window : Nat := 3
  /-- Drop plaintext every member still read has acknowledged. -/
  discardAcked : Bool := true
  /-- Epochs the policy keeps sent content. -/
  keepSent : Option Nat := none
  /-- Epochs the policy keeps received content. -/
  keepReceived : Option Nat := none
  deriving DecidableEq, Inhabited

structure Record where
  /-- Where the box falls in the order the member wrote its boxes. -/
  seq : Nat
  /-- `none` once the plaintext is gone, or if it was never handed over. -/
  plaintext : Option Message
  control : Bool
  written : Nat
  deriving DecidableEq, Inhabited

structure SentBox where
  records : Dict Index Record := {}
  count : Nat := 0
  /-- The epoch last backfilled. -/
  backfilled : Option Nat := none
  deriving DecidableEq, Inhabited

namespace SentBox

def record (s : SentBox) (index : Index) (plaintext : Option Message) (control : Bool) (epoch : Nat) :
    SentBox :=
  { s with records := s.records.set index ⟨s.count, plaintext, control, epoch⟩, count := s.count + 1 }

/-- The Sent-box check: where in the member's order the box `index` names falls, or `none` if it
never wrote it. -/
def check (s : SentBox) (index : Index) : Option Nat := (s.records.get? index).map (·.seq)

def retain (s : SentBox) (epoch : Nat) (policy : Retention) (everyoneAcked : Nat → Bool) : SentBox :=
  let records := s.records.filter fun _ r => epoch ≤ r.written + policy.window
  let records := records.mapValues fun r =>
    let expired := match policy.keepSent with
      | some keep => !r.control && r.written + keep ≤ epoch
      | none => false
    if expired || (policy.discardAcked && everyoneAcked r.seq) then { r with plaintext := none } else r
  { s with records }

/-- Rewrite every record, at most once per epoch. -/
def backfill (s : SentBox) (epoch : Nat) : SentBox × List Effect :=
  if s.backfilled = some epoch then (s, [])
  else
    let ordered := s.records.pairs.mergeSort fun a b => a.2.seq ≤ b.2.seq
    ({ s with backfilled := some epoch },
      ordered.map fun (i, r) => match r.plaintext with
        | some m => .writeBox i m
        | none => .writeTombstone i)

end SentBox

end CryptWalker.GroupChat.Member

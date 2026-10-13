/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.GroupChat.Member.Dict
import CryptWalker.GroupChat.Member.Wire

/-! # Acknowledgements

katzenqt's `groupchat/ledger.py`: what this member has published, what others have acknowledged of
its stream, and what others have acknowledged of every stream. An induction holds publishing
back. See "Joining" in the group chat spec. -/

namespace CryptWalker.GroupChat.Member

inductive Induction | idle | catchingUp | inducting
  deriving DecidableEq, Inhabited

structure Ledger where
  /-- The last index acknowledged of each stream. -/
  published : Dict Key Index := {}
  /-- The `Idx64` of the last box of our stream each member has acknowledged, after the Sent-box
  check. -/
  ackedBy : Dict Key Nat := {}
  /-- For each stream, the `Idx64` of the last box each other member acknowledged of it. -/
  heard : Dict Key (Dict Key Nat) := {}
  induction : Induction := .idle
  /-- The name and read cap of the member being inducted. -/
  invitee : Option (String × ByteArray) := none
  /-- Commit the induction as soon as catching up is done. -/
  commit : Bool := false
  /-- Where each stream had been read when the invitation began. -/
  starts : Dict Key Index := {}
  deriving DecidableEq, Inhabited

namespace Ledger

def holding (l : Ledger) : Bool := l.induction = .inducting

/-- The index to acknowledge of `stream`, the end of the unbroken run read, if anything new. -/
def owed (l : Ledger) (stream : Key) (run : Option Index) : Option Index :=
  match run with
  | none => none
  | some r => if l.holding || l.published.get? stream = some r then none else some r

def publish (l : Ledger) (stream : Key) (index : Index) : Ledger :=
  { l with published := l.published.set stream index }

def hear (l : Ledger) (stream : Key) (idx64 : Nat) (by_ : Key) : Ledger :=
  { l with heard := l.heard.set stream ((l.heard.getD stream {}).set by_ idx64) }

def acked (l : Ledger) (member : Key) (idx64 : Nat) : Ledger :=
  { l with ackedBy := l.ackedBy.set member (match l.ackedBy.get? member with
    | some s => max s idx64
    | none => idx64) }

def forget (l : Ledger) (member : Key) : Ledger :=
  { l with ackedBy := l.ackedBy.erase member
           heard := (l.heard.erase member).mapValues (·.erase member) }

end Ledger

end CryptWalker.GroupChat.Member

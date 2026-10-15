/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Protocols.GroupComm.Common.Persist
import CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member.Group

/-! # Keeping a member

A `Group` as CBOR, so that a client can stop and carry on where it was. This is the format of a
Lean client's own state, not katzenqt's. -/

namespace CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member.Persist

open Cborg
open CryptWalker.Protocols.GroupComm.Common.Persist
open CryptWalker.Protocols.GroupComm.Common.Persist.Persist

instance : Persist Mode where
  toTerm | .idle => enumTerm 0 | .reading => enumTerm 1 | .scanning => enumTerm 2
  ofTerm t := do
    match (← ofTerm t : Nat) with
    | 0 => some .idle | 1 => some .reading | 2 => some .scanning | _ => none

instance : Persist Induction where
  toTerm | .idle => enumTerm 0 | .catchingUp => enumTerm 1 | .inducting => enumTerm 2
  ofTerm t := do
    match (← ofTerm t : Nat) with
    | 0 => some .idle | 1 => some .catchingUp | 2 => some .inducting | _ => none

instance : Persist IntroRef where
  toTerm r := .TList #[toTerm r.introducer, toTerm r.index]
  ofTerm t := do let fs ← fieldsOf t 2; some ⟨← fieldAt fs 0, ← fieldAt fs 1⟩

instance : Persist Introduction where
  toTerm i := .TList #[toTerm i.name, toTerm i.readCap]
  ofTerm t := do let fs ← fieldsOf t 2; some ⟨← fieldAt fs 0, ← fieldAt fs 1⟩

instance : Persist Message where
  toTerm m := .TList #[toTerm m.content, toTerm m.introduction, toTerm m.numbers,
    toTerm m.introducedAt, toTerm m.acks]
  ofTerm t := do
    let fs ← fieldsOf t 5
    some ⟨← fieldAt fs 0, ← fieldAt fs 1, ← fieldAt fs 2, ← fieldAt fs 3, ← fieldAt fs 4⟩

instance : Persist Payload where
  toTerm
    | .message m => .TList #[enumTerm 0, toTerm m]
    | .bytes b => .TList #[enumTerm 1, toTerm b]
  ofTerm t := do
    let fs ← fieldsOf t 2
    match (← fieldAt fs 0 : Nat) with
    | 0 => some (.message (← fieldAt fs 1))
    | 1 => some (.bytes (← fieldAt fs 1))
    | _ => none

instance : Persist Entry where
  toTerm e := .TList #[toTerm e.key, toTerm e.prefix_]
  ofTerm t := do let fs ← fieldsOf t 2; some ⟨← fieldAt fs 0, ← fieldAt fs 1⟩

instance : Persist Rosters where
  toTerm r := .TList #[toTerm r.entries, toTerm r.started, toTerm r.introductions, toTerm r.keys]
  ofTerm t := do
    let fs ← fieldsOf t 4
    some ⟨← fieldAt fs 0, ← fieldAt fs 1, ← fieldAt fs 2, ← fieldAt fs 3⟩

instance : Persist Reader where
  toTerm r := .TList #[toTerm r.stream, toTerm r.readCap, toTerm r.next, toTerm r.last,
    toTerm r.passed, toTerm r.kept, toTerm r.lost, toTerm r.mode, toTerm r.tried]
  ofTerm t := do
    let fs ← fieldsOf t 9
    some ⟨← fieldAt fs 0, ← fieldAt fs 1, ← fieldAt fs 2, ← fieldAt fs 3, ← fieldAt fs 4,
      ← fieldAt fs 5, ← fieldAt fs 6, ← fieldAt fs 7, ← fieldAt fs 8⟩

instance : Persist Retention where
  toTerm r := .TList #[toTerm r.window, toTerm r.discardAcked, toTerm r.keepSent,
    toTerm r.keepReceived]
  ofTerm t := do
    let fs ← fieldsOf t 4
    some ⟨← fieldAt fs 0, ← fieldAt fs 1, ← fieldAt fs 2, ← fieldAt fs 3⟩

instance : Persist Record where
  toTerm r := .TList #[toTerm r.index, toTerm r.plaintext, toTerm r.control, toTerm r.written,
    toTerm r.settled]
  ofTerm t := do
    let fs ← fieldsOf t 5
    some ⟨← fieldAt fs 0, ← fieldAt fs 1, ← fieldAt fs 2, ← fieldAt fs 3, ← fieldAt fs 4⟩

instance : Persist SentBox where
  toTerm s := .TList #[toTerm s.records, toTerm s.backfilled]
  ofTerm t := do let fs ← fieldsOf t 2; some ⟨← fieldAt fs 0, ← fieldAt fs 1⟩

instance : Persist Ledger where
  toTerm l := .TList #[toTerm l.published, toTerm l.ackedBy, toTerm l.heard, toTerm l.induction,
    toTerm l.invitee, toTerm l.commit, toTerm l.starts]
  ofTerm t := do
    let fs ← fieldsOf t 7
    some ⟨← fieldAt fs 0, ← fieldAt fs 1, ← fieldAt fs 2, ← fieldAt fs 3, ← fieldAt fs 4,
      ← fieldAt fs 5, ← fieldAt fs 6⟩

instance : Persist Pending where
  toTerm p := .TList #[toTerm p.numbers, toTerm p.introduced, toTerm p.acks, toTerm p.control]
  ofTerm t := do
    let fs ← fieldsOf t 4
    some ⟨← fieldAt fs 0, ← fieldAt fs 1, ← fieldAt fs 2, ← fieldAt fs 3⟩

instance : Persist Group where
  toTerm g := .TList #[toTerm g.readCap, toTerm g.policy, toTerm g.recheck, toTerm g.rosters,
    toTerm g.readers, toTerm g.sent, toTerm g.ledger, toTerm g.epoch, toTerm g.pool,
    toTerm g.tip, toTerm g.deriving_, toTerm g.outbox, toTerm g.pending, toTerm g.tokens,
    toTerm g.unnumbered, toTerm g.introducedAt, toTerm g.joinedThrough, toTerm g.awaitingStart,
    toTerm g.received]
  ofTerm t := do
    let fs ← fieldsOf t 19
    some ⟨← fieldAt fs 0, ← fieldAt fs 1, ← fieldAt fs 2, ← fieldAt fs 3, ← fieldAt fs 4,
      ← fieldAt fs 5, ← fieldAt fs 6, ← fieldAt fs 7, ← fieldAt fs 8, ← fieldAt fs 9,
      ← fieldAt fs 10, ← fieldAt fs 11, ← fieldAt fs 12, ← fieldAt fs 13, ← fieldAt fs 14,
      ← fieldAt fs 15, ← fieldAt fs 16, ← fieldAt fs 17, ← fieldAt fs 18⟩

end CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member.Persist

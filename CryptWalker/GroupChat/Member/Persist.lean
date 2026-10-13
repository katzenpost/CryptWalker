/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cborg
import CryptWalker.GroupChat.Member.Group

/-! # Keeping a member

A `Group` as CBOR, so that a client can stop and carry on where it was. Each structure is an array
of its fields in declaration order; the whole is `[formatVersion, group]`. This is the format of a
Lean client's own state, not katzenqt's. -/

namespace CryptWalker.GroupChat.Member.Persist

open Cborg

def formatVersion : Nat := 1

class Persist (α : Type) where
  toTerm : α → Term
  ofTerm : Term → Option α

open Persist

def termList? : Term → Option (List Term)
  | .TList ts | .TListI ts => some ts.toList
  | _ => none

instance : Persist Nat where
  toTerm n := if n < 2 ^ 63 then .TInt n.toInt64 else .TInteger n
  ofTerm
    | .TInt n => if 0 ≤ n then some n.toInt.toNat else none
    | .TInteger n => if 0 ≤ n then some n.toNat else none
    | _ => none

instance : Persist Bool where
  toTerm := .TBool
  ofTerm | .TBool b => some b | _ => none

instance : Persist String where
  toTerm := .TString
  ofTerm | .TString s => some s | _ => none

instance : Persist ByteArray where
  toTerm := .TBytes
  ofTerm | .TBytes b => some b | _ => none

instance {α : Type} [Persist α] : Persist (Option α) where
  toTerm | some a => toTerm a | none => .TNull
  ofTerm
    | .TNull => some none
    | t => (ofTerm t).map some

instance {α : Type} [Persist α] : Persist (List α) where
  toTerm l := .TList (l.map toTerm).toArray
  ofTerm t := do (← termList? t).mapM ofTerm

instance {α β : Type} [Persist α] [Persist β] : Persist (α × β) where
  toTerm p := .TList #[toTerm p.1, toTerm p.2]
  ofTerm t := do
    match ← termList? t with
    | [a, b] => some (← ofTerm a, ← ofTerm b)
    | _ => none

instance {K V : Type} [Persist K] [Persist V] : Persist (Dict K V) where
  toTerm d := toTerm d.pairs
  ofTerm t := (ofTerm t).map Dict.mk

/-- A structure: its fields as an array. -/
def fieldsOf (t : Term) (n : Nat) : Option (Array Term) := do
  let ts ← termList? t
  if ts.length = n then some ts.toArray else none

def fieldAt {α : Type} [Persist α] (fs : Array Term) (i : Nat) : Option α :=
  ofTerm (fs.getD i .TNull)

def enumTerm (n : Nat) : Term := toTerm n

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

/-- A value in CBOR, under `formatVersion`. -/
def save {α : Type} [Persist α] (a : α) : ByteArray :=
  toByteArray (encodeTerm (.TList #[toTerm formatVersion, toTerm a]))

/-- What `save` wrote, or `none` when the bytes are not such a value. -/
def load {α : Type} [Persist α] (b : ByteArray) : Option α :=
  match deserialiseFromBytes decodeTerm b with
  | .ok (_, t) => do
    let fs ← fieldsOf t 2
    if (← fieldAt fs 0 : Nat) ≠ formatVersion then none
    fieldAt fs 1
  | .error _ => none

end CryptWalker.GroupChat.Member.Persist

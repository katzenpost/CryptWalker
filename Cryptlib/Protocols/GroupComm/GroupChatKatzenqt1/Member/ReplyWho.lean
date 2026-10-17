/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cborg
import Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.Events

/-! # The reply to a new member

What an introducer seals into a contact voucher's reply, as katzenqt's `GroupChatReplyWho`: its
roster in order, each member as a display name and a read cap starting where the new member is to
start reading, then the rest of a `JoinReply`, each member written as its place in that list. -/

namespace Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.ReplyWho

open Cborg

def maxNameChars : Nat := 30
def readCapSize : Nat := 136

structure PleaseAdd where
  name : String
  readCap : ByteArray
  deriving DecidableEq, Inhabited

structure ReplyWho where
  pleaseAdds : List (Option PleaseAdd)
  rosters : Option (List (Option (List (Nat × Option Nat)))) := none
  introductions : Option (List (Nat × Index × Nat)) := none
  introducer : Option Nat := none
  newcomer : Option Nat := none
  deriving DecidableEq, Inhabited

/-! ## Between a reply and a `JoinReply` -/

/-- The reply for `r`, naming each member by `name`; a member with no name takes no place, as
katzenqt leaves out a member it does not know. -/
def ofJoinReply (r : JoinReply) (name : Key → Option String) : ReplyWho :=
  { pleaseAdds := r.members.map fun m => m.bind fun (readCap, start) =>
      (name (keyOf readCap)).map fun n => ⟨n, keyOf readCap ++ start⟩
    rosters := some r.rosters
    introductions := some r.introductions
    introducer := some r.introducer
    newcomer := some r.newcomer }

/-- The `JoinReply` a reply carries, or `none` when it carries no rosters or cannot be read. -/
def toJoinReply (w : ReplyWho) : Option JoinReply := do
  let places := w.pleaseAdds.length
  let rosters ← w.rosters
  let introducer ← w.introducer
  let newcomer ← w.newcomer
  if newcomer ≠ places ∨ ¬ (introducer < places ∧ places < rosterMax) then none
  if (w.pleaseAdds.getD introducer none).isNone ∨ rosters.length ≠ places then none
  let keys := w.pleaseAdds.filterMap (·.map fun p => (keyOf p.readCap).data.toList)
  if keys.eraseDups.length ≠ keys.length then none
  let ok := rosters.all fun r => (r.getD []).all fun (i, slot) =>
    i < rosterMax && (slot.all (· < places))
  if !ok then none
  let introductions := (w.introductions.getD []).filter fun (by_, index, member) =>
    by_ < places && member < places && index.size == indexSize
  some { members := w.pleaseAdds.map (·.map fun p => (p.readCap, startOf p.readCap))
         rosters, introductions, introducer, newcomer }

/-! ## CBOR -/

def nat (n : Nat) : Term := .TInt n.toInt64

def optNat : Option Nat → Term
  | some n => nat n
  | none => .TNull

def pleaseAddTerm (p : PleaseAdd) : Term :=
  .TMap #[(.TString "display_name", .TString p.name), (.TString "read_cap", .TBytes p.readCap)]

def rosterTerm (r : List (Nat × Option Nat)) : Term :=
  .TList (r.map fun (i, slot) => .TList #[nat i, optNat slot]).toArray

def toTerm (w : ReplyWho) : Term :=
  let entries : List (Option (Term × Term)) :=
    [ some (.TString "please_adds",
        .TList (w.pleaseAdds.map fun p => (p.map pleaseAddTerm).getD .TNull).toArray),
      w.rosters.map fun rs => (.TString "rosters",
        .TList (rs.map fun r => (r.map rosterTerm).getD .TNull).toArray),
      w.introductions.map fun is => (.TString "introductions",
        .TList (is.map fun (b, i, m) => .TList #[nat b, .TBytes i, nat m]).toArray),
      w.introducer.map fun n => (.TString "introducer", nat n),
      w.newcomer.map fun n => (.TString "newcomer", nat n) ]
  .TMap (entries.filterMap id).toArray

def encode (w : ReplyWho) : ByteArray := toByteArray (encodeTerm (toTerm w))

def termNat? : Term → Option Nat
  | .TInt n => if 0 ≤ n then some n.toInt.toNat else none
  | .TInteger n => if 0 ≤ n then some n.toNat else none
  | _ => none

def termList? : Term → Option (List Term)
  | .TList ts | .TListI ts => some ts.toList
  | _ => none

def termMap? : Term → Option (List (Term × Term))
  | .TMap kvs | .TMapI kvs => some kvs.toList
  | _ => none

def termString? : Term → Option String
  | .TString s => some s
  | .TStringI ss => some (String.join ss.toList)
  | _ => none

def termBytes? : Term → Option ByteArray
  | .TBytes b => some b
  | .TBytesI bs => some (bs.foldl (· ++ ·) .empty)
  | _ => none

def isNull : Term → Bool
  | .TNull => true
  | _ => false

def field? (kvs : List (Term × Term)) (key : String) : Option Term :=
  (kvs.reverse.find? fun (k, _) => termString? k = some key).map (·.2)

/-- A value that may be absent or `null`; `none` when it is present and cannot be read. -/
def optional {α : Type} (t : Option Term) (read : Term → Option α) : Option (Option α) :=
  match t with
  | none => some none
  | some t => if isNull t then some none else (read t).map some

def nullableList {α : Type} (read : Term → Option α) (t : Term) : Option (List (Option α)) := do
  (← termList? t).mapM fun x => if isNull x then some none else (read x).map some

def readPleaseAdd (t : Term) : Option PleaseAdd := do
  let kvs ← termMap? t
  let name ← termString? (← field? kvs "display_name")
  let cap ← termBytes? (← field? kvs "read_cap")
  if 1 ≤ name.length ∧ name.length ≤ maxNameChars ∧ cap.size = readCapSize then some ⟨name, cap⟩
  else none

def readRoster (t : Term) : Option (List (Nat × Option Nat)) := do
  (← termList? t).mapM fun e => do
    match ← termList? e with
    | [i, slot] => some (← termNat? i, ← if isNull slot then some none else (termNat? slot).map some)
    | _ => none

def readIntroduction (t : Term) : Option (Nat × Index × Nat) := do
  match ← termList? t with
  | [b, i, m] => some (← termNat? b, ← termBytes? i, ← termNat? m)
  | _ => none

def ofTerm (t : Term) : Option ReplyWho := do
  let kvs ← termMap? t
  let pleaseAdds ← nullableList readPleaseAdd (← field? kvs "please_adds")
  let rosters ← optional (field? kvs "rosters") (nullableList readRoster)
  let introductions ← optional (field? kvs "introductions") fun t => do
    (← termList? t).mapM readIntroduction
  let introducer ← optional (field? kvs "introducer") termNat?
  let newcomer ← optional (field? kvs "newcomer") termNat?
  some { pleaseAdds, rosters, introductions, introducer, newcomer }

def decode (b : ByteArray) : Option ReplyWho :=
  match deserialiseFromBytes decodeTerm b with
  | .ok (_, t) => ofTerm t
  | .error _ => none

end Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.ReplyWho

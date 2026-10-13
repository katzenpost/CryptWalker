/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.GroupChat.Member.Dict
import CryptWalker.GroupChat.Member.Wire

/-! # Rosters with explicit numbering

Every roster index is announced explicitly, so a missed message leaves an index unresolved and
never shifts others. A roster that began as its introducer's reads its early entries from that
roster. See "Rosters" in the group chat spec. -/

namespace CryptWalker.GroupChat.Member

/-- An `Introduction`: its introducer and its box. -/
abbrev At := Key × Index

structure Entry where
  key : Option Key := none
  /-- The start of the member's key, as a `Numbers` field names it. -/
  prefix_ : Option ByteArray := none
  deriving DecidableEq, Inhabited

structure Rosters where
  entries : Dict Key (Dict Nat Entry) := {}
  /-- A member whose roster began as its introducer's, through the index the introducer gave it. -/
  started : Dict Key (Key × Nat) := {}
  introductions : Dict At Key := {}
  /-- Every member whose key this member knows: whom a prefix can name. -/
  keys : List Key := []
  deriving DecidableEq, Inhabited

namespace Rosters

def learn (r : Rosters) (key : Key) : Rosters :=
  if r.keys.contains key then r else { r with keys := r.keys ++ [key] }

def startsWith (key p : ByteArray) : Bool := p.data.toList.isPrefixOf key.data.toList

/-- The one member known whose key starts with `p`. -/
def named (r : Rosters) (p : ByteArray) : Option Key :=
  match r.keys.filter (startsWith · p) with
  | [k] => some k
  | _ => none

def sortKeys (l : List Key) : List Key := l.mergeSort fun a b => !bytesLt b.toList a.toList

def sortNats (l : List Nat) : List Nat := l.eraseDups.mergeSort (· ≤ ·)

/-- Start a group: every founder's roster is all founders in ascending order of key. -/
def found (r : Rosters) (founders : List Key) : Rosters :=
  let roster : Dict Nat Entry :=
    Dict.ofList ((sortKeys founders).zipIdx.map fun (k, i) => (i, { key := some k }))
  founders.foldl (fun r f => ({ r with entries := r.entries.set f roster } : Rosters).learn f) r

/-- Who `owner` numbered `index`, following where rosters began; `seen` stops a cycle. -/
def resolveAux (r : Rosters) : Nat → List Key → Key → Nat → Option Key
  | fuel, seen, owner, index =>
    match ((r.entries.getD owner {}).get? index) with
    | some e =>
      match e.key, e.prefix_ with
      | some k, _ => some k
      | none, some p => if p.size = 0 then none else r.named p
      | none, none => none
    | none =>
      match fuel with
      | 0 => none
      | f + 1 =>
        match r.started.get? owner with
        | some (i, top) => if index > top || seen.any (· = owner) then none else resolveAux r f (owner :: seen) i index
        | none => none

/-- Who `owner` numbered `index`, if this member can tell. -/
def resolve (r : Rosters) (owner : Key) (index : Nat) : Option Key :=
  resolveAux r (r.started.size + 1) [] owner index

def indexesAux (r : Rosters) : Nat → List Key → Key → List Nat
  | fuel, seen, owner =>
    let own := (r.entries.getD owner {}).keys
    match fuel, r.started.get? owner with
    | f + 1, some (i, top) =>
      if seen.any (· = owner) then own else own ++ (indexesAux r f (owner :: seen) i).filter (· ≤ top)
    | _, _ => own

/-- Every index `owner` is known to have assigned, in ascending order, and to whom. -/
def known (r : Rosters) (owner : Key) : List (Nat × Option Key) :=
  (sortNats (indexesAux r (r.started.size + 1) [] owner)).map fun i => (i, r.resolve owner i)

def size (r : Rosters) (owner : Key) : Nat :=
  match (r.known owner).getLast? with
  | some (i, _) => i + 1
  | none => 0

def indexOf (r : Rosters) (owner member : Key) : Option Nat :=
  ((r.known owner).find? (·.2 = some member)).map (·.1)

/-- `owner` numbered `index` as `entry` says; an entry already held is kept. -/
def number (r : Rosters) (owner : Key) (index : Nat) (entry : Entry) : Rosters :=
  { r with entries := r.entries.set owner ((r.entries.getD owner {}).setDefault index entry) }

/-- Forget `member`'s key, keeping every place it holds, under `token`. A place named by a prefix
is `member`'s only if the prefix names no other member known. -/
def retire (r : Rosters) (member token : Key) : Rosters :=
  let renamed := fun (k : Key) => if k = member then token else k
  let entries := r.entries.mapValues fun roster => roster.mapValues fun e =>
    let hit := e.key = some member ||
      match e.prefix_ with
      | some p => p.size ≠ 0 && r.named p = some member
      | none => false
    if hit then { key := some token, prefix_ := none } else e
  let entries := match entries.get? member with
    | some roster => (entries.erase member).set token roster
    | none => entries
  { entries := entries
    started := Dict.ofList (r.started.pairs.map fun (o, (i, top)) => (renamed o, (renamed i, top)))
    introductions := Dict.ofList (r.introductions.pairs.map fun ((i, b), k) => ((renamed i, b), renamed k))
    keys := r.keys.map renamed }

end Rosters

end CryptWalker.GroupChat.Member

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.GroupChat.Member.Dict
import CryptWalker.GroupChat.Member.Wire

/-! # Rosters with explicit numbering

See "Rosters" in the group chat spec, and katzenqt's `groupchat/numbering.py`. Every roster index
is announced, as the member it names or as the `Introduction` that introduced it, so a missed
message leaves an index unresolved and never shifts the others. A roster that began as a copy of
an introducer's is not copied: its early entries are read from the introducer's roster, up to the
index it assigned the new member. -/

namespace CryptWalker.GroupChat.Member

/-- An `Introduction`: its introducer and its box. -/
abbrev At := Key × Index

structure Entry where
  key : Option Key := none
  introduced : Option At := none
  deriving DecidableEq, Inhabited

structure Rosters where
  entries : Dict Key (Dict Nat Entry) := {}
  /-- A member whose roster began as its introducer's, through the index the introducer gave it. -/
  started : Dict Key (Key × Nat) := {}
  introductions : Dict At Key := {}
  deriving DecidableEq, Inhabited

namespace Rosters

def sortKeys (l : List Key) : List Key := l.mergeSort fun a b => !bytesLt b.toList a.toList

def sortNats (l : List Nat) : List Nat := l.eraseDups.mergeSort (· ≤ ·)

/-- Start a group: every founder's roster is all founders in ascending order of key. -/
def found (r : Rosters) (founders : List Key) : Rosters :=
  let roster : Dict Nat Entry :=
    Dict.ofList ((sortKeys founders).zipIdx.map fun (k, i) => (i, { key := some k }))
  { r with entries := founders.foldl (fun e f => e.set f roster) r.entries }

/-- Who `owner` numbered `index`, following where rosters began; `seen` stops a cycle. -/
def resolveAux (r : Rosters) : Nat → List Key → Key → Nat → Option Key
  | fuel, seen, owner, index =>
    match ((r.entries.getD owner {}).get? index) with
    | some e =>
      match e.key with
      | some k => some k
      | none => e.introduced.bind r.introductions.get?
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

/-- `owner` numbered `index`, as the member `introduced` introduced; an entry already held is
kept. -/
def number (r : Rosters) (owner : Key) (index : Nat) (introduced : Option At) : Rosters :=
  { r with entries := r.entries.set owner ((r.entries.getD owner {}).setDefault index { introduced := introduced }) }

/-- Forget `member`'s key, keeping every place it holds, under `token`. -/
def retire (r : Rosters) (member token : Key) : Rosters :=
  let renamed := fun (k : Key) => if k = member then token else k
  let entries := r.entries.mapValues fun roster => roster.mapValues fun e =>
    { key := e.key.map renamed, introduced := e.introduced.map fun (i, b) => (renamed i, b) }
  let entries := match entries.get? member with
    | some roster => (entries.erase member).set token roster
    | none => entries
  { entries := entries
    started := Dict.ofList (r.started.pairs.map fun (o, (i, top)) => (renamed o, (renamed i, top)))
    introductions := Dict.ofList (r.introductions.pairs.map fun ((i, b), k) => ((renamed i, b), renamed k)) }

end Rosters

end CryptWalker.GroupChat.Member

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cborg
import CryptWalker.Protocols.GroupComm.Common.Dict

/-! # Keeping state on disk

A client's state as CBOR, so that it can stop and carry on where it was. Each structure is an
array of its fields in declaration order; the whole is `[formatVersion, value]`. -/

namespace CryptWalker.Protocols.GroupComm.Common.Persist

open Cborg
open CryptWalker.Protocols.GroupComm.Common

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

end CryptWalker.Protocols.GroupComm.Common.Persist

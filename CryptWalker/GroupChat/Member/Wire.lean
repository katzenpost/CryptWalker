/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # What a group chat message says to the protocol

See "Group chat message types" and "Numbers and IntroducedAt wire format" in the group chat spec,
and katzenqt's `groupchat/wire.py`. A message is modelled after decoding: the CBOR envelope is
the client's business, as `Codec` is in katzenqt. A box is named by its `MessageBoxIndex`, an
opaque value compared only for equality. -/

namespace CryptWalker.GroupChat.Member

/-- A member's identity: the public key its read cap begins with. -/
abbrev Key := ByteArray

/-- A box: its 104-byte `MessageBoxIndex`. -/
abbrev Index := ByteArray

def keySize : Nat := 32
def indexSize : Nat := 104
/-- The most entries a roster holds: roster indexes are one byte. -/
def rosterMax : Nat := 256

def keyOf (readCap : ByteArray) : Key := readCap.extract 0 keySize

/-- The index a read cap starts at. -/
def startOf (readCap : ByteArray) : Index := readCap.extract keySize readCap.size

/-- Python's ordering of `bytes`: lexicographic, a prefix first. -/
def bytesLt : List UInt8 → List UInt8 → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => if a = b then bytesLt as bs else a < b

/-- An `Introduction`: its introducer's roster index in the sender's roster, and its box. -/
structure IntroRef where
  introducer : Nat
  index : Index
  deriving DecidableEq, Inhabited

structure Introduction where
  name : String
  readCap : ByteArray
  deriving DecidableEq, Inhabited

/-- Roster indexes assigned, each with the `Introduction` of the member assigned it; `none` for
the `Introduction` the message itself carries. -/
abbrev Numbers := List (Nat × Option IntroRef)

/-- A message carries content or control, never both. `acks` is in ascending roster index. -/
structure Message where
  content : Option ByteArray := none
  introduction : Option Introduction := none
  numbers : Numbers := []
  introducedAt : Option IntroRef := none
  acks : List (Nat × Index) := []
  deriving DecidableEq, Inhabited

/-! ## Numbers and IntroducedAt -/

def entrySize : Nat := 2 + indexSize

def encodeNumbers : Numbers → List UInt8
  | [(k, none)] => [k.toUInt8]
  | ns => ns.flatMap fun
    | (k, some r) => k.toUInt8 :: r.introducer.toUInt8 :: r.index.data.toList
    | (_, none) => []

def ascending : List Nat → Bool
  | a :: b :: rest => a < b && ascending (b :: rest)
  | _ => true

/-- Split a field into 106-byte entries. -/
def entries : Nat → List UInt8 → List (List UInt8)
  | 0, _ => []
  | n + 1, l => l.take entrySize :: entries n (l.drop entrySize)

/-- Empty when the field is malformed. -/
def decodeNumbers (field : List UInt8) : Numbers :=
  match field with
  | [k] => [(k.toNat, none)]
  | _ =>
    if field.length % entrySize ≠ 0 then []
    else
      let ns := (entries (field.length / entrySize) field).map fun e =>
        ((e.getD 0 0).toNat, some ⟨(e.getD 1 0).toNat, ⟨(e.drop 2).toArray⟩⟩)
      if ascending (ns.map (·.1)) then ns else []

def encodeIntroducedAt (r : IntroRef) : List UInt8 := r.introducer.toUInt8 :: r.index.data.toList

def decodeIntroducedAt : List UInt8 → Option IntroRef
  | field@(i :: rest) => if field.length = 1 + indexSize then some ⟨i.toNat, ⟨rest.toArray⟩⟩ else none
  | [] => none

end CryptWalker.GroupChat.Member

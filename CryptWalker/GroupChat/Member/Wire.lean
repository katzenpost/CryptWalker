/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # Group chat messages

Messages are modelled after CBOR decoding. See "Group chat message types" and "Numbers and
IntroducedAt wire format" in the group chat spec. -/

namespace CryptWalker.GroupChat.Member

/-- A member's identity: the public key its read cap begins with. -/
abbrev Key := ByteArray

/-- A box: its 104-byte `MessageBoxIndex`. -/
abbrev Index := ByteArray

def keySize : Nat := 32
def indexSize : Nat := 104
/-- The most entries a roster holds: roster indexes are one byte. -/
def rosterMax : Nat := 256
/-- How much of a member's key a `Numbers` field names it by. -/
def prefixSize : Nat := 8

def keyOf (readCap : ByteArray) : Key := readCap.extract 0 keySize

def prefixOf (key : Key) : ByteArray := key.extract 0 prefixSize

/-- The index a read cap starts at. -/
def startOf (readCap : ByteArray) : Index := readCap.extract keySize readCap.size

/-- The BACAP `Idx64` of `index`: its first 8 bytes, little-endian. -/
def counter (index : Index) : Nat :=
  (index.extract 0 8).toList.foldr (fun b n => b.toNat + 256 * n) 0

/-- Lexicographic order on bytes, a proper prefix first. -/
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

/-- Roster indexes assigned, consecutive, each with the key prefix of the member assigned it;
`none` for the member the message's own `Introduction` introduces. -/
abbrev Numbers := List (Nat × Option ByteArray)

/-- A message carries content or control, never both. `acks` pairs roster indexes, ascending, with
the `Idx64` of the box acknowledged. -/
structure Message where
  content : Option ByteArray := none
  introduction : Option Introduction := none
  numbers : Numbers := []
  introducedAt : Option IntroRef := none
  acks : List (Nat × Nat) := []
  deriving DecidableEq, Inhabited

/-! ## Numbers and IntroducedAt -/

/-- The first index assigned, then the key prefix of each member, one per consecutive index; a
lone byte for the member an `Introduction` introduces. -/
def encodeNumbers : Numbers → List UInt8
  | [(k, none)] => [k.toUInt8]
  | [] => []
  | (k, p) :: rest => k.toUInt8 :: ((p :: rest.map (·.2)).flatMap fun
    | some p => p.data.toList
    | none => [])

/-- Split a field into `n` prefixes. -/
def prefixes : Nat → List UInt8 → List (List UInt8)
  | 0, _ => []
  | n + 1, l => l.take prefixSize :: prefixes n (l.drop prefixSize)

/-- Empty when the field is malformed. -/
def decodeNumbers (field : List UInt8) : Numbers :=
  match field with
  | [k] => [(k.toNat, none)]
  | [] => []
  | first :: rest =>
    if rest.length = 0 ∨ rest.length % prefixSize ≠ 0 then []
    else
      let ps := prefixes (rest.length / prefixSize) rest
      if first.toNat + ps.length > rosterMax ∨ ¬ ps.Nodup then []
      else ps.zipIdx.map fun (p, n) => (first.toNat + n, some ⟨p.toArray⟩)

def encodeIntroducedAt (r : IntroRef) : List UInt8 := r.introducer.toUInt8 :: r.index.data.toList

def decodeIntroducedAt : List UInt8 → Option IntroRef
  | field@(i :: rest) => if field.length = 1 + indexSize then some ⟨i.toNat, ⟨rest.toArray⟩⟩ else none
  | [] => none

end CryptWalker.GroupChat.Member

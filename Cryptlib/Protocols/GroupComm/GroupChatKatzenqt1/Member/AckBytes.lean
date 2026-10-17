/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # The `Acks` field, in bytes

The executable codec for the `Acks` field, following katzenqt's `ack_codec.py`: the count less
one, the members named as a list or a bitmap, whichever is shorter, then each one's `Idx64`,
little-endian. Each definition follows its namesake in `Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.AckCodec`, whose
theorems `AckBytesProofs` carries over to this one. Reading is not strict: like katzenqt, it
accepts a list where the bitmap would have been shorter. -/

namespace Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.AckBytes

def rosterMax : Nat := 256

/-- The longest naming: a bitmap reaching roster index 255. -/
def maxNaming : Nat := 32

/-- Bytes in a value: an `Idx64`. -/
def idxSize : Nat := 8

/-- Bytes a bitmap needs to reach roster index `i`. -/
def width (i : Nat) : Nat := i / 8 + 1

/-- Whether bit `k` of byte `j` marks a member of `idx`: index `i` is bit `7 - i % 8` of byte
`i / 8`. -/
def marks (idx : List Nat) (j k : Nat) : Bool := idx.any fun i => i / 8 = j && 7 - i % 8 = k

/-- Byte `j` of the bitmap for `idx`. -/
def bitmapByte (idx : List Nat) (j : Nat) : Nat :=
  ((List.range 8).filter (marks idx j)).foldr (fun k s => 2 ^ k + s) 0

def bitmap (idx : List Nat) (w : Nat) : List Nat := (List.range w).map (bitmapByte idx)

/-- Ascending roster indexes as a list or a bitmap, whichever is shorter. -/
def nameMembers (idx : List Nat) : List Nat :=
  match idx.getLast? with
  | none => []
  | some last => if idx.length ≤ width last then idx else bitmap idx (width last)

def bitSet (naming : List Nat) (i : Nat) : Bool := (naming.getD (i / 8) 0).testBit (7 - i % 8)

/-- The roster indexes a bitmap marks, in ascending order. -/
def setBits (naming : List Nat) : List Nat :=
  (List.range (naming.length * 8)).filter (bitSet naming)

def ascending : List Nat → Bool
  | a :: b :: rest => a < b && ascending (b :: rest)
  | _ => true

/-- What precedes `count` values. -/
def readMembers (naming : List Nat) (count : Nat) : Option (List Nat) :=
  if naming.length = count then
    if ascending naming then some naming else none
  else if count < naming.length then none
  else if maxNaming < naming.length then none
  else if naming = [] ∨ naming.getLast? = some 0 then none
  else if (setBits naming).length = count then some (setBits naming) else none

/-- The `n` values of `v` bytes that follow the naming. -/
def chunks (v : Nat) : List Nat → Nat → List (List Nat)
  | _, 0 => []
  | l, n + 1 => l.take v :: chunks v (l.drop v) n

/-- The `k` bytes of `n`, least significant first. -/
def le : Nat → Nat → List Nat
  | 0, _ => []
  | k + 1, n => n % 256 :: le k (n / 256)

/-- The number little-endian bytes spell. -/
def fromLE (l : List Nat) : Nat := l.foldr (fun b n => b + 256 * n) 0

def encodeUncounted (acks : List (Nat × List Nat)) : List Nat :=
  nameMembers (acks.map Prod.fst) ++ (acks.map Prod.snd).flatten

def encodeValues (acks : List (Nat × List Nat)) : List Nat :=
  if acks = [] then [] else (acks.length - 1) :: encodeUncounted acks

def decodeValues (v : Nat) : List Nat → Option (List (Nat × List Nat))
  | [] => some []
  | c :: rest =>
    if rest.length < (c + 1) * v then none
    else
      let w := rest.length - (c + 1) * v
      (readMembers (rest.take w) (c + 1)).map fun idx =>
        idx.zip (chunks v (rest.drop w) (c + 1))

/-- The field for `acks`, pairs of roster index and `Idx64` in ascending order of index, as
numbers below 256. -/
def encodeNat (acks : List (Nat × Nat)) : List Nat :=
  encodeValues (acks.map fun a => (a.1, le idxSize a.2))

def decodeNat (field : List Nat) : Option (List (Nat × Nat)) :=
  (decodeValues idxSize field).map (·.map fun a => (a.1, fromLE a.2))

/-- The field for `acks`; empty when there is nothing to acknowledge. -/
def encode (acks : List (Nat × Nat)) : ByteArray :=
  ⟨((encodeNat acks).map Nat.toUInt8).toArray⟩

/-- The acknowledgements a field carries, or `none` when it is malformed. -/
def decode (field : ByteArray) : Option (List (Nat × Nat)) :=
  decodeNat (field.data.toList.map UInt8.toNat)

end Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.AckBytes

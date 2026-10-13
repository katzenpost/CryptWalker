/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # The CBOR a group chat message uses

Definite-length unsigned integers, byte strings, text strings and maps, as Python's `cbor2` writes
them: each header in its shortest form. Reading also skips any other well-formed item, so that a
field this client does not interpret can be passed over or kept as it came. Every function here is
total, so what is proved of it holds of what runs. -/

namespace CryptWalker.GroupChat.Member.Cbor

/-- `n` as `k` bytes, most significant first. -/
def be : Nat → Nat → List UInt8
  | 0, _ => []
  | k + 1, n => be k (n / 256) ++ [(n % 256).toUInt8]

/-- The number big-endian bytes spell. -/
def fromBE (l : List UInt8) : Nat := l.foldl (fun n b => n * 256 + b.toNat) 0

/-- The header of an item of major type `major` with argument `n`, in its shortest form. -/
def header (major n : Nat) : List UInt8 :=
  let m := major * 32
  if n < 24 then [(m + n).toUInt8]
  else if n < 2 ^ 8 then (m + 24).toUInt8 :: be 1 n
  else if n < 2 ^ 16 then (m + 25).toUInt8 :: be 2 n
  else if n < 2 ^ 32 then (m + 26).toUInt8 :: be 4 n
  else (m + 27).toUInt8 :: be 8 n

/-- An item's major type, its argument, and what follows the header. Indefinite lengths and the
reserved additional information values are refused. -/
def readHeader : List UInt8 → Option (Nat × Nat × List UInt8)
  | [] => none
  | b :: rest =>
    let ai := b.toNat % 32
    if ai < 24 then some (b.toNat / 32, ai, rest)
    else if ai < 28 then
      let k := 2 ^ (ai - 24)
      if rest.length < k then none else some (b.toNat / 32, fromBE (rest.take k), rest.drop k)
    else none

def uint (n : Nat) : List UInt8 := header 0 n

def bytes (b : List UInt8) : List UInt8 := header 2 b.length ++ b

def text (s : String) : List UInt8 := header 3 s.utf8ByteSize ++ s.toByteArray.data.toList

def null : List UInt8 := [0xf6]

def readUInt (l : List UInt8) : Option (Nat × List UInt8) := do
  let (major, n, rest) ← readHeader l
  if major = 0 then some (n, rest) else none

/-- A string's contents: of major type `major`, `n` bytes. -/
def readString (major : Nat) (l : List UInt8) : Option (List UInt8 × List UInt8) := do
  let (m, n, rest) ← readHeader l
  if m = major ∧ n ≤ rest.length then some (rest.take n, rest.drop n) else none

def readBytes : List UInt8 → Option (List UInt8 × List UInt8) := readString 2

def readText (l : List UInt8) : Option (String × List UInt8) := do
  let (b, rest) ← readString 3 l
  let s ← String.fromUTF8? ⟨b.toArray⟩
  some (s, rest)

/-- Whether the next item is `null`. -/
def isNull (l : List UInt8) : Bool := l.head? == some 0xf6

/-- Pass over `count` well-formed items. `fuel` bounds the items visited; one per byte of input
is always enough, since every item takes at least one byte. -/
def skipItems : Nat → Nat → List UInt8 → Option (List UInt8)
  | _, 0, l => some l
  | 0, _ + 1, _ => none
  | fuel + 1, count + 1, l => do
    let (major, n, rest) ← readHeader l
    let after ← match major with
      | 0 | 1 | 7 => some rest
      | 2 | 3 => if n ≤ rest.length then some (rest.drop n) else none
      | 4 => skipItems fuel n rest
      | 5 => skipItems fuel (2 * n) rest
      | 6 => skipItems fuel 1 rest
      | _ => none
    skipItems fuel count after

/-- The next item as it came, and what follows it. -/
def readRaw (l : List UInt8) : Option (List UInt8 × List UInt8) := do
  let rest ← skipItems (l.length + 1) 1 l
  some (l.take (l.length - rest.length), rest)

end CryptWalker.GroupChat.Member.Cbor

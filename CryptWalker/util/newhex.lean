
import Mathlib.Data.String.Basic

namespace CryptWalker.util.newhex

def byteToHex (b : UInt8) : String :=
  let high := hexDigitRepr (b.toNat / 16)
  let low := hexDigitRepr (b.toNat % 16)
  s!"{high}{low}"

def byteArrayToHex (blob : ByteArray) : String :=
  blob.foldl (fun acc b => acc ++ byteToHex b) ""

instance : Repr ByteArray where
  reprPrec a _ := byteArrayToHex a

instance : ToString ByteArray where
  toString x :=
    byteArrayToHex x

def hexCharToDigit (c : Char) : Option UInt8 :=
  if '0' ≤ c ∧ c ≤ '9' then
    some (UInt8.ofNat (c.toNat - '0'.toNat))
  else if 'a' ≤ c ∧ c ≤ 'f' then
    some (UInt8.ofNat (10 + c.toNat - 'a'.toNat))
  else if 'A' ≤ c ∧ c ≤ 'F' then
    some (UInt8.ofNat (10 + c.toNat - 'A'.toNat))
  else
    none

def hexToByte (high : Char) (low : Char) : Option UInt8 :=
  match hexCharToDigit high, hexCharToDigit low with
  | some h, some l => some (h <<< 4 ||| l)
  | _, _ => none

partial def hexStringToByteArrayAux (s : String) (pos : String.Pos) (acc : List UInt8) : Option (List UInt8) :=
  if pos < s.endPos then
    let nextPos := s.next pos
    let nextNextPos := s.next nextPos
    match hexToByte (s.get pos) (s.get nextPos) with
    | some byte => hexStringToByteArrayAux s nextNextPos (byte :: acc)
    | none => none
  else
    some acc.reverse

def hexStringToByteArray (s : String) : Option ByteArray :=
  if s.length % 2 ≠ 0 then
    none
  else
    match hexStringToByteArrayAux s 0 [] with
    | some bytes => some (ByteArray.mk (Array.mk bytes))
    | none => none

def falliableHexStringToByteArray (s : String) : ByteArray :=
  if s.length % 2 ≠ 0 then
    panic! "Hex string length must be even."
  else
    match hexStringToByteArrayAux s 0 [] with
    | some bytes => ByteArray.mk (Array.mk bytes)
    | none => panic! "Failed to convert hex string to ByteArray."

end CryptWalker.util.newhex

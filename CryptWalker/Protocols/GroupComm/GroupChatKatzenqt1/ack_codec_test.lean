/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json

import CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.AckCodec
import CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member.AckBytes
import CryptWalker.Util.newhex

/-! # `Acks` field vectors

Checks `testdata/acks_vectors.json`. Valid cases must encode exactly and decode under both
parsers; lenient fields decode only under the spec's parser; malformed fields decode under
neither. -/

open Lean
open CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.AckCodec
open CryptWalker.Util.newhex

def hexNats (s : String) : Except String (List ℕ) :=
  match hexStringToByteArray s with
  | some b => pure (b.toList.map (·.toNat))
  | none => throw s!"not valid hex: {s}"

def readAcks (j : Json) : Except String (List (ℕ × ℕ)) := do
  let raw ← (← j.getObjVal? "acks").getArr?
  let acks ← raw.toList.mapM fun pair => do
    let p ← pair.getArr?
    pure ((← (p[0]!).getNat?), (← (p[1]!).getNat?))
  pure (acks.mergeSort (fun a b => a.1 ≤ b.1))

def caseOf (j : Json) : Except String (String × List ℕ) := do
  pure ((← (← j.getObjVal? "name").getStr?), ← hexNats (← (← j.getObjVal? "field").getStr?))

/-- The executable codec reads `field` as `acks`, and writes `acks` back as the encoder would. -/
def checkBytes (name : String) (field : List ℕ) (acks : Option (List (ℕ × ℕ))) :
    Except String Unit := do
  let bytes : ByteArray := ⟨(field.map Nat.toUInt8).toArray⟩
  if CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member.AckBytes.decode bytes != acks then
    throw s!"{name}: the byte codec misreads it"
  if let some acks := acks then
    if (CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member.AckBytes.encode acks).data.toList.map (·.toNat) != encodeIdx64 acks then
      throw s!"{name}: the byte codec encodes differently"

def valid (j : Json) : Except String String := do
  let (name, field) ← caseOf j
  let acks ← readAcks j
  if encodeIdx64 acks != field then throw s!"{name}: encodes differently"
  if decodeIdx64 false field != some acks then throw s!"{name}: the spec's parser misreads it"
  if decodeIdx64 true field != some acks then throw s!"{name}: the strict parser misreads it"
  checkBytes name field (some acks)
  pure s!"{name} ({acks.length} acknowledged, {field.length} bytes)"

def lenient (j : Json) : Except String String := do
  let (name, field) ← caseOf j
  let acks ← readAcks j
  if decodeIdx64 false field != some acks then throw s!"{name}: the spec's parser misreads it"
  if decodeIdx64 true field != none then throw s!"{name}: the strict parser accepts it"
  checkBytes name field (some acks)
  pure s!"{name} (lenient, refused by the strict parser)"

def malformed (j : Json) : Except String String := do
  let (name, field) ← caseOf j
  if decodeIdx64 false field != none then throw s!"{name}: the spec's parser accepts it"
  if decodeIdx64 true field != none then throw s!"{name}: the strict parser accepts it"
  checkBytes name field none
  pure s!"{name} (malformed)"

def main : IO UInt32 := do
  let text ← IO.FS.readFile "testdata/acks_vectors.json"
  let groups ← IO.ofExcept do
    let j ← Json.parse text
    pure [((← (← j.getObjVal? "valid").getArr?), valid),
      ((← (← j.getObjVal? "lenient").getArr?), lenient),
      ((← (← j.getObjVal? "malformed").getArr?), malformed)]
  let mut ok := true
  let mut n := 0
  for (cases, check) in groups do
    for c in cases do
      n := n + 1
      match check c with
      | .ok msg => IO.println s!"  ok    {msg}"
      | .error e => ok := false; IO.println s!"  FAIL  {e}"
  if ok then
    IO.println s!"all {n} Acks vectors passed"
    pure 0
  else
    IO.eprintln "some Acks vectors FAILED"
    pure 1

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json

import Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.Gcm
import Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.Membership
import Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.ReplyWho
import Cryptlib.Util.newhex

/-! # Group chat wire vectors

Checks `testdata/groupchat_wire_vectors.json`, generated from katzenqt: each message reads as
katzenqt reads it and is written back as katzenqt writes it, each member's message is written as
the same box, membership hashes agree, and each reply decodes, encodes to the same bytes and
carries the same `JoinReply`. -/

open Lean
open Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member
open Cryptlib.Util.newhex

def hex (s : String) : Except String ByteArray :=
  match hexStringToByteArray s with
  | some b => pure b
  | none => throw s!"not valid hex: {s}"

def str (j : Json) (k : String) : Except String String := do (← j.getObjVal? k).getStr?

def opt {α : Type} (j : Json) (k : String) (read : Json → Except String α) :
    Except String (Option α) := do
  match j.getObjVal? k with
  | .ok .null | .error _ => pure none
  | .ok v => some <$> read v

def readMessage (j : Json) : Except String Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.Message := do
  let content ← opt j "content" fun v => do hex (← v.getStr?)
  let introduction ← opt j "introduction" fun v => do
    pure (Introduction.mk (← str v "name") (← hex (← str v "read_cap")))
  let numbers ← (← (← j.getObjVal? "numbers").getArr?).toList.mapM fun n => do
    let p ← n.getArr?
    let k ← p[0]!.getNat?
    match p[1]! with
    | .null => pure (k, none)
    | v => pure (k, some (← hex (← v.getStr?)))
  let introducedAt ← opt j "introduced_at" fun v => do
    pure (IntroRef.mk (← (← v.getObjVal? "introducer").getNat?) (← hex (← str v "index")))
  let acks ← (← (← j.getObjVal? "acks").getArr?).toList.mapM fun a => do
    let p ← a.getArr?
    pure (← p[0]!.getNat?, ← p[1]!.getNat?)
  pure { content, introduction, numbers, introducedAt, acks }

def message (j : Json) : Except String String := do
  let name ← str j "name"
  let cbor ← hex (← str j "cbor")
  let expected ← opt j "message" readMessage
  let got := Gcm.toMessage cbor
  if got != expected then throw s!"{name}: read differently"
  match got, ← opt j "rewritten" fun v => do hex (← v.getStr?) with
  | some m, some rewritten =>
    unless (Gcm.ofMessage m).map Gcm.encode == some rewritten do
      throw s!"{name}: written back differently"
    if rewritten == cbor then
      unless (Gcm.decode cbor).map Gcm.encode == some cbor do
        throw s!"{name}: does not decode and encode to itself"
  | none, none => pure ()
  | _, _ => throw s!"{name}: the vector is inconsistent"
  pure s!"{name}{if got.isNone then " (refused)" else ""}"

def written (j : Json) : Except String String := do
  let name ← str j "name"
  let m ← readMessage (← j.getObjVal? "message")
  unless Gcm.box m == some (← hex (← str j "box")) do throw s!"{name}: written as another box"
  pure s!"{name} (written)"

def membership (j : Json) : Except String String := do
  let caps ← (← (← j.getObjVal? "read_caps").getArr?).toList.mapM fun c => do hex (← c.getStr?)
  unless membershipHash caps == (← hex (← str j "hash")) do
    throw s!"membership of {caps.length}: a different hash"
  pure s!"membership of {caps.length} read caps"

def readJoinReply (j : Json) : Except String JoinReply := do
  let members ← (← (← j.getObjVal? "members").getArr?).toList.mapM fun m => do
    match m with
    | .null => pure none
    | v => do
      let p ← v.getArr?
      pure (some (← hex (← p[0]!.getStr?), ← hex (← p[1]!.getStr?)))
  let rosters ← (← (← j.getObjVal? "rosters").getArr?).toList.mapM fun r => do
    match r with
    | .null => pure none
    | v => some <$> (← v.getArr?).toList.mapM fun e => do
      let p ← e.getArr?
      let slot ← match p[1]! with
        | .null => pure none
        | s => some <$> s.getNat?
      pure (← p[0]!.getNat?, slot)
  let introductions ← (← (← j.getObjVal? "introductions").getArr?).toList.mapM fun i => do
    let p ← i.getArr?
    pure (← p[0]!.getNat?, ← hex (← p[1]!.getStr?), ← p[2]!.getNat?)
  pure { members, rosters, introductions,
         introducer := ← (← j.getObjVal? "introducer").getNat?,
         newcomer := ← (← j.getObjVal? "newcomer").getNat? }

def reply (j : Json) : Except String String := do
  let name ← str j "name"
  let cbor ← hex (← str j "cbor")
  let some w := ReplyWho.decode cbor | throw s!"{name}: does not decode"
  unless ReplyWho.encode w == cbor do throw s!"{name}: encodes differently"
  unless ReplyWho.toJoinReply w == (← opt j "join_reply" readJoinReply) do
    throw s!"{name}: carries another JoinReply"
  pure s!"{name} (reply)"

def main : IO UInt32 := do
  let text ← IO.FS.readFile "testdata/groupchat_wire_vectors.json"
  let results ← IO.ofExcept do
    let j ← Json.parse text
    let run (key : String) (check : Json → Except String String) : Except String (List String) :=
      do (← (← j.getObjVal? key).getArr?).toList.mapM check
    pure ((← run "messages" message) ++ (← run "written" written)
      ++ (← run "membership" membership) ++ (← run "replies" reply))
  results.forM fun r => IO.println s!"ok   {r}"
  IO.println s!"{results.length} group chat wire vectors"
  pure 0

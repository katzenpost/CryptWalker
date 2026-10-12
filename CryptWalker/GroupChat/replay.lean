/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json

import CryptWalker.BACAP.API
import CryptWalker.GroupChat.Member.Json
import CryptWalker.Util.Bytes

/-! # Replaying katzenqt's group chat traces through the Lean member

Each trace, written by katzenqt's `groupchat/trace.py` from a simulator run, is one JSON line per
call made on a member. The replay makes the same call on the Lean `Group` of that member and
requires the same result and the same state afterwards. The Lean member is driven only by what
the trace says the Python member was given, so a difference means the two compute different
things from the same inputs.

The replay also checks what the trace says BACAP did, with CryptWalker's own BACAP: every index
given as the one after a box read, every run of indexes derived for a member's own stream, and
every walk a member asked for.

Usage: `lake exe CryptWalker.GroupChat.replay [trace.jsonl | dir]...`, by default every trace in
`testdata/groupchat_traces/`. -/

open Lean
open CryptWalker.GroupChat.Member
open CryptWalker.GroupChat.Member.Trace
open CryptWalker.BACAP.Types

/-- The index after `b`, by BACAP. -/
def step (b : ByteArray) : Option ByteArray := do
  if b.size ≠ MessageBoxIndexSize then none
  let n ← (unmarshalMessageBoxIndex (CryptWalker.Util.Bytes.toVecN _ b)).nextIndex
  pure (CryptWalker.Util.Bytes.ofVector (marshalMessageBoxIndex n))

/-- How far a walk steps a stream forward looking for an index, as katzenqt's simulator does. -/
def walkLimit : Nat := 256

/-- Step forward from `start` to the furthest of `targets` met within `walkLimit`, keeping the
last `keep` indexes passed (all of them for `keep = 0`, as Python's `[-0:]` does), and how many
steps it took. -/
def walk (start : ByteArray) (targets : List ByteArray) (keep : Nat) :
    Option (Option ByteArray × List ByteArray × Nat) := do
  let mut index := start
  let mut passed : Array ByteArray := #[]
  let mut found : Option (ByteArray × Nat) := none
  for _ in [0:walkLimit] do
    if targets.contains index then found := some (index, passed.size)
    passed := passed.push index
    index ← step index
  match found with
  | none => pure (none, [], 0)
  | some (t, n) =>
    let p := passed.toList.take n
    pure (some t, if keep = 0 then p else p.drop (n - keep), n)

/-- `count` indexes after `start`. -/
def derive (start : ByteArray) : Nat → Option (List ByteArray)
  | 0 => pure []
  | n + 1 => do
    let next ← step start
    pure (next :: (← derive next n))

/-- What a member has asked BACAP for and not yet been told. -/
structure Asked where
  derives : List (ByteArray × Nat) := []
  walks : List (ByteArray × ByteArray × List ByteArray × Nat) := []

/-- Check what the trace says BACAP did for this call against BACAP. Returns the number of checks
made, and what is still asked. -/
def checkBACAP (asked : Asked) (line : Json) (effects : List Effect) :
    Except String (Nat × Asked) := do
  let args ← field line "args"
  let mut asked := asked
  let mut checks := 0
  match (← field line "call").getStr? with
  | .ok "handle" =>
    match ← readEvent (← field args "event") with
    | .boxRead _ index _ (some next) =>
      checks := checks + 1
      unless step index = some next do throw "the index after a box read is not BACAP's"
    | .indexesDerived _ indexes =>
      match asked.derives with
      | (start, count) :: rest =>
        checks := checks + 1
        asked := { asked with derives := rest }
        unless derive start count = some indexes do throw "the indexes derived are not BACAP's"
      | [] => throw "indexes derived that were not asked for"
    | .walked stream target skipped steps =>
      match asked.walks.find? (·.1 = stream) with
      | some w@(_, start, targets, keep) =>
        checks := checks + 1
        asked := { asked with walks := asked.walks.erase w }
        unless walk start targets keep = some (target, skipped, steps) do
          throw "the walk's result is not BACAP's"
      | none => throw "a walk that was not asked for"
    | _ => pure ()
  | .ok "observe" =>
    checks := checks + 1
    unless step (← bytes (← field args "index")) = some (← bytes (← field args "next")) do
      throw "the index after an observed box is not BACAP's"
  | _ => pure ()
  for e in effects do
    match e with
    | .deriveIndexes _ start count => asked := { asked with derives := asked.derives ++ [(start, count)] }
    | .walk stream start targets keep =>
      asked := { asked with walks := asked.walks ++ [(stream, start, targets, keep)] }
    | _ => pure ()
  pure (checks, asked)

/-- Where two JSON values first differ, if they do. -/
partial def diff (path : String) (lean python : Json) : Option String :=
  match lean, python with
  | .obj a, .obj b =>
    let keys := (a.toArray.toList.map (·.1) ++ b.toArray.toList.map (·.1)).eraseDups
    keys.findSome? fun k => diff s!"{path}.{k}" (lean.getObjValD k) (python.getObjValD k)
  | .arr a, .arr b =>
    if a.size ≠ b.size then
      some s!"{path}: {a.size} items in Lean, {b.size} in Python\n  Lean   {lean.compress}\n  Python {python.compress}"
    else (List.range a.size).findSome? fun i => diff s!"{path}[{i}]" a[i]! b[i]!
  | a, b =>
    if a == b then none else some s!"{path}: Lean {a.compress}, Python {b.compress}"

/-- Make one recorded call on the member, returning what it returned. -/
def call (g : Option Group) (line : Json) : Parse (Json × List Effect × Group) := do
  let args ← field line "args"
  let arg := fun k => field args k
  let policy ← readRetention (← arg "policy")
  let recheck ← num (← arg "recheck")
  let name ← (← field line "call").getStr?
  match name, g with
  | "found", _ =>
    pure (.null, [], Group.found (← bytes (← arg "read_cap")) (← list bytes (← arg "founders")) policy recheck)
  | "joined", _ =>
    pure (.null, [], Group.joined (← bytes (← arg "read_cap")) (← readJoinReply (← arg "reply")) policy recheck)
  | _, none => throw s!"{name} before the member started"
  | "handle", some g =>
    let (es, g) := (Group.handle (← readEvent (← arg "event"))).run g
    pure (arr (es.map effect), es, g)
  | "observe", some g =>
    let (es, g) := (Group.observe (← bytes (← arg "stream")) (← bytes (← arg "index"))
      (← optional readMessage (← arg "message")) (← bytes (← arg "next"))).run g
    pure (arr (es.map effect), es, g)
  | "compose", some g =>
    let (os, g) := (Group.compose (← optional bytes (← arg "content"))).run g
    pure (arr (os.map outgoing), [], g)
  | "written", some g =>
    let ((), g) := (Group.written (← num (← arg "token")) (← bytes (← arg "index"))
      (← optional readMessage (← arg "message"))).run g
    pure (.null, [], g)
  | "abandoned", some g =>
    let ((), g) := (Group.abandoned (← num (← arg "token"))).run g
    pure (.null, [], g)
  | "begin_induction", some g =>
    let (os, g) := Group.beginInduction.run g
    pure (arr (os.map outgoing), [], g)
  | "introduce_now", some g =>
    let (o, g) := (Group.introduceNow (← (← arg "name").getStr?) (← bytes (← arg "read_cap"))).run g
    pure (outgoing o, [], g)
  | "cancel_induction", some g =>
    let ((), g) := Group.cancelInduction.run g
    pure (.null, [], g)
  | "reply", some g => pure (joinReply (g.reply (← bytes (← arg "own_start"))), [], g)
  | "remove", some g =>
    let ((), g) := (Group.remove (← bytes (← arg "member"))).run g
    pure (.null, [], g)
  | other, _ => throw s!"unknown call {other}"

/-- Replay one trace. Returns the number of calls replayed, of BACAP checks made, and the first
difference, if any. -/
def replay (path : System.FilePath) : IO (Nat × Nat × Option String) := do
  let mut members : List (String × Group × Asked) := []
  let mut n := 0
  let mut checks := 0
  for text in (← IO.FS.lines path) do
    if text.isEmpty then continue
    n := n + 1
    let fail := fun (what : String) => pure (n, checks, some s!"{path}:{n}: {what}")
    let line ← match Json.parse text with
      | .ok j => pure j
      | .error e => return ← fail s!"not JSON: {e}"
    let me := (line.getObjValD "me").getStr?.toOption.getD ""
    let who := (line.getObjValD "member").getStr?.toOption.getD me
    let callName := (line.getObjValD "call").getStr?.toOption.getD "?"
    let (g, asked) := match members.lookup me with
      | some (g, a) => (some g, a)
      | none => (none, {})
    match call g line with
    | .error e => return ← fail s!"{who} {callName}: {e}"
    | .ok (result, effects, g) =>
      if let some d := diff "result" result (line.getObjValD "result") then
        return ← fail s!"{who} {callName}: {d}"
      if let some d := diff "state" (group g) (line.getObjValD "state") then
        return ← fail s!"{who} {callName}: {d}"
      match checkBACAP asked line effects with
      | .error e => return ← fail s!"{who} {callName}: {e}"
      | .ok (c, asked) =>
        checks := checks + c
        members := (me, g, asked) :: members.filter (·.1 ≠ me)
  pure (n, checks, none)

def traces (args : List String) : IO (List System.FilePath) := do
  let roots := if args.isEmpty then ["testdata/groupchat_traces"] else args
  let mut out := []
  for root in roots do
    let p : System.FilePath := root
    if ← p.isDir then
      let entries ← p.readDir
      out := out ++ ((entries.map (·.path)).toList.filter (·.extension == some "jsonl")).mergeSort
        (fun a b => a.toString ≤ b.toString)
    else out := out ++ [p]
  pure out

def main (args : List String) : IO UInt32 := do
  let files ← traces args
  let mut calls := 0
  let mut checks := 0
  let mut failed := 0
  for f in files do
    let (n, c, d) ← replay f
    calls := calls + n
    checks := checks + c
    if let some d := d then
      failed := failed + 1
      IO.println d
  IO.println s!"{files.length} traces, {calls} calls, {checks} BACAP checks, {failed} with a difference"
  pure (if failed = 0 then 0 else 1)

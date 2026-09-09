/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.Sphinx.Commands
import CryptWalker.Util.newhex

/-!
# Sphinx routing-command wire-format known-answer tests

Checks `Commands.RoutingCommand.toBytes` against `testdata/sphinx_commands_vectors.json`
(`katzenpost/core/sphinx/commands/testdata/sphinx_commands_vectors.json`, vendored as-is — a
flat object, not the usual `{primitive, vectors: [...]}` envelope, since it comes straight from
`commands_vectors_test.go` rather than `testvectors/cmd/generate`), then round-trips each
through `fromBytesOne` to check parsing agrees. -/

open Lean
open CryptWalker.Util.newhex
open CryptWalker.Sphinx.Commands

def field (j : Json) (k : String) : Except String ByteArray := do
  let s ← (← j.getObjVal? k).getStr?
  match hexStringToByteArray s with
  | some b => pure b
  | none   => throw s!"field {k}: not valid hex: {s}"

def toVecN (n : Nat) (b : ByteArray) : Option (Vector UInt8 n) :=
  if h : b.data.size = n then some ⟨b.data, h⟩ else none

def check (label : String) (want got : ByteArray) : IO Bool := do
  let w := byteArrayToHex want
  let g := byteArrayToHex got
  if w == g then
    IO.println s!"  ok    {label}"
    pure true
  else
    IO.println s!"  FAIL  {label}"
    IO.println s!"          want {w}"
    IO.println s!"          got  {g}"
    pure false

def main : IO UInt32 := do
  let path := "testdata/sphinx_commands_vectors.json"
  let raw ← IO.FS.readFile path
  match Json.parse raw with
  | .error e => do IO.eprintln s!"failed to parse {path}: {e}"; pure 1
  | .ok j =>
    match (do
      let nextID ← field j "NextHopID"
      let nextMAC ← field j "NextHopMAC"
      let nextWant ← field j "NextHopCmdWant"
      let recipID ← field j "RecipientID"
      let recipWant ← field j "RecipientCmdWant"
      let surbID ← field j "SURBReplyID"
      let surbWant ← field j "SURBReplyCmdWant"
      let delay ← (← j.getObjVal? "NodeDelay").getNat?
      let delayWant ← field j "NodeDelayCmdWant"
      pure (nextID, nextMAC, nextWant, recipID, recipWant, surbID, surbWant, delay, delayWant)
      : Except String _) with
    | .error e => do IO.eprintln e; pure 1
    | .ok (nextID, nextMAC, nextWant, recipID, recipWant, surbID, surbWant, delay, delayWant) =>
      IO.println "Sphinx routing-command wire formats"
      let mut ok := true

      match toVecN 32 nextID, toVecN 32 nextMAC with
      | some idV, some macV =>
        let cmd := RoutingCommand.nextNodeHop idV macV
        ok := (← check "NextNodeHop.toBytes" nextWant cmd.toBytes) && ok
        match fromBytesOne cmd.toBytes with
        | .ok (some parsed, rest) =>
          ok := (parsed == cmd && rest.size == 0) && ok
          IO.println s!"  {if parsed == cmd && rest.size == 0 then "ok   " else "FAIL "} NextNodeHop round-trip"
        | _ => do IO.eprintln "  FAIL  NextNodeHop failed to parse back"; ok := false
      | _, _ => do IO.eprintln "NextHopID/MAC wrong length"; ok := false

      match toVecN 32 recipID with
      | some idV =>
        let cmd := RoutingCommand.recipient idV
        ok := (← check "Recipient.toBytes" recipWant cmd.toBytes) && ok
        match fromBytesOne cmd.toBytes with
        | .ok (some parsed, rest) =>
          ok := (parsed == cmd && rest.size == 0) && ok
          IO.println s!"  {if parsed == cmd && rest.size == 0 then "ok   " else "FAIL "} Recipient round-trip"
        | _ => do IO.eprintln "  FAIL  Recipient failed to parse back"; ok := false
      | _ => do IO.eprintln "RecipientID wrong length"; ok := false

      match toVecN 16 surbID with
      | some idV =>
        let cmd := RoutingCommand.surbReply idV
        ok := (← check "SURBReply.toBytes" surbWant cmd.toBytes) && ok
        match fromBytesOne cmd.toBytes with
        | .ok (some parsed, rest) =>
          ok := (parsed == cmd && rest.size == 0) && ok
          IO.println s!"  {if parsed == cmd && rest.size == 0 then "ok   " else "FAIL "} SURBReply round-trip"
        | _ => do IO.eprintln "  FAIL  SURBReply failed to parse back"; ok := false
      | _ => do IO.eprintln "SURBReplyID wrong length"; ok := false

      let cmd := RoutingCommand.nodeDelay (UInt32.ofNat delay)
      ok := (← check "NodeDelay.toBytes" delayWant cmd.toBytes) && ok
      match fromBytesOne cmd.toBytes with
      | .ok (some parsed, rest) =>
        ok := (parsed == cmd && rest.size == 0) && ok
        IO.println s!"  {if parsed == cmd && rest.size == 0 then "ok   " else "FAIL "} NodeDelay round-trip"
      | _ => do IO.eprintln "  FAIL  NodeDelay failed to parse back"; ok := false

      -- The terminal `null` command: no body, and `fromBytesOne` on an empty buffer agrees.
      let nullOk := RoutingCommand.null.toBytes.data == #[0x00] &&
        (match fromBytesOne ByteArray.empty with | .ok (none, _) => true | _ => false)
      ok := nullOk && ok
      IO.println s!"  {if nullOk then "ok   " else "FAIL "} null command"

      IO.println ""
      if ok then
        IO.println "all Sphinx routing-command vectors passed"
        pure 0
      else
        IO.eprintln "Sphinx routing-command vectors FAILED"
        pure 1

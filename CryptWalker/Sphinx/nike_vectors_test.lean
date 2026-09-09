/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.NikeSphinx
import CryptWalker.Sphinx.SURB
import CryptWalker.Util.newhex
import CryptWalker.Util.Bytes

/-!
# NIKE-Sphinx full-packet cross-implementation vectors

The payoff: `testdata/sphinx_nike_vectors.json` is
`katzenpost/core/sphinx/testdata/sphinx_vectors.json`, vendored as-is (`.sha256` records which
copy) — 10 real Sphinx packets `sphinx_vectors_test.go`'s `buildVectorSphinx` built with the
*Go* implementation (`withSURB ∈ {false, true} × nrHops 1..5`, geometry
`GeometryFromUserForwardPayloadLength(x25519, 103, withSURB, 5)`), each with every intermediate
`Unwrap` result recorded. This decodes `Packets[0]` and replays `unwrapNike` hop by hop,
checking that the forwarded packet at each step is *byte-identical* to Go's own `Packets[i+1]`,
and that the final payload (through `SURB.decryptSURBPayload` for the `withSURB` half) matches.
Nothing here was built by this Lean port — `unwrapNike` is the only thing on trial. -/

open Lean
open CryptWalker.Util.newhex
open CryptWalker.Sphinx.Geometry
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.NikeSphinx
open CryptWalker.Sphinx.SURB (decryptSURBPayload)
open CryptWalker.Util.Bytes (ofVector)

def field (j : Json) (k : String) : Except String ByteArray := do
  let s ← (← j.getObjVal? k).getStr?
  match hexStringToByteArray s with
  | some b => pure b
  | none   => throw s!"field {k}: not valid hex: {s}"

def strArr (j : Json) (k : String) : Except String (Array ByteArray) := do
  let arr ← (← j.getObjVal? k).getArr?
  arr.mapM fun s => do
    match hexStringToByteArray (← s.getStr?) with
    | some b => pure b
    | none   => throw s!"array element of {k}: not valid hex"

structure NodeParam where
  privateKey : Vector UInt8 32
  deriving Inhabited

structure PathHopHex where
  id : ByteArray
  deriving Inhabited

structure TestVec where
  nodes : Array NodeParam
  path : Array PathHopHex
  packets : Array ByteArray
  payload : ByteArray
  surb : ByteArray
  surbKeys : ByteArray
  deriving Inhabited

def toVec32 (b : ByteArray) : Option (Vector UInt8 32) :=
  if h : b.data.size = 32 then some ⟨b.data, h⟩ else none

def parseNode (j : Json) : Except String NodeParam := do
  let pk ← field j "PrivateKey"
  match toVec32 pk with
  | some v => pure { privateKey := v }
  | none   => throw "PrivateKey: not 32 bytes"

def parsePathHop (j : Json) : Except String PathHopHex := do
  pure { id := ← field j "ID" }

def parseVec (j : Json) : Except String TestVec := do
  let nodes ← (← (← j.getObjVal? "Nodes").getArr?).mapM parseNode
  let path ← (← (← j.getObjVal? "Path").getArr?).mapM parsePathHop
  let packets ← strArr j "Packets"
  let payload ← field j "Payload"
  let surb ← field j "Surb"
  let surbKeys ← field j "SurbKeys"
  pure { nodes, path, packets, payload, surb, surbKeys }

/-- Replay `unwrapNike` at every node, checking against the recorded `Packets`/`Payload`. -/
def runVec (geomNoSurb geomSurb : Geometry) (v : TestVec) : IO Bool := do
  let withSurb := decide (v.surb.size > 0)
  let geom := if withSurb then geomSurb else geomNoSurb
  let n := v.nodes.size
  let mut pkt := v.packets[0]!
  let mut ok := true
  let mut stop := false
  for i in [0:n] do
    if !stop then
      let node := v.nodes[i]!
      match unwrapNike geom node.privateKey pkt with
      | .error e =>
        IO.eprintln s!"    hop {i}: unwrap failed: {e}"
        ok := false; stop := true
      | .ok (payload, _replayTag, cmds, forwardPkt) =>
        if i < n - 1 then
          match forwardPkt with
          | none =>
            IO.eprintln s!"    hop {i}: expected forwarding, got terminal"
            ok := false; stop := true
          | some fwd =>
            let want := v.packets[i + 1]!
            if byteArrayToHex (ofVector fwd) ≠ byteArrayToHex want then
              IO.eprintln s!"    hop {i}: forwarded packet mismatch"
              ok := false
            if cmds.length ≠ 2 then
              IO.eprintln s!"    hop {i}: expected 2 commands, got {cmds.length}"
              ok := false
            let second : Option RoutingCommand := cmds[1]?
            match second with
            | some (RoutingCommand.nextNodeHop nextID _) =>
              if byteArrayToHex (ofVector nextID) ≠ byteArrayToHex v.path[i + 1]!.id then
                IO.eprintln s!"    hop {i}: NextNodeHop.ID mismatch"
                ok := false
            | _ =>
              IO.eprintln s!"    hop {i}: cmds[1] is not NextNodeHop"
              ok := false
            pkt := ofVector fwd
        else
          if withSurb then
            if cmds.length ≠ 2 then
              IO.eprintln s!"    hop {i}: SURB: expected 2 commands, got {cmds.length}"
              ok := false
            match payload with
            | none =>
              IO.eprintln s!"    hop {i}: expected terminal payload, got forwarding"
              ok := false
            | some p =>
              match decryptSURBPayload geom v.surbKeys p with
              | .error e =>
                IO.eprintln s!"    hop {i}: DecryptSURBPayload failed: {e}"
                ok := false
              | .ok final =>
                if byteArrayToHex final ≠ byteArrayToHex v.payload then
                  IO.eprintln s!"    hop {i}: SURB payload mismatch"
                  ok := false
          else
            if cmds.length ≠ 1 then
              IO.eprintln s!"    hop {i}: expected 1 command, got {cmds.length}"
              ok := false
            match payload with
            | none =>
              IO.eprintln s!"    hop {i}: expected terminal payload, got forwarding"
              ok := false
            | some p =>
              if byteArrayToHex p ≠ byteArrayToHex v.payload then
                IO.eprintln s!"    hop {i}: payload mismatch"
                ok := false
  pure ok

def main : IO UInt32 := do
  let path := "testdata/sphinx_nike_vectors.json"
  let raw ← IO.FS.readFile path
  match Json.parse raw with
  | .error e => do IO.eprintln s!"failed to parse {path}: {e}"; pure 1
  | .ok j =>
    match j.getArr? with
    | .error e => do IO.eprintln e; pure 1
    | .ok arr =>
      match arr.mapM parseVec with
      | .error e => do IO.eprintln e; pure 1
      | .ok vecs =>
        IO.println s!"NIKE-Sphinx full-packet vectors ({vecs.size} from katzenpost)"
        let geomNoSurb := ofNIKE 32 103 false 5
        let geomSurb := ofNIKE 32 103 true 5
        let mut ok := true
        for i in [0:vecs.size] do
          let v := vecs[i]!
          let withSurb := decide (v.surb.size > 0)
          let vecOk ← runVec geomNoSurb geomSurb v
          IO.println s!"  {if vecOk then "ok  " else "FAIL"}  {v.nodes.size} hop(s), withSurb={withSurb}"
          ok := ok && vecOk
        IO.println ""
        if ok then
          IO.println s!"all {vecs.size} NIKE-Sphinx vectors passed"
          pure 0
        else
          IO.eprintln "NIKE-Sphinx vectors FAILED"
          pure 1

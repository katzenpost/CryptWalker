/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Types
import CryptWalker.Sphinx.NikeSphinx
import CryptWalker.NIKE.X25519
import CryptWalker.Util.newhex

/-!
# NIKE-Sphinx create/unwrap round-trip self-test

`createHeader`'s exact output can't be cross-checked against Go (the client's ephemeral
randomness isn't recorded in katzenpost's vectors — see `NikeSphinx`'s module doc), so this
checks it the only way available: build a packet with fresh Lean-side keys, then `Unwrap` it
hop by hop with the system CSPRNG, and confirm the commands and final payload come back exactly
as built. `Crypto.aez_test`/`Crypto.test`/`commands_test` already pin every primitive this
exercises against Go; what's new here is that `createHeader`/`unwrapNike` compose them the same
way `sphinx.go` does.

Runs at several hop counts, all equal to the geometry's `nrHops` (so no filler padding is
needed), plus one round with `nrHops < geom.nrHops` to exercise the filler path. -/

open CryptWalker.Util.newhex
open CryptWalker.Sphinx.Geometry
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.NikeSphinx
open CryptWalker.NIKE.X25519 (curve25519 basepointBytes)

private def randomVector (n : Nat) : IO (Vector UInt8 n) := do
  let bs ← IO.getRandomBytes (USize.ofNat n)
  pure (Vector.ofFn fun i : Fin n => bs[i.val]!)

private def randomBytes (n : Nat) : IO ByteArray := IO.getRandomBytes (USize.ofNat n)

structure Node where
  id : Vector UInt8 32
  priv : Vector UInt8 32
  pub : Vector UInt8 32
  deriving Inhabited

private def newNode : IO Node := do
  let priv ← randomVector 32
  let id ← randomVector 32
  pure { id, priv, pub := curve25519 priv basepointBytes }

private def buildPath (nodes : Array Node) : IO (Array PathHop) := do
  let n := nodes.size
  let mut path : Array PathHop := #[]
  for i in [0:n] do
    let node := nodes[i]!
    let cmds : List RoutingCommand ←
      if i < n - 1 then
        pure [.nodeDelay (UInt32.ofNat (1000 + i))]
      else do
        let rid ← randomVector 32
        pure [.recipient rid]
    path := path.push { id := node.id, nikePublicKey := node.pub, commands := cmds }
  pure path

/-- Unwrap `pkt` at every node in order, checking forwarding commands and the final payload
against `wantPayload`. Returns whether every hop behaved as expected. -/
def unwrapAll (geom : Geometry) (nodes : Array Node) (pkt0 : ByteArray) (wantPayload : ByteArray) :
    IO Bool := do
  let n := nodes.size
  let mut pkt := pkt0
  let mut ok := true
  let mut stop := false
  for i in [0:n] do
    if !stop then
      let node := nodes[i]!
      match unwrapNike geom node.priv pkt with
      | .error e =>
        IO.eprintln s!"  hop {i}: unwrap failed: {e}"
        ok := false
        stop := true
      | .ok r =>
        if i < n - 1 then
          match r.forwardPkt with
          | none =>
            IO.eprintln s!"  hop {i}: expected forwarding, got terminal"
            ok := false; stop := true
          | some fwd =>
            if r.cmds.length ≠ 2 then
              IO.eprintln s!"  hop {i}: expected 2 commands, got {r.cmds.length}"
              ok := false
            pkt := fwd
        else
          match r.payload with
          | none =>
            IO.eprintln s!"  hop {i}: expected terminal payload, got forwarding"
            ok := false
          | some p =>
            if byteArrayToHex p ≠ byteArrayToHex wantPayload then
              IO.eprintln s!"  hop {i}: payload mismatch"
              IO.eprintln s!"    want {byteArrayToHex wantPayload}"
              IO.eprintln s!"    got  {byteArrayToHex p}"
              ok := false
            if r.cmds.length ≠ 1 then
              IO.eprintln s!"  hop {i}: expected 1 command, got {r.cmds.length}"
              ok := false
  pure ok

/-- One round: build an `nrHops`-hop path using all of `geom.nrHops`'s slots (so `filler` is
empty), send a random payload through it, and unwrap hop by hop. -/
def runRound (geom : Geometry) : IO Bool := do
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode)
  let path ← buildPath nodes
  let clientPriv ← randomVector 32
  let payload ← randomBytes geom.forwardPayloadLength
  match newNikePacket geom clientPriv ByteArray.empty path payload with
  | .error e =>
    IO.eprintln s!"newNikePacket failed: {e}"
    pure false
  | .ok pkt0 =>
    if pkt0.size ≠ geom.packetLength then
      IO.eprintln s!"packet length mismatch: got {pkt0.size}, want {geom.packetLength}"
      pure false
    else
      unwrapAll geom nodes pkt0 payload

/-- A round using only 3 of a 5-hop geometry's slots, so `createHeader` exercises the random
filler for the two skipped hops. -/
def runFillerRound : IO Bool := do
  let geom := ofNIKE 32 103 false 5
  let nodes ← (List.range 3).toArray.mapM (fun _ => newNode)
  let path ← buildPath nodes
  let clientPriv ← randomVector 32
  let payload ← randomBytes geom.forwardPayloadLength
  let filler ← randomBytes ((geom.nrHops - 3) * geom.perHopRoutingInfoLength)
  match newNikePacket geom clientPriv filler path payload with
  | .error e =>
    IO.eprintln s!"filler round: newNikePacket failed: {e}"
    pure false
  | .ok pkt0 => unwrapAll geom nodes pkt0 payload

def main : IO UInt32 := do
  let mut ok := true
  for nrHops in [1, 2, 3, 5] do
    let geom := ofNIKE 32 103 false nrHops
    let roundOk ← runRound geom
    IO.println s!"{nrHops} hop(s), no filler: {if roundOk then "ok" else "FAIL"}"
    ok := ok && roundOk

  let fillerOk ← runFillerRound
  IO.println s!"3 hop(s) of 5 (filler path): {if fillerOk then "ok" else "FAIL"}"
  ok := ok && fillerOk

  IO.println ""
  if ok then
    IO.println "all NIKE-Sphinx round-trip self-tests passed"
    pure 0
  else
    IO.eprintln "NIKE-Sphinx round-trip self-tests FAILED"
    pure 1

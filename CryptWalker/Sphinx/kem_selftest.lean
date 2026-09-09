/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Types
import CryptWalker.Sphinx.KemSphinx
import CryptWalker.NIKE.X25519
import CryptWalker.Util.newhex
import CryptWalker.Util.Bytes

/-!
# KEM-Sphinx create/unwrap round-trip self-test

As `NikeSphinx.nike_selftest`: `createKEMHeader`'s output can't be cross-checked against Go
(the per-hop KEM encapsulations aren't recorded anywhere), so this builds a packet with fresh
Lean-side keys and confirms `Unwrap` recovers exactly what was built.

A `kemX25519` keypair *is* an X25519 keypair (`Adapter.kemOfNike`'s `PublicKey`/`PrivateKey` are
`nike.PublicKey`/`nike.PrivateKey` verbatim), so node generation is identical to
`nike_selftest`'s. -/

open CryptWalker.Util.newhex
open CryptWalker.Sphinx.Geometry
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.KemSphinx
open CryptWalker.NIKE.X25519 (curve25519 basepointBytes)
open CryptWalker.Util.Bytes (ofVector)

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
    path := path.push { id := node.id, publicKey := node.pub, commands := cmds }
  pure path

def unwrapAll (geom : Geometry) (nodes : Array Node) (pkt0 : ByteArray) (wantPayload : ByteArray) :
    IO Bool := do
  let n := nodes.size
  let mut pkt := pkt0
  let mut ok := true
  let mut stop := false
  for i in [0:n] do
    if !stop then
      let node := nodes[i]!
      match unwrapKem geom node.priv pkt with
      | .error e =>
        IO.eprintln s!"  hop {i}: unwrap failed: {e}"
        ok := false
        stop := true
      | .ok (payload, _replayTag, cmds, forwardPkt) =>
        if i < n - 1 then
          match forwardPkt with
          | none =>
            IO.eprintln s!"  hop {i}: expected forwarding, got terminal"
            ok := false; stop := true
          | some fwd =>
            if cmds.length ≠ 2 then
              IO.eprintln s!"  hop {i}: expected 2 commands, got {cmds.length}"
              ok := false
            pkt := ofVector fwd
        else
          match payload with
          | none =>
            IO.eprintln s!"  hop {i}: expected terminal payload, got forwarding"
            ok := false
          | some p =>
            if byteArrayToHex p ≠ byteArrayToHex wantPayload then
              IO.eprintln s!"  hop {i}: payload mismatch"
              IO.eprintln s!"    want {byteArrayToHex wantPayload}"
              IO.eprintln s!"    got  {byteArrayToHex p}"
              ok := false
            if cmds.length ≠ 1 then
              IO.eprintln s!"  hop {i}: expected 1 command, got {cmds.length}"
              ok := false
  pure ok

def runRound (geom : Geometry) : IO Bool := do
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode)
  let path ← buildPath nodes
  let seeds ← nodes.mapM (fun _ => randomVector 32)
  let payload ← randomBytes geom.forwardPayloadLength
  match newKEMPacket geom seeds ByteArray.empty path payload with
  | .error e =>
    IO.eprintln s!"newKEMPacket failed: {e}"
    pure false
  | .ok pkt0 =>
    if pkt0.size ≠ geom.packetLength then
      IO.eprintln s!"packet length mismatch: got {pkt0.size}, want {geom.packetLength}"
      pure false
    else
      unwrapAll geom nodes pkt0 payload

def runFillerRound : IO Bool := do
  let geom := ofKEM 32 103 false 5
  let nodes ← (List.range 3).toArray.mapM (fun _ => newNode)
  let path ← buildPath nodes
  let seeds ← nodes.mapM (fun _ => randomVector 32)
  let payload ← randomBytes geom.forwardPayloadLength
  let filler ← randomBytes ((geom.nrHops - 3) * geom.perHopRoutingInfoLength)
  match newKEMPacket geom seeds filler path payload with
  | .error e =>
    IO.eprintln s!"filler round: newKEMPacket failed: {e}"
    pure false
  | .ok pkt0 => unwrapAll geom nodes pkt0 payload

def main : IO UInt32 := do
  let mut ok := true
  for nrHops in [1, 2, 3, 5] do
    let geom := ofKEM 32 103 false nrHops
    let roundOk ← runRound geom
    IO.println s!"{nrHops} hop(s), no filler: {if roundOk then "ok" else "FAIL"}"
    ok := ok && roundOk

  let fillerOk ← runFillerRound
  IO.println s!"3 hop(s) of 5 (filler path): {if fillerOk then "ok" else "FAIL"}"
  ok := ok && fillerOk

  IO.println ""
  if ok then
    IO.println "all KEM-Sphinx round-trip self-tests passed"
    pure 0
  else
    IO.eprintln "KEM-Sphinx round-trip self-tests FAILED"
    pure 1

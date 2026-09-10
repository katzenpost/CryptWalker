/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Types
import CryptWalker.Sphinx.KEMSphinx
import CryptWalker.Sphinx.SURB
import CryptWalker.NIKE.X25519_montgomery_ladder
import CryptWalker.Util.newhex
import CryptWalker.Util.Bytes

/-!
# KEM-Sphinx create/unwrap round-trip self-test

As `NIKESphinx.nike_selftest`: `createKEMHeader`'s output can't be cross-checked against Go
(the per-hop KEM encapsulations aren't recorded anywhere), so this builds a packet with fresh
Lean-side keys and confirms `Unwrap` recovers exactly what was built.

A `kemX25519` keypair *is* an X25519 keypair (`Adapter.kemOfNike`'s `PublicKey`/`PrivateKey` are
`nike.PublicKey`/`nike.PrivateKey` verbatim), so node generation is identical to
`nike_selftest`'s. -/

open CryptWalker.Util.newhex
open CryptWalker.Sphinx.Geometry
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.KEMSphinx
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

private def buildPath (nodes : Array Node) (isSURB : Bool := false) : IO (Array PathHop) := do
  let n := nodes.size
  let mut path : Array PathHop := #[]
  for i in [0:n] do
    let node := nodes[i]!
    let cmds : List RoutingCommand ←
      if i < n - 1 then
        pure [.nodeDelay (UInt32.ofNat (1000 + i))]
      else do
        let rid ← randomVector 32
        if isSURB then
          let sid ← randomVector 16
          pure [.recipient rid, .surbReply sid]
        else
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
      match unwrapKEM geom node.priv pkt with
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

/-- The same round as `runRound`, but driven through `Sphinx.Sphinx.wrap`/`KEMSphinxScheme`
instead of calling `newKEMPacket` directly. `wrapKEM` draws one seed *per hop*, so the stream
must actually vary with the counter — unlike `NIKESphinx`'s version of this check, which draws
only one seed total and can get away with a constant stream. -/
def runAbstractWrapRound (geom : Geometry) : IO Bool := do
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode)
  let path ← buildPath nodes
  let seeds ← nodes.mapM (fun _ => randomVector 32)
  let payload ← randomVector geom.forwardPayloadLength
  let scheme := KEMSphinxScheme geom
  let stream := fun i => seeds[i]!
  match scheme.wrap path.toList ByteArray.empty payload (CryptWalker.Sphinx.Sphinx.initWith stream) with
  | .error e _ =>
    IO.eprintln s!"abstract wrap failed: {e}"
    pure false
  | .ok pkt _ => unwrapAll geom nodes (ofVector pkt) (ofVector payload)

/-- As `NIKESphinx.nike_selftest`'s: empirical check of `Sphinx.Sphinx.unwrap_complete` (the
property `wrapKEM_unwrapKEM_complete` axiomatizes). -/
def runCompletenessRound (geom : Geometry) : IO Bool := do
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode)
  let path ← buildPath nodes
  let seeds ← nodes.mapM (fun _ => randomVector 32)
  let payload ← randomVector geom.forwardPayloadLength
  let scheme := KEMSphinxScheme geom
  let stream := fun i => seeds[i]!
  match scheme.wrap path.toList ByteArray.empty payload (CryptWalker.Sphinx.Sphinx.initWith stream) with
  | .error e _ =>
    IO.eprintln s!"completeness: wrap failed: {e}"
    pure false
  | .ok pkt _ =>
    let privKeys := (nodes.map (·.priv)).toList
    match CryptWalker.Sphinx.Sphinx.unwrapChainAux (unwrapKEM geom) privKeys (ofVector pkt) with
    | .error e =>
      IO.eprintln s!"completeness: unwrapChainAux failed: {e}"
      pure false
    | .ok none =>
      IO.eprintln "completeness: unwrapChainAux returned no payload"
      pure false
    | .ok (some p) =>
      if byteArrayToHex p ≠ byteArrayToHex (ofVector payload) then
        IO.eprintln "completeness: payload mismatch"
        pure false
      else
        pure true

/-- As `runAbstractWrapRound`, over `newSURB`/`newPacketFromSURB` — confirms those two fields
round-trip through `unwrapKEM`/`SURB.decryptSURBPayload`. `wrapKEMSURB` draws one seed per hop
plus two more (`keyPayload`), so the stream needs `nodes.size + 2` distinct entries. -/
def runAbstractSURBRound (geom : Geometry) : IO Bool := do
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode)
  let path ← buildPath nodes true
  let seeds ← (List.range (nodes.size + 2)).toArray.mapM (fun _ => randomVector 32)
  let scheme := KEMSphinxScheme geom
  let stream := fun i => seeds[i]!
  match scheme.newSURB path.toList ByteArray.empty (CryptWalker.Sphinx.Sphinx.initWith stream) with
  | .error e _ =>
    IO.eprintln s!"abstract newSURB failed: {e}"
    pure false
  | .ok (surb, surbKeys) _ =>
    let payload ← randomBytes geom.forwardPayloadLength
    match scheme.newPacketFromSURB surb payload with
    | .error e =>
      IO.eprintln s!"abstract newPacketFromSURB failed: {e}"
      pure false
    | .ok (pkt0, firstHopID) =>
      if byteArrayToHex (ofVector firstHopID) ≠ byteArrayToHex (ofVector nodes[0]!.id) then
        IO.eprintln "first-hop ID mismatch"
        pure false
      else do
      let mut pkt := pkt0
      let mut ok := true
      let mut stop := false
      let n := nodes.size
      for i in [0:n] do
        if !stop then
          let node := nodes[i]!
          match unwrapKEM geom node.priv pkt with
          | .error e =>
            IO.eprintln s!"hop {i}: unwrap failed: {e}"
            ok := false; stop := true
          | .ok (respPayload, _replayTag, _cmds, forwardPkt) =>
            if i < n - 1 then
              match forwardPkt with
              | none =>
                IO.eprintln s!"hop {i}: expected forwarding"
                ok := false; stop := true
              | some fwd => pkt := ofVector fwd
            else
              match respPayload with
              | none =>
                IO.eprintln s!"hop {i}: expected terminal payload"
                ok := false
              | some p =>
                match CryptWalker.Sphinx.SURB.decryptSURBPayload geom surbKeys p with
                | .error e =>
                  IO.eprintln s!"decryptSURBPayload failed: {e}"
                  ok := false
                | .ok final =>
                  if byteArrayToHex final ≠ byteArrayToHex payload then
                    IO.eprintln "SURB payload mismatch"
                    ok := false
      pure ok

/-- Full SURB round trip, as `NIKESphinx.nike_selftest`'s: build a SURB (`newKEMSURB`), use it
to build a reply packet (`SURB.newPacketFromSURB`), unwrap that reply through every hop, and
confirm `SURB.decryptSURBPayload` recovers the original payload. -/
def runSURBRound (geom : Geometry) : IO Bool := do
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode)
  let path ← buildPath nodes true
  let seeds ← nodes.mapM (fun _ => randomVector 32)
  let kp1 ← randomVector 32
  let kp2 ← randomVector 32
  match newKEMSURB geom seeds (kp1 ++ kp2) ByteArray.empty path with
  | .error e =>
    IO.eprintln s!"newKEMSURB failed: {e}"
    pure false
  | .ok (surb, surbKeys) =>
    if surb.size ≠ geom.surbLength then
      IO.eprintln s!"SURB length mismatch: got {surb.size}, want {geom.surbLength}"
      pure false
    else
    let payload ← randomBytes geom.forwardPayloadLength
    match CryptWalker.Sphinx.SURB.newPacketFromSURB geom surb payload with
    | .error e =>
      IO.eprintln s!"newPacketFromSURB failed: {e}"
      pure false
    | .ok (pkt0, firstHopID) =>
      if byteArrayToHex (ofVector firstHopID) ≠ byteArrayToHex (ofVector nodes[0]!.id) then
        IO.eprintln "first-hop ID mismatch"
        pure false
      else do
      let mut pkt := pkt0
      let mut ok := true
      let mut stop := false
      let n := nodes.size
      for i in [0:n] do
        if !stop then
          let node := nodes[i]!
          match unwrapKEM geom node.priv pkt with
          | .error e =>
            IO.eprintln s!"hop {i}: unwrap failed: {e}"
            ok := false; stop := true
          | .ok (respPayload, _replayTag, cmds, forwardPkt) =>
            if i < n - 1 then
              match forwardPkt with
              | none =>
                IO.eprintln s!"hop {i}: expected forwarding"
                ok := false; stop := true
              | some fwd => pkt := ofVector fwd
            else
              if cmds.length ≠ 2 then
                IO.eprintln s!"hop {i}: expected 2 commands, got {cmds.length}"
                ok := false
              match respPayload with
              | none =>
                IO.eprintln s!"hop {i}: expected terminal payload"
                ok := false
              | some p =>
                match CryptWalker.Sphinx.SURB.decryptSURBPayload geom surbKeys p with
                | .error e =>
                  IO.eprintln s!"decryptSURBPayload failed: {e}"
                  ok := false
                | .ok final =>
                  if byteArrayToHex final ≠ byteArrayToHex payload then
                    IO.eprintln "SURB payload mismatch"
                    ok := false
      pure ok

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

  let abstractOk ← runAbstractWrapRound (ofKEM 32 103 false 3)
  IO.println s!"abstract Sphinx.Sphinx.wrap (3 hops): {if abstractOk then "ok" else "FAIL"}"
  ok := ok && abstractOk

  let completeOk ← runCompletenessRound (ofKEM 32 103 false 3)
  IO.println s!"Sphinx.Sphinx.unwrap_complete via unwrapChainAux (3 hops): {if completeOk then "ok" else "FAIL"}"
  ok := ok && completeOk

  let abstractSurbOk ← runAbstractSURBRound (ofKEM 32 103 true 3)
  IO.println s!"abstract Sphinx.Sphinx.newSURB/newPacketFromSURB (3 hops): {if abstractSurbOk then "ok" else "FAIL"}"
  ok := ok && abstractSurbOk

  for nrHops in [1, 2, 3, 5] do
    let geom := ofKEM 32 103 true nrHops
    let surbOk ← runSURBRound geom
    IO.println s!"SURB round trip ({nrHops} hop(s)): {if surbOk then "ok" else "FAIL"}"
    ok := ok && surbOk

  IO.println ""
  if ok then
    IO.println "all KEM-Sphinx round-trip self-tests passed"
    pure 0
  else
    IO.eprintln "KEM-Sphinx round-trip self-tests FAILED"
    pure 1

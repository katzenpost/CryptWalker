/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Types
import CryptWalker.Sphinx.NikeSphinx
import CryptWalker.Sphinx.SURB
import CryptWalker.NIKE.X25519
import CryptWalker.Util.newhex
import CryptWalker.Util.Bytes

/-!
# NIKE-Sphinx packet-creation vectors, for cross-checking against Go

The reverse direction of `nike_vectors_test`: that file replays *Go*-built packets through
`unwrapNike`, checking the Lean port's unwrap side against real output. Nothing checks the
creation side (`createHeader`/`newNikePacket`/`newNikeSURB`) against an independent
implementation — `nike_selftest` only confirms Lean agrees with itself. This builds packets with
the Lean port's creation side and writes them out in the same `hexSphinxTest` JSON shape
`sphinx_vectors_test.go` uses (`Nodes`/`Path`/`Packets`/`Payload`/`Surb`/`SurbKeys`, all hex), so
they can be vendored into katzenpost and unwrapped there — the same `withSURB ∈ {false,true} ×
nrHops 1..5` matrix, geometry `GeometryFromUserForwardPayloadLength(x25519, 103, withSURB, 5)`. -/

open Lean
open CryptWalker.Util.newhex
open CryptWalker.Sphinx.Geometry
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.NikeSphinx
open CryptWalker.Sphinx.SURB (decryptSURBPayload newPacketFromSURB)
open CryptWalker.NIKE.X25519 (curve25519 basepointBytes)
open CryptWalker.Util.Bytes (ofVector)

private def randomVector (n : Nat) : IO (Vector UInt8 n) := do
  let bs ← IO.getRandomBytes (USize.ofNat n)
  pure (Vector.ofFn fun i : Fin n => bs[i.val]!)

private def randomBytes (n : Nat) : IO ByteArray := IO.getRandomBytes (USize.ofNat n)

private structure Node where
  id : Vector UInt8 32
  priv : Vector UInt8 32
  pub : Vector UInt8 32
  deriving Inhabited

private def newNode : IO Node := do
  let priv ← randomVector 32
  let id ← randomVector 32
  pure { id, priv, pub := curve25519 priv basepointBytes }

private def buildPath (nodes : Array Node) (isSURB : Bool) : IO (Array PathHop) := do
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

private def hexNode (n : Node) : Json :=
  Json.mkObj [("ID", Json.str (byteArrayToHex (ofVector n.id))),
              ("PrivateKey", Json.str (byteArrayToHex (ofVector n.priv)))]

private def hexPathHop (h : PathHop) : Json :=
  Json.mkObj [("ID", Json.str (byteArrayToHex (ofVector h.id))),
              ("PublicKey", Json.str (byteArrayToHex (ofVector h.publicKey))),
              ("Commands", Json.arr (h.commands.toArray.map (fun c => Json.str (byteArrayToHex c.toBytes))))]

/-- One vector entry: create a path of `nrHops` hops (out of `geom.nrHops` slots) and, for
`withSURB`, a SURB and a reply packet built from it; then unwrap hop by hop, recording the
packet chain and final payload exactly as `buildVectorSphinx` does — so a consumer needs no
Lean-side trust, only `Unwrap`/`DecryptSURBPayload`. -/
def buildVec (geom : Geometry) (withSURB : Bool) (nrHops : Nat) : IO Json := do
  let nodes ← (List.range nrHops).toArray.mapM (fun _ => newNode)
  let path ← buildPath nodes withSURB
  let payload ← randomBytes geom.userForwardPayloadLength
  let filler ← randomBytes ((geom.nrHops - nrHops) * geom.perHopRoutingInfoLength)
  let mut surb : ByteArray := ByteArray.empty
  let mut surbKeys : ByteArray := ByteArray.empty
  let mut pkt0 : ByteArray := ByteArray.empty
  if withSURB then
    let clientSeed ← randomVector 32
    let kp1 ← randomVector 32
    let kp2 ← randomVector 32
    match newNikeSURB geom clientSeed (kp1 ++ kp2) filler path with
    | .error e => throw (IO.userError s!"newNikeSURB failed: {e}")
    | .ok (s, k) =>
      surb := s; surbKeys := k
      match newPacketFromSURB geom surb payload with
      | .error e => throw (IO.userError s!"newPacketFromSURB failed: {e}")
      | .ok (p, firstHop) =>
        if byteArrayToHex (ofVector firstHop) ≠ byteArrayToHex (ofVector nodes[0]!.id) then
          throw (IO.userError "first-hop ID mismatch")
        pkt0 := p
  else
    let clientPriv ← randomVector 32
    match newNikePacket geom clientPriv filler path payload with
    | .error e => throw (IO.userError s!"newNikePacket failed: {e}")
    | .ok p => pkt0 := p

  let mut packets : Array ByteArray := #[pkt0]
  let mut pkt := pkt0
  let mut finalPayload : ByteArray := ByteArray.empty
  for i in [0:nrHops] do
    let node := nodes[i]!
    match unwrapNike geom node.priv pkt with
    | .error e => throw (IO.userError s!"hop {i}: unwrap failed: {e}")
    | .ok (payloadOut, _replayTag, _cmds, forwardPkt) =>
      if i < nrHops - 1 then
        match forwardPkt with
        | none => throw (IO.userError s!"hop {i}: expected forwarding")
        | some fwd => pkt := ofVector fwd; packets := packets.push pkt
      else
        match payloadOut with
        | none => throw (IO.userError s!"hop {i}: expected terminal payload")
        | some p =>
          if withSURB then
            match decryptSURBPayload geom surbKeys p with
            | .error e => throw (IO.userError s!"decryptSURBPayload failed: {e}")
            | .ok final => finalPayload := final
          else
            finalPayload := p

  if byteArrayToHex finalPayload ≠ byteArrayToHex payload then
    throw (IO.userError "final payload mismatch")

  pure (Json.mkObj [
    ("Nodes", Json.arr (nodes.map hexNode)),
    ("Path", Json.arr (path.map hexPathHop)),
    ("Packets", Json.arr (packets.map (fun p => Json.str (byteArrayToHex p)))),
    ("Payload", Json.str (byteArrayToHex payload)),
    ("Surb", Json.str (byteArrayToHex surb)),
    ("SurbKeys", Json.str (byteArrayToHex surbKeys))])

def main : IO UInt32 := do
  let mut vecs : Array Json := #[]
  for withSURB in [false, true] do
    let geom := ofNIKE 32 103 withSURB 5
    for nrHops in [1, 2, 3, 4, 5] do
      let v ← buildVec geom withSURB nrHops
      vecs := vecs.push v
      IO.println s!"built withSURB={withSURB} nrHops={nrHops}"
  let out := (Json.arr vecs).pretty
  let outPath := "testdata/lean_nike_vectors.json"
  IO.FS.writeFile outPath out
  IO.println s!"wrote {outPath}"
  pure 0

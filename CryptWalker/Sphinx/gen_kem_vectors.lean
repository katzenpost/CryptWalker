/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Types
import CryptWalker.Sphinx.KEMSphinx
import CryptWalker.Sphinx.SURB
import CryptWalker.NIKE.X25519
import CryptWalker.Util.newhex
import CryptWalker.Util.Bytes

/-!
# KEM-Sphinx packet-creation vectors, for cross-checking against Go

As `gen_nike_vectors`: builds packets with the Lean port's creation side
(`createKEMHeader`/`newKEMPacket`/`newKEMSURB`) and writes them out in the same `hexSphinxTest`
JSON shape `generate_kem/main.go` uses, so katzenpost's own `Unwrap` can check them. A
`kemX25519` keypair *is* an X25519 keypair, so node generation is identical to
`gen_nike_vectors`'s. -/

open Lean
open CryptWalker.Util.newhex
open CryptWalker.Sphinx.Geometry
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.KEMSphinx
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

/-- As `gen_nike_vectors.buildVec`, over `createKEMHeader`/`newKEMPacket`/`newKEMSURB`: one
ephemeral seed per hop instead of one client private key. -/
def buildVec (geom : Geometry) (withSURB : Bool) (nrHops : Nat) : IO Json := do
  let nodes ← (List.range nrHops).toArray.mapM (fun _ => newNode)
  let path ← buildPath nodes withSURB
  let payload ← randomBytes geom.userForwardPayloadLength
  let filler ← randomBytes ((geom.nrHops - nrHops) * geom.perHopRoutingInfoLength)
  let seeds ← nodes.mapM (fun _ => randomVector 32)
  let mut surb : ByteArray := ByteArray.empty
  let mut surbKeys : ByteArray := ByteArray.empty
  let mut pkt0 : ByteArray := ByteArray.empty
  if withSURB then
    let kp1 ← randomVector 32
    let kp2 ← randomVector 32
    match newKEMSURB geom seeds (kp1 ++ kp2) filler path with
    | .error e => throw (IO.userError s!"newKEMSURB failed: {e}")
    | .ok (s, k) =>
      surb := s; surbKeys := k
      match newPacketFromSURB geom surb payload with
      | .error e => throw (IO.userError s!"newPacketFromSURB failed: {e}")
      | .ok (p, firstHop) =>
        if byteArrayToHex (ofVector firstHop) ≠ byteArrayToHex (ofVector nodes[0]!.id) then
          throw (IO.userError "first-hop ID mismatch")
        pkt0 := p
  else
    match newKEMPacket geom seeds filler path payload with
    | .error e => throw (IO.userError s!"newKEMPacket failed: {e}")
    | .ok p => pkt0 := p

  let mut packets : Array ByteArray := #[pkt0]
  let mut pkt := pkt0
  let mut finalPayload : ByteArray := ByteArray.empty
  for i in [0:nrHops] do
    let node := nodes[i]!
    match unwrapKEM geom node.priv pkt with
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
    let geom := ofKEM 32 103 withSURB 5
    for nrHops in [1, 2, 3, 4, 5] do
      let v ← buildVec geom withSURB nrHops
      vecs := vecs.push v
      IO.println s!"built withSURB={withSURB} nrHops={nrHops}"
  let out := (Json.arr vecs).pretty
  let outPath := "testdata/lean_kem_vectors.json"
  IO.FS.writeFile outPath out
  IO.println s!"wrote {outPath}"
  pure 0

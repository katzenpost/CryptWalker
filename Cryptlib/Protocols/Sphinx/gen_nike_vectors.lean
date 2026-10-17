/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import Cryptlib.Protocols.Sphinx.geometry
import Cryptlib.Protocols.Sphinx.types
import Cryptlib.Protocols.Sphinx.nike_sphinx_theorems
import Cryptlib.Protocols.Sphinx.surb
import Cryptlib.Primitives.NIKE.X25519_montgomery_ladder
import Cryptlib.Util.newhex
import Cryptlib.Util.Bytes

/-!
# NIKE-Sphinx packet-creation vectors

Builds packets with `createHeader`/`newNIKEPacket`/`newNIKESURB` and writes them as JSON for
unwrapping by another implementation, over `withSURB ∈ {false,true} × nrHops 1..5`. -/

open Lean
open Cryptlib.Util.newhex
open Cryptlib.Protocols.Sphinx.Geometry
open Cryptlib.Protocols.Sphinx.Commands
open Cryptlib.Protocols.Sphinx.Types
open Cryptlib.Protocols.Sphinx.NIKESphinx
open Cryptlib.Protocols.Sphinx.SURB (decryptSURBPayload newPacketFromSURB)
open Cryptlib.Primitives.NIKE.X25519_montgomery_ladder (curve25519 basepointBytes)
open Cryptlib.Util.Bytes (ofVector)

private def x25519Nike := Cryptlib.Primitives.NIKE.X25519_montgomery_ladder.LadderScheme

private def wbCipher := Cryptlib.Primitives.WideBlockCipher.AEZ.aez
private def macS := Cryptlib.Primitives.MAC.HMAC.hmacSha256MAC
private def kdfS := Cryptlib.Primitives.KDF.HKDF.hkdfSha256Expand
private def streamS := Cryptlib.Primitives.StreamCipher.AES256CTR.aes256CTR

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
    path := path.push { id := node.id, publicKey := ofVector node.pub, commands := cmds }
  pure path

private def hexNode (n : Node) : Json :=
  Json.mkObj [("ID", Json.str (byteArrayToHex (ofVector n.id))),
              ("PrivateKey", Json.str (byteArrayToHex (ofVector n.priv)))]

private def hexPathHop (h : PathHop) : Json :=
  Json.mkObj [("ID", Json.str (byteArrayToHex (ofVector h.id))),
              ("PublicKey", Json.str (byteArrayToHex h.publicKey)),
              ("Commands", Json.arr (h.commands.toArray.map (fun c => Json.str (byteArrayToHex c.toBytes))))]

/-- One vector: build an `nrHops`-hop packet (and, for `withSURB`, a SURB and reply packet), then
unwrap hop by hop, recording every intermediate packet and the final payload. -/
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
    match newNIKESURB x25519Nike macS kdfS streamS geom (ofVector clientSeed) (kp1 ++ kp2) filler path with
    | .error e => throw (IO.userError s!"newNIKESURB failed: {e}")
    | .ok (s, k) =>
      surb := s; surbKeys := k
      match newPacketFromSURB wbCipher geom surb payload with
      | .error e => throw (IO.userError s!"newPacketFromSURB failed: {e}")
      | .ok (p, firstHop) =>
        if byteArrayToHex (ofVector firstHop) ≠ byteArrayToHex (ofVector nodes[0]!.id) then
          throw (IO.userError "first-hop ID mismatch")
        pkt0 := p
  else
    let clientPriv ← randomVector 32
    match newNIKEPacket x25519Nike wbCipher macS kdfS streamS geom (ofVector clientPriv) filler path payload with
    | .error e => throw (IO.userError s!"newNIKEPacket failed: {e}")
    | .ok p => pkt0 := p

  let mut packets : Array ByteArray := #[pkt0]
  let mut pkt := pkt0
  let mut finalPayload : ByteArray := ByteArray.empty
  for i in [0:nrHops] do
    let node := nodes[i]!
    match unwrapNIKE x25519Nike wbCipher macS kdfS streamS geom (ofVector node.priv) pkt with
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
            match decryptSURBPayload wbCipher geom surbKeys p with
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
    let geom ← IO.ofExcept (ofNIKE "x25519-ladder" 103 withSURB 5)
    for nrHops in [1, 2, 3, 4, 5] do
      let v ← buildVec geom withSURB nrHops
      vecs := vecs.push v
      IO.println s!"built withSURB={withSURB} nrHops={nrHops}"
  let out := (Json.arr vecs).pretty
  let outPath := "testdata/lean_nike_vectors.json"
  IO.FS.writeFile outPath out
  IO.println s!"wrote {outPath}"
  pure 0

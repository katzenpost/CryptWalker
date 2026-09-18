/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.Sphinx.geometry
import CryptWalker.Sphinx.types
import CryptWalker.Sphinx.kem_sphinx_theorems
import CryptWalker.Sphinx.surb
import CryptWalker.Util.newhex
import CryptWalker.Util.Bytes

/-!
# KEM-Sphinx packet-creation vectors, for cross-checking against Go

As `gen_nike_vectors`: builds packets with the Lean port's creation side
(`createKEMHeader`/`newKEMPacket`/`newKEMSURB`) and writes them out in the same `hexSphinxTest`
JSON shape `generate_kem/main.go` (and `generate_kem_hybrid/main.go`) use, so katzenpost's own
`Unwrap` can check them.

Generic over `kem : KEM` (`Node.priv`/`pub` are `ByteArray`, not a fixed `Vector UInt8 32`, since
that's only true for X25519 -- the hybrid's private key is 1280 bytes), unlike this file's earlier
X25519-only version: node keys now come from `kem.generate`, matching `kem_selftest.lean`'s
generalization (not raw scalar bytes, which only happens to double as a valid key for a
Diffie-Hellman KEM). Runs once for `x25519-ladder-kem` (output unchanged, so katzenpost's existing
checker needs no changes) and once for `mlkem768-x25519-kem` (new output file). -/

open Lean
open CryptWalker.Util.newhex
open CryptWalker.Sphinx.Geometry
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.KEMSphinx
open CryptWalker.Sphinx.SURB (decryptSURBPayload newPacketFromSURB)
open CryptWalker.KEM.KEM (KEM)
open CryptWalker.Util.Bytes (ofVector)

private def wbCipher := CryptWalker.WideBlockCipher.AEZ.aez
private def macS := CryptWalker.MAC.HMAC.hmacSha256MAC
private def kdfS := CryptWalker.KDF.HKDF.hkdfSha256Expand
private def streamS := CryptWalker.StreamCipher.AES256CTR.aes256CTR

private def randomVector (n : Nat) : IO (Vector UInt8 n) := do
  let bs ← IO.getRandomBytes (USize.ofNat n)
  pure (Vector.ofFn fun i : Fin n => bs[i.val]!)

private def randomBytes (n : Nat) : IO ByteArray := IO.getRandomBytes (USize.ofNat n)

private structure Node where
  id : Vector UInt8 32
  priv : ByteArray
  pub : ByteArray
  deriving Inhabited

private def newNode (kem : KEM) : IO Node := do
  let seed ← randomVector 32
  let id ← randomVector 32
  match kem.generate (kem.stateFromSeed seed) with
  | .error _ _ => throw (IO.userError "newNode: kem.generate failed")
  | .ok ⟨pk, sk, _⟩ _ =>
    pure { id, priv := ofVector (kem.encodePrivateKey sk), pub := ofVector (kem.encodePublicKey pk) }

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
              ("PrivateKey", Json.str (byteArrayToHex n.priv))]

private def hexPathHop (h : PathHop) : Json :=
  Json.mkObj [("ID", Json.str (byteArrayToHex (ofVector h.id))),
              ("PublicKey", Json.str (byteArrayToHex h.publicKey)),
              ("Commands", Json.arr (h.commands.toArray.map (fun c => Json.str (byteArrayToHex c.toBytes))))]

/-- As `gen_nike_vectors.buildVec`, over `createKEMHeader`/`newKEMPacket`/`newKEMSURB`: one
ephemeral seed per hop instead of one client private key. -/
def buildVec (kem : KEM) (geom : Geometry) (withSURB : Bool) (nrHops : Nat) : IO Json := do
  let nodes ← (List.range nrHops).toArray.mapM (fun _ => newNode kem)
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
    match newKEMSURB kem macS kdfS streamS geom seeds (kp1 ++ kp2) filler path with
    | .error e => throw (IO.userError s!"newKEMSURB failed: {e}")
    | .ok (s, k) =>
      surb := s; surbKeys := k
      match newPacketFromSURB wbCipher geom surb payload with
      | .error e => throw (IO.userError s!"newPacketFromSURB failed: {e}")
      | .ok (p, firstHop) =>
        if byteArrayToHex (ofVector firstHop) ≠ byteArrayToHex (ofVector nodes[0]!.id) then
          throw (IO.userError "first-hop ID mismatch")
        pkt0 := p
  else
    match newKEMPacket kem wbCipher macS kdfS streamS geom seeds filler path payload with
    | .error e => throw (IO.userError s!"newKEMPacket failed: {e}")
    | .ok p => pkt0 := p

  let mut packets : Array ByteArray := #[pkt0]
  let mut pkt := pkt0
  let mut finalPayload : ByteArray := ByteArray.empty
  for i in [0:nrHops] do
    let node := nodes[i]!
    match unwrapKEM kem wbCipher macS kdfS streamS geom node.priv pkt with
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

def runGen (schemeName : String) (kem : KEM) (outPath : String) : IO Unit := do
  let mut vecs : Array Json := #[]
  for withSURB in [false, true] do
    let geom ← IO.ofExcept (ofKEM schemeName 103 withSURB 5)
    for nrHops in [1, 2, 3, 4, 5] do
      let v ← buildVec kem geom withSURB nrHops
      vecs := vecs.push v
      IO.println s!"{schemeName}: built withSURB={withSURB} nrHops={nrHops}"
  let out := (Json.arr vecs).pretty
  IO.FS.writeFile outPath out
  IO.println s!"wrote {outPath}"

def main : IO UInt32 := do
  runGen "x25519-ladder-kem" CryptWalker.KEM.kemX25519Ladder "testdata/lean_kem_vectors.json"
  runGen "mlkem768-x25519-kem" CryptWalker.KEM.kemMLKEM768X25519
    "testdata/lean_kem_hybrid_vectors.json"
  pure 0

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.geometry
import CryptWalker.Sphinx.types
import CryptWalker.Sphinx.kem_sphinx_theorems
import CryptWalker.Sphinx.surb
import CryptWalker.Util.newhex
import CryptWalker.Util.Bytes

/-!
# KEM-Sphinx create/unwrap round-trip self-test

Builds packets with fresh keys and checks that unwrapping recovers them, for every registered
KEM-Sphinx scheme. -/

open CryptWalker.Util.newhex
open CryptWalker.Sphinx.Geometry
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.KEMSphinx
open CryptWalker.KEM.KEM (KEM)
open CryptWalker.Util.Bytes (ofVector)

private def x25519Ladder := CryptWalker.KEM.kemX25519Ladder
private def x25519Group := CryptWalker.KEM.kemX25519
private def mlkem768 := CryptWalker.KEM.MLKEM768.kemMLKEM768
private def mlkem768X25519 := CryptWalker.KEM.kemMLKEM768X25519
private def mlkem768Hedged := CryptWalker.KEM.MLKEMHedged.kemMLKEMHedged768
private def mlkem768HedgedX25519 := CryptWalker.KEM.kemMLKEMHedged768X25519

private def wbCipher := CryptWalker.WideBlockCipher.AEZ.aez
private def macS := CryptWalker.MAC.HMAC.hmacSha256MAC
private def kdfS := CryptWalker.KDF.HKDF.hkdfSha256Expand
private def streamS := CryptWalker.StreamCipher.AES256CTR.aes256CTR

private def randomVector (n : Nat) : IO (Vector UInt8 n) := do
  let bs ← IO.getRandomBytes (USize.ofNat n)
  pure (Vector.ofFn fun i : Fin n => bs[i.val]!)

private def randomBytes (n : Nat) : IO ByteArray := IO.getRandomBytes (USize.ofNat n)

structure Node where
  id : Vector UInt8 32
  /-- `kem.privateKeySize` bytes. -/
  priv : ByteArray
  pub : ByteArray
  deriving Inhabited

/-- A fresh node keypair. Lattice KEM private keys must come from `generate`, not random bytes. -/
private def newNode (kem : KEM) : IO Node := do
  let seed ← randomVector 32
  let id ← randomVector 32
  match kem.generate (kem.stateFromSeed seed) with
  | .error _ _ => throw (IO.userError "newNode: kem.generate failed")
  | .ok ⟨pk, sk, _⟩ _ =>
    pure { id, priv := ofVector (kem.encodePrivateKey sk), pub := ofVector (kem.encodePublicKey pk) }

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

def unwrapAll (kem : KEM) (geom : Geometry) (nodes : Array Node) (pkt0 : ByteArray)
    (wantPayload : ByteArray) : IO Bool := do
  let n := nodes.size
  let mut pkt := pkt0
  let mut ok := true
  let mut stop := false
  for i in [0:n] do
    if !stop then
      let node := nodes[i]!
      match unwrapKEM kem wbCipher macS kdfS streamS geom node.priv pkt with
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

def runRound (kem : KEM) (geom : Geometry) : IO Bool := do
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode kem)
  let path ← buildPath nodes
  let seeds ← nodes.mapM (fun _ => randomVector 32)
  let payload ← randomBytes geom.forwardPayloadLength
  match newKEMPacket kem wbCipher macS kdfS streamS geom seeds ByteArray.empty path payload with
  | .error e =>
    IO.eprintln s!"newKEMPacket failed: {e}"
    pure false
  | .ok pkt0 =>
    if pkt0.size ≠ geom.packetLength then
      IO.eprintln s!"packet length mismatch: got {pkt0.size}, want {geom.packetLength}"
      pure false
    else
      unwrapAll kem geom nodes pkt0 payload

def runFillerRound (schemeName : String) (kem : KEM) : IO Bool := do
  let geom ← IO.ofExcept (ofKEM schemeName 103 false 5)
  let nodes ← (List.range 3).toArray.mapM (fun _ => newNode kem)
  let path ← buildPath nodes
  let seeds ← nodes.mapM (fun _ => randomVector 32)
  let payload ← randomBytes geom.forwardPayloadLength
  let filler ← randomBytes ((geom.nrHops - 3) * geom.perHopRoutingInfoLength)
  match newKEMPacket kem wbCipher macS kdfS streamS geom seeds filler path payload with
  | .error e =>
    IO.eprintln s!"filler round: newKEMPacket failed: {e}"
    pure false
  | .ok pkt0 => unwrapAll kem geom nodes pkt0 payload

/-- As `runRound`, through `Sphinx.Interface.wrap`. `wrapKEM` draws one seed per hop, so the
stream must vary with the counter. -/
def runAbstractWrapRound (kem : KEM) (geom : Geometry) (hvalid : geom.ValidForKEM kem)
    (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength)
    (pathLen : Nat := geom.nrHops) : IO Bool := do
  let scheme := kemSphinxSchemeOf kem wbCipher macS kdfS streamS geom hvalid rfl h16
  let nodes ← (List.range pathLen).toArray.mapM (fun _ => newNode kem)
  let path ← buildPath nodes
  let fillerSeeds := (CryptWalker.Sphinx.Interface.fillerLength geom pathLen + 31) / 32
  let seeds ← (List.range (pathLen + fillerSeeds)).toArray.mapM (fun _ => randomVector 32)
  let payload ← randomVector geom.forwardPayloadLength
  let stream := fun i => seeds[i]!
  match scheme.wrap path.toList payload (CryptWalker.Sphinx.Interface.initWith stream) with
  | .error e _ =>
    IO.eprintln s!"abstract wrap failed: {e}"
    pure false
  | .ok pkt _ => unwrapAll kem geom nodes (ofVector pkt) (ofVector payload)

/-- Empirical check of `Sphinx.Interface.unwrap_complete`. -/
def runCompletenessRound (kem : KEM) (geom : Geometry) (hvalid : geom.ValidForKEM kem)
    (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength) : IO Bool := do
  let scheme := kemSphinxSchemeOf kem wbCipher macS kdfS streamS geom hvalid rfl h16
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode kem)
  let path ← buildPath nodes
  let seeds ← nodes.mapM (fun _ => randomVector 32)
  let payload ← randomVector geom.forwardPayloadLength
  let stream := fun i => seeds[i]!
  match scheme.wrap path.toList payload (CryptWalker.Sphinx.Interface.initWith stream) with
  | .error e _ =>
    IO.eprintln s!"completeness: wrap failed: {e}"
    pure false
  | .ok pkt _ =>
    let privKeys := (nodes.map (fun n => n.priv)).toList
    match CryptWalker.Sphinx.Interface.unwrapChainAux (unwrapKEM kem wbCipher macS kdfS streamS geom) privKeys (ofVector pkt) with
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

/-- As `runAbstractWrapRound`, over `newSURB`/`newPacketFromSURB`. The stream needs
`nodes.size + 2` distinct entries. -/
def runAbstractSURBRound (kem : KEM) (geom : Geometry) (hvalid : geom.ValidForKEM kem)
    (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength) : IO Bool := do
  let scheme := kemSphinxSchemeOf kem wbCipher macS kdfS streamS geom hvalid rfl h16
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode kem)
  let path ← buildPath nodes true
  let seeds ← (List.range (nodes.size + 2)).toArray.mapM (fun _ => randomVector 32)
  let stream := fun i => seeds[i]!
  match scheme.newSURB path.toList (CryptWalker.Sphinx.Interface.initWith stream) with
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
          match unwrapKEM kem wbCipher macS kdfS streamS geom node.priv pkt with
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
                match CryptWalker.Sphinx.SURB.decryptSURBPayload wbCipher geom surbKeys p with
                | .error e =>
                  IO.eprintln s!"decryptSURBPayload failed: {e}"
                  ok := false
                | .ok final =>
                  if byteArrayToHex final ≠ byteArrayToHex payload then
                    IO.eprintln "SURB payload mismatch"
                    ok := false
      pure ok

/-- SURB round trip: build a SURB, build a reply packet from it, unwrap through every hop, and
check `decryptSURBPayload` recovers the payload. -/
def runSURBRound (kem : KEM) (geom : Geometry) : IO Bool := do
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode kem)
  let path ← buildPath nodes true
  let seeds ← nodes.mapM (fun _ => randomVector 32)
  let kp1 ← randomVector 32
  let kp2 ← randomVector 32
  match newKEMSURB kem macS kdfS streamS geom seeds (kp1 ++ kp2) ByteArray.empty path with
  | .error e =>
    IO.eprintln s!"newKEMSURB failed: {e}"
    pure false
  | .ok (surb, surbKeys) =>
    if surb.size ≠ geom.surbLength then
      IO.eprintln s!"SURB length mismatch: got {surb.size}, want {geom.surbLength}"
      pure false
    else
    let payload ← randomBytes geom.forwardPayloadLength
    match CryptWalker.Sphinx.SURB.newPacketFromSURB wbCipher geom surb payload with
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
          match unwrapKEM kem wbCipher macS kdfS streamS geom node.priv pkt with
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
                match CryptWalker.Sphinx.SURB.decryptSURBPayload wbCipher geom surbKeys p with
                | .error e =>
                  IO.eprintln s!"decryptSURBPayload failed: {e}"
                  ok := false
                | .ok final =>
                  if byteArrayToHex final ≠ byteArrayToHex payload then
                    IO.eprintln "SURB payload mismatch"
                    ok := false
      pure ok

/-- Every round, against one KEM-Sphinx scheme. -/
def runSuite (schemeName : String) (kem : KEM) : IO Bool := do
  IO.println s!"-- {schemeName} --"
  let mut ok := true
  for nrHops in [1, 2, 3, 5] do
    let geom ← IO.ofExcept (ofKEM schemeName 103 false nrHops)
    let roundOk ← runRound kem geom
    IO.println s!"{nrHops} hop(s), no filler: {if roundOk then "ok" else "FAIL"}"
    ok := ok && roundOk

  let fillerOk ← runFillerRound schemeName kem
  IO.println s!"3 hop(s) of 5 (filler path): {if fillerOk then "ok" else "FAIL"}"
  ok := ok && fillerOk

  let geom3 := ofKEMWith schemeName kem 103 false 3
  let hvalid3 := ofKEMWith_validForKEM schemeName kem 103 false 3
  let h163 : 16 ≤ geom3.payloadTagLength + geom3.forwardPayloadLength := by
    rw [ofKEMWith_payloadTagLength schemeName kem 103 false 3]
    unfold CryptWalker.Sphinx.Constants.payloadTagLength; omega

  let abstractOk ← runAbstractWrapRound kem geom3 hvalid3 h163
  IO.println s!"abstract Sphinx.Interface.wrap (3 hops): {if abstractOk then "ok" else "FAIL"}"
  ok := ok && abstractOk

  let geom5 := ofKEMWith schemeName kem 103 false 5
  let hvalid5 := ofKEMWith_validForKEM schemeName kem 103 false 5
  let h165 : 16 ≤ geom5.payloadTagLength + geom5.forwardPayloadLength := by
    rw [ofKEMWith_payloadTagLength schemeName kem 103 false 5]
    unfold CryptWalker.Sphinx.Constants.payloadTagLength; omega
  let abstractFillerOk ← runAbstractWrapRound kem geom5 hvalid5 h165 3
  IO.println s!"abstract Sphinx.Interface.wrap (3 hops of 5, drawn filler): {if abstractFillerOk then "ok" else "FAIL"}"
  ok := ok && abstractFillerOk

  let completeOk ← runCompletenessRound kem geom3 hvalid3 h163
  IO.println s!"Sphinx.Interface.unwrap_complete via unwrapChainAux (3 hops): {if completeOk then "ok" else "FAIL"}"
  ok := ok && completeOk

  let geom3surb := ofKEMWith schemeName kem 103 true 3
  let hvalid3s := ofKEMWith_validForKEM schemeName kem 103 true 3
  let h163s : 16 ≤ geom3surb.payloadTagLength + geom3surb.forwardPayloadLength := by
    rw [ofKEMWith_payloadTagLength schemeName kem 103 true 3]
    unfold CryptWalker.Sphinx.Constants.payloadTagLength; omega
  let abstractSurbOk ← runAbstractSURBRound kem geom3surb hvalid3s h163s
  IO.println s!"abstract Sphinx.Interface.newSURB/newPacketFromSURB (3 hops): {if abstractSurbOk then "ok" else "FAIL"}"
  ok := ok && abstractSurbOk

  for nrHops in [1, 2, 3, 5] do
    let geom ← IO.ofExcept (ofKEM schemeName 103 true nrHops)
    let surbOk ← runSURBRound kem geom
    IO.println s!"SURB round trip ({nrHops} hop(s)): {if surbOk then "ok" else "FAIL"}"
    ok := ok && surbOk

  pure ok

def main (args : List String) : IO UInt32 := do
  match args with
  | [schemeName] =>
    match CryptWalker.KEM.byName schemeName with
    | none => IO.eprintln s!"unknown KEM scheme: {schemeName}"; pure 1
    | some kem =>
      let ok ← runSuite schemeName kem
      if ok then pure 0 else IO.eprintln "KEM-Sphinx round-trip self-tests FAILED"; pure 1
  | _ =>
    let okLadder ← runSuite "X25519LadderKEM" x25519Ladder
    IO.println ""
    let okGroup ← runSuite "X25519KEM" x25519Group
    IO.println ""
    let okMLKEM ← runSuite "MLKEM768" mlkem768
    IO.println ""
    let okHybrid ← runSuite "MLKEM768X25519" mlkem768X25519
    IO.println ""
    let okHedged ← runSuite "MLKEM768Hedged" mlkem768Hedged
    IO.println ""
    let okHedgedHybrid ← runSuite "MLKEM768HedgedX25519" mlkem768HedgedX25519
    IO.println ""
    if okLadder && okGroup && okMLKEM && okHybrid && okHedged && okHedgedHybrid then
      IO.println "all KEM-Sphinx round-trip self-tests passed (all six schemes)"
      pure 0
    else
      IO.eprintln "KEM-Sphinx round-trip self-tests FAILED"
      pure 1

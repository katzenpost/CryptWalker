/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.geometry
import CryptWalker.Sphinx.types
import CryptWalker.Sphinx.nike_sphinx_theorems
import CryptWalker.Sphinx.surb
import CryptWalker.Util.newhex
import CryptWalker.Util.Bytes

/-!
# NIKE-Sphinx create/unwrap round-trip self-test

`createHeader`'s exact output can't be cross-checked against Go (the client's ephemeral
randomness isn't recorded in katzenpost's vectors — see `NIKESphinx`'s module doc), so this
checks it the only way available: build a packet with fresh Lean-side keys, then `Unwrap` it
hop by hop with the system CSPRNG, and confirm the commands and final payload come back exactly
as built. `Crypto.aez_test`/`Crypto.test`/`commands_test` already pin every primitive this
exercises against Go; what's new here is that `createHeader`/`unwrapNIKE` compose them the same
way `sphinx.go` does.

Runs the full round set (several hop counts, all equal to the geometry's `nrHops` so no filler
padding is needed, one round with `nrHops < geom.nrHops` to exercise the filler path, plus the
abstract-interface/completeness/SURB rounds below) once per registered NIKE-Sphinx scheme —
`"x25519-ladder"` (`NIKE.X25519LadderScheme`) and `"x25519"` (`NIKE.X25519Scheme`) — since
`createHeader`/`unwrapNIKE` are generic over any `NIKE`, not just the ladder implementation
`nike_vectors_test`'s Go-cross-checked vectors happen to use. -/

open CryptWalker.Util.newhex
open CryptWalker.Sphinx.Geometry
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.NIKESphinx
open CryptWalker.NIKE.NIKE (NIKE)
open CryptWalker.Util.Bytes (ofVector toVecN)

private def x25519Ladder := CryptWalker.NIKE.X25519LadderScheme
private def x25519Group := CryptWalker.NIKE.X25519Scheme

-- As `kem_selftest.lean`: the four crypto primitives `nikeSphinxCore` now takes explicitly rather
-- than wiring up internally.
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
  priv : Vector UInt8 32
  pub : ByteArray
  deriving Inhabited

/-- The public key `priv` derives under `nike` — both `x25519LadderEntry`/`x25519GroupEntry` have
`privateKeySize = publicKeySize = 32`, but their encodings differ (u-coordinate bytes vs. the
group's field-element encoding), so this must go through `nike.derivePublicKey`/
`encodePublicKey` rather than any one scheme's raw arithmetic. `decodePrivateKey` never actually
fails here (both schemes' is total, `decodePrivateKey_total`), so the `none` branch is
unreachable in practice, not a real error path. -/
private def derivePubBytes (nike : NIKE) (priv : Vector UInt8 32) : IO ByteArray := do
  match nike.decodePrivateKey (toVecN nike.privateKeySize (ofVector priv)) with
  | none => throw (IO.userError "derivePubBytes: decodePrivateKey failed")
  | some sk => pure (ofVector (nike.encodePublicKey (nike.derivePublicKey sk)))

private def newNode (nike : NIKE) : IO Node := do
  let priv ← randomVector 32
  let id ← randomVector 32
  let pub ← derivePubBytes nike priv
  pure { id, priv, pub }

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

/-- Unwrap `pkt` at every node in order, checking forwarding commands and the final payload
against `wantPayload`. Returns whether every hop behaved as expected. -/
def unwrapAll (nike : NIKE) (geom : Geometry) (nodes : Array Node) (pkt0 : ByteArray)
    (wantPayload : ByteArray) : IO Bool := do
  let n := nodes.size
  let mut pkt := pkt0
  let mut ok := true
  let mut stop := false
  for i in [0:n] do
    if !stop then
      let node := nodes[i]!
      match unwrapNIKE nike wbCipher macS kdfS streamS geom (ofVector node.priv) pkt with
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

/-- One round: build an `nrHops`-hop path using all of `geom.nrHops`'s slots (so `filler` is
empty), send a random payload through it, and unwrap hop by hop. -/
def runRound (nike : NIKE) (geom : Geometry) : IO Bool := do
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode nike)
  let path ← buildPath nodes
  let clientPriv ← randomVector 32
  let payload ← randomBytes geom.forwardPayloadLength
  match newNIKEPacket nike wbCipher macS kdfS streamS geom (ofVector clientPriv) ByteArray.empty path payload with
  | .error e =>
    IO.eprintln s!"newNIKEPacket failed: {e}"
    pure false
  | .ok pkt0 =>
    if pkt0.size ≠ geom.packetLength then
      IO.eprintln s!"packet length mismatch: got {pkt0.size}, want {geom.packetLength}"
      pure false
    else
      unwrapAll nike geom nodes pkt0 payload

/-- A round using only 3 of a 5-hop geometry's slots, so `createHeader` exercises the random
filler for the two skipped hops. -/
def runFillerRound (schemeName : String) (nike : NIKE) : IO Bool := do
  let geom ← IO.ofExcept (ofNIKE schemeName 103 false 5)
  let nodes ← (List.range 3).toArray.mapM (fun _ => newNode nike)
  let path ← buildPath nodes
  let clientPriv ← randomVector 32
  let payload ← randomBytes geom.forwardPayloadLength
  let filler ← randomBytes ((geom.nrHops - 3) * geom.perHopRoutingInfoLength)
  match newNIKEPacket nike wbCipher macS kdfS streamS geom (ofVector clientPriv) filler path payload with
  | .error e =>
    IO.eprintln s!"filler round: newNIKEPacket failed: {e}"
    pure false
  | .ok pkt0 => unwrapAll nike geom nodes pkt0 payload

/-- The same round as `runRound`, but driven through `Sphinx.Interface.wrap`/`nikeSphinxScheme`
instead of calling `newNIKEPacket` directly — confirms the abstract-interface unification
actually produces a packet `unwrapNIKE` accepts, not just that it typechecks. A `pathLen` below
`geom.nrHops` exercises `wrap`'s own filler draw. -/
def runAbstractWrapRound (nike : NIKE) (geom : Geometry) (hvalid : geom.ValidForNIKE nike)
    (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength)
    (pathLen : Nat := geom.nrHops) : IO Bool := do
  let scheme := nikeSphinxCore nike wbCipher macS kdfS streamS geom hvalid rfl h16
  let nodes ← (List.range pathLen).toArray.mapM (fun _ => newNode nike)
  let path ← buildPath nodes
  let seed ← randomVector 32
  let payload ← randomVector geom.forwardPayloadLength
  match scheme.wrap path.toList payload (CryptWalker.Sphinx.Interface.initWith (fun _ => seed)) with
  | .error e _ =>
    IO.eprintln s!"abstract wrap failed: {e}"
    pure false
  | .ok pkt _ => unwrapAll nike geom nodes (ofVector pkt) (ofVector payload)

/-- Empirical check of `Sphinx.Interface.unwrap_complete` (the property
`wrapNIKE_unwrapNIKE_complete_valid` proves outright): `unwrapChainAux`, given every hop's private
key in path order, recovers the payload from a `wrap`-built packet in one call — no per-hop
bookkeeping, unlike `unwrapAll`. -/
def runCompletenessRound (nike : NIKE) (geom : Geometry) (hvalid : geom.ValidForNIKE nike)
    (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength) : IO Bool := do
  let scheme := nikeSphinxCore nike wbCipher macS kdfS streamS geom hvalid rfl h16
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode nike)
  let path ← buildPath nodes
  let seed ← randomVector 32
  let payload ← randomVector geom.forwardPayloadLength
  match scheme.wrap path.toList payload (CryptWalker.Sphinx.Interface.initWith (fun _ => seed)) with
  | .error e _ =>
    IO.eprintln s!"completeness: wrap failed: {e}"
    pure false
  | .ok pkt _ =>
    let privKeys := (nodes.map (fun n => ofVector n.priv)).toList
    match CryptWalker.Sphinx.Interface.unwrapChainAux (unwrapNIKE nike wbCipher macS kdfS streamS geom) privKeys (ofVector pkt) with
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
round-trip through `unwrapNIKE`/`SURB.decryptSURBPayload`, not just that they typecheck. -/
def runAbstractSURBRound (nike : NIKE) (geom : Geometry) (hvalid : geom.ValidForNIKE nike)
    (h16 : 16 ≤ geom.payloadTagLength + geom.forwardPayloadLength) : IO Bool := do
  let scheme := nikeSphinxCore nike wbCipher macS kdfS streamS geom hvalid rfl h16
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode nike)
  let path ← buildPath nodes true
  let seeds ← (List.range 3).toArray.mapM (fun _ => randomVector 32)
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
          match unwrapNIKE nike wbCipher macS kdfS streamS geom (ofVector node.priv) pkt with
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

/-- Full SURB round trip: build a SURB (`newNIKESURB`), use it to build a reply packet
(`SURB.newPacketFromSURB`), unwrap that reply through every hop, and confirm
`SURB.decryptSURBPayload` recovers the original payload — the creation-side counterpart to the
byte-exact `newPacketFromSURB`/`decryptSURBPayload` checks in `nike_vectors_test` (which can
only check the deterministic half; nothing records the randomness a real SURB was built with). -/
def runSURBRound (nike : NIKE) (geom : Geometry) : IO Bool := do
  let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNode nike)
  let path ← buildPath nodes true
  let clientSeed ← randomVector 32
  let kp1 ← randomVector 32
  let kp2 ← randomVector 32
  match newNIKESURB nike macS kdfS streamS geom (ofVector clientSeed) (kp1 ++ kp2) ByteArray.empty path with
  | .error e =>
    IO.eprintln s!"newNIKESURB failed: {e}"
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
          match unwrapNIKE nike wbCipher macS kdfS streamS geom (ofVector node.priv) pkt with
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

/-- The full round set above, run against one registered NIKE-Sphinx scheme. Called once per
entry in `NIKE.registry` from `main`. The abstract/completeness/SURB rounds build their geometry
via `ofNIKEWith` (which needs no `byName` witness, since it's handed `nike` directly) rather than
`ofNIKE schemeName`, purely to sidestep `byName`'s case-insensitive `String.toLower` comparison
being unable to reduce inside a kernel proof for anything but the registry's first entry — the
concrete `runRound`/`runFillerRound`/`runSURBRound` calls below still go through the real
string-keyed `ofNIKE`, so that resolution path stays exercised at runtime for every scheme. -/
def runSuite (schemeName : String) (nike : NIKE) : IO Bool := do
  IO.println s!"-- {schemeName} --"
  let mut ok := true
  for nrHops in [1, 2, 3, 5] do
    let geom ← IO.ofExcept (ofNIKE schemeName 103 false nrHops)
    let roundOk ← runRound nike geom
    IO.println s!"{nrHops} hop(s), no filler: {if roundOk then "ok" else "FAIL"}"
    ok := ok && roundOk

  let fillerOk ← runFillerRound schemeName nike
  IO.println s!"3 hop(s) of 5 (filler path): {if fillerOk then "ok" else "FAIL"}"
  ok := ok && fillerOk

  let geom3 := ofNIKEWith schemeName nike 103 false 3
  let hvalid3 := ofNIKEWith_validForNIKE schemeName nike 103 false 3
  let h163 : 16 ≤ geom3.payloadTagLength + geom3.forwardPayloadLength := by
    rw [ofNIKEWith_payloadTagLength schemeName nike 103 false 3]
    unfold CryptWalker.Sphinx.Constants.payloadTagLength; omega

  let abstractOk ← runAbstractWrapRound nike geom3 hvalid3 h163
  IO.println s!"abstract Sphinx.Interface.wrap (3 hops): {if abstractOk then "ok" else "FAIL"}"
  ok := ok && abstractOk

  let geom5 := ofNIKEWith schemeName nike 103 false 5
  let hvalid5 := ofNIKEWith_validForNIKE schemeName nike 103 false 5
  let h165 : 16 ≤ geom5.payloadTagLength + geom5.forwardPayloadLength := by
    rw [ofNIKEWith_payloadTagLength schemeName nike 103 false 5]
    unfold CryptWalker.Sphinx.Constants.payloadTagLength; omega
  let abstractFillerOk ← runAbstractWrapRound nike geom5 hvalid5 h165 3
  IO.println s!"abstract Sphinx.Interface.wrap (3 hops of 5, drawn filler): {if abstractFillerOk then "ok" else "FAIL"}"
  ok := ok && abstractFillerOk

  let completeOk ← runCompletenessRound nike geom3 hvalid3 h163
  IO.println s!"Sphinx.Interface.unwrap_complete via unwrapChainAux (3 hops): {if completeOk then "ok" else "FAIL"}"
  ok := ok && completeOk

  let geom3surb := ofNIKEWith schemeName nike 103 true 3
  let hvalid3s := ofNIKEWith_validForNIKE schemeName nike 103 true 3
  let h163s : 16 ≤ geom3surb.payloadTagLength + geom3surb.forwardPayloadLength := by
    rw [ofNIKEWith_payloadTagLength schemeName nike 103 true 3]
    unfold CryptWalker.Sphinx.Constants.payloadTagLength; omega
  let abstractSurbOk ← runAbstractSURBRound nike geom3surb hvalid3s h163s
  IO.println s!"abstract Sphinx.Interface.newSURB/newPacketFromSURB (3 hops): {if abstractSurbOk then "ok" else "FAIL"}"
  ok := ok && abstractSurbOk

  for nrHops in [1, 2, 3, 5] do
    let geom ← IO.ofExcept (ofNIKE schemeName 103 true nrHops)
    let surbOk ← runSURBRound nike geom
    IO.println s!"SURB round trip ({nrHops} hop(s)): {if surbOk then "ok" else "FAIL"}"
    ok := ok && surbOk

  pure ok

def main : IO UInt32 := do
  let okLadder ← runSuite "x25519-ladder" x25519Ladder
  IO.println ""
  let okGroup ← runSuite "x25519" x25519Group
  IO.println ""
  if okLadder && okGroup then
    IO.println "all NIKE-Sphinx round-trip self-tests passed (both schemes)"
    pure 0
  else
    IO.eprintln "NIKE-Sphinx round-trip self-tests FAILED"
    pure 1

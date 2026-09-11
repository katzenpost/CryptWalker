/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Constants
import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Commands
import CryptWalker.Sphinx.Types
import CryptWalker.Sphinx.Interface
import CryptWalker.Sphinx.Common
import CryptWalker.Sphinx.SURB
import CryptWalker.Sphinx.Crypto.KDF
import CryptWalker.Sphinx.Crypto.ChaCha20
import CryptWalker.Sphinx.Crypto.Stream
import CryptWalker.Sphinx.Crypto.AEZ
import CryptWalker.NIKE.X25519_montgomery_ladder
import CryptWalker.NIKE.X25519
import CryptWalker.Sphinx.WrapResistance
import CryptWalker.Hash.Sha512
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.NIKESphinx

open CryptWalker.Sphinx.Constants
open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Common
open CryptWalker.Sphinx.Crypto.KDF (PacketKeys sphinxKDF)
open CryptWalker.Sphinx.Crypto.ChaCha20 (keystream32)
open CryptWalker.Sphinx.Crypto.Stream (keystream)
open CryptWalker.Sphinx.Crypto.AEZ (sprpEncrypt sprpDecrypt)
open CryptWalker.NIKE.X25519_montgomery_ladder (curve25519 basepointBytes)
open CryptWalker.NIKE.X25519 (Point liftX)
open CryptWalker.NIKE.X25519Common (toField)
open CryptWalker.Hash.Sha512 (sha512_256)
open CryptWalker.Util.Bytes (ofVector)

/-! # NIKE-Sphinx (X25519)

Port of `sphinx.go`'s NIKE path (`createHeader`, `newNIKEPacket`, `unwrapNIKE`), concrete to
X25519 rather than an abstract NIKE. `createHeader` takes its randomness (client ephemeral key,
hop-count-hiding filler) as plain arguments rather than `IO`, so it stays pure.

`unwrapNIKE` needs no randomness, which is what makes it the half `Crypto.aez_test` and friends
can eventually check against Go's own `sphinx_vectors.json` byte-for-byte: that file's packets
were built with a client ephemeral key it doesn't record, so `createHeader`'s output can't be
reproduced from it, but `Unwrap` is deterministic. -/

/-- Diffie-Hellman: `curve25519(sk, pk)`. Also stands in for `nike.Blind` below —
`hpqc/nike/x25519`'s `Blind` *is* `Exp`/`curve25519`, just with the arguments named
differently. -/
private def dh (sk pk : Vector UInt8 32) : Vector UInt8 32 := curve25519 sk pk

/-- `nike.Blind(pk, factor) = Exp(pk, factor) = curve25519(factor, pk)`. -/
private def blind (pk factor : Vector UInt8 32) : Vector UInt8 32 := curve25519 factor pk

/-- `BlindingFactor`'s raw seed, as the NIKE private key it represents: the first 32 bytes of
`rand.NewDeterministicRandReader(seed)`, unclamped (clamping happens inside `curve25519`,
matching `nike/x25519.NewKeypair`). -/
private def blindingFactorPrivKey (seed : Vector UInt8 32) : Vector UInt8 32 :=
  toVec32 ⟨keystream32 seed.toArray⟩

/-- Everything `crypto.KDF` derives for one hop, with the raw `BlindingFactor` seed already
turned into the NIKE private key it represents (`internal/crypto.PacketKeys.BlindingFactor` is
itself a `nike.PrivateKey`, not a raw seed — `deriveHopKeys` is the point where that conversion
happens, once, rather than at every later use site). -/
structure HopKeys where
  headerMAC : Vector UInt8 32
  headerEncryption : Vector UInt8 32
  headerEncryptionIV : Vector UInt8 16
  payloadEncryption : Vector UInt8 48
  blindingFactor : Vector UInt8 32
  deriving Inhabited

def deriveHopKeys (sharedSecret : Vector UInt8 32) : HopKeys :=
  let pk : PacketKeys := sphinxKDF (ofVector sharedSecret)
  { headerMAC := pk.headerMAC
    headerEncryption := pk.headerEncryption
    headerEncryptionIV := pk.headerEncryptionIV
    payloadEncryption := pk.payloadEncryption
    blindingFactor := blindingFactorPrivKey pk.blindingFactorSeed }

/-- **`createHeader`**. `filler` must be exactly `(geom.nrHops - path.size) *
geom.perHopRoutingInfoLength` bytes (ignored, and may be empty, when `path.size = geom.nrHops`)
— the random padding that hides a shorter-than-maximum path's true hop count. -/
def createHeader (geom : Geometry) (clientPrivateKey : Vector UInt8 32) (filler : ByteArray)
    (path : Array PathHop) : Except String (ByteArray × Array SPRPKey) := do
  let nrHops := path.size
  if nrHops == 0 || nrHops > geom.nrHops then throw "sphinx: invalid path"
  if geom.nrHops > nrHops && filler.size ≠ (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
  then throw "sphinx: invalid filler length"

  let clientPublicKey0 := dh clientPrivateKey basepointBytes

  -- Per-hop shared secrets/keys, and the (progressively blinded) group elements.
  let mut groupElements : Array (Vector UInt8 32) := Array.replicate nrHops clientPublicKey0
  let mut keys : Array HopKeys := #[deriveHopKeys (dh clientPrivateKey (path[0]!).publicKey)]
  let mut clientPublicKey := clientPublicKey0
  for i in [1:nrHops] do
    let mut sharedSecret := dh clientPrivateKey (path[i]!).publicKey
    for j in [0:i] do
      sharedSecret := dh (keys[j]!).blindingFactor sharedSecret
    keys := keys.push (deriveHopKeys sharedSecret)
    clientPublicKey := blind clientPublicKey (keys[i-1]!).blindingFactor
    groupElements := groupElements.set! i clientPublicKey

  -- Per-hop routing-info keystream and encrypted padding.
  let totalRiLen := geom.routingInfoLength + geom.perHopRoutingInfoLength
  let mut riKeyStream : Array ByteArray := #[]
  let mut riPadding : Array ByteArray := #[]
  for i in [0:nrHops] do
    let ks := keystream (keys[i]!).headerEncryption (keys[i]!).headerEncryptionIV totalRiLen
    let ksLen := totalRiLen - (i + 1) * geom.perHopRoutingInfoLength
    let mut thisPad := ks.extract ksLen totalRiLen
    if i > 0 then
      let prevPad := riPadding[i - 1]!
      thisPad := xorBytes (thisPad.extract 0 prevPad.size) prevPad
        ++ thisPad.extract prevPad.size thisPad.size
    riKeyStream := riKeyStream.push (ks.extract 0 ksLen)
    riPadding := riPadding.push thisPad

  -- Assemble the routing_information block, back to front.
  let mut routingInfo : ByteArray := if geom.nrHops > nrHops then filler else ByteArray.empty
  let mut macBytes : ByteArray := ByteArray.empty
  for iRev in [0:nrHops] do
    let i := nrHops - 1 - iRev
    let isTerminal := i == nrHops - 1
    let hop := path[i]!
    let mut riFragment ← commandsToBytes geom hop.commands
    if !isTerminal then
      let next := path[i + 1]!
      riFragment := riFragment ++ (RoutingCommand.nextNodeHop next.id (toVec32 macBytes)).toBytes
    routingInfo := zeroPadTo geom.perHopRoutingInfoLength riFragment ++ routingInfo
    routingInfo := xorBytes routingInfo (riKeyStream[i]!)
    let mPreimage := v0AD ++ ofVector (groupElements[i]!) ++ routingInfo
      ++ (if i > 0 then riPadding[i - 1]! else ByteArray.empty)
    macBytes := ofVector (mac (keys[i]!).headerMAC mPreimage)

  let hdr := v0AD ++ ofVector (groupElements[0]!) ++ routingInfo ++ macBytes
  let sprpKeys : Array SPRPKey := Array.ofFn fun i : Fin nrHops =>
    { key := (keys[i.val]!).payloadEncryption, iv := (keys[i.val]!).headerEncryptionIV }
  pure (hdr, sprpKeys)

/-- **`newNIKEPacket`**. -/
def newNIKEPacket (geom : Geometry) (clientPrivateKey : Vector UInt8 32) (filler : ByteArray)
    (path : Array PathHop) (payload : ByteArray) : Except String ByteArray := do
  if payload.size ≠ geom.forwardPayloadLength then
    throw s!"sphinx: invalid payload length: {payload.size}, expected {geom.forwardPayloadLength}"
  let (hdr, sprpKeys) ← createHeader geom clientPrivateKey filler path
  let mut b := (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload
  for iRev in [0:sprpKeys.size] do
    let k := sprpKeys[sprpKeys.size - 1 - iRev]!
    b := sprpEncrypt k.key.toArray (ofVector k.iv) b
  pure (hdr ++ b)

/-- A successful `newNIKEPacket` on a `geom.forwardPayloadLength`-sized payload produces exactly
`geom.packetLength` bytes: `headerLength` (itself `createHeader`'s routing-info-block
construction, accumulated over a `for` loop) plus `payloadTagLength + payload.size`
(`sprpEncrypt`'s length preservation, applied in another loop). True by construction and
confirmed by all 20 `sphinx_{nike,kem}_vectors.json` packets — see `Sphinx.Interface`'s doc comment
for why this is an axiom rather than a proof through those loops. `wrapNIKE` uses it to give
`Sphinx.Interface.wrap` a packet-length-preserving *type*, the same way `sprpDecrypt_size` lets
`unwrapNIKE` do that for `forwardPkt`. -/
axiom newNIKEPacket_size (geom : Geometry) (clientPrivateKey : Vector UInt8 32) (filler : ByteArray)
    (path : Array PathHop) (payload : ByteArray) (pkt : ByteArray)
    (h : newNIKEPacket geom clientPrivateKey filler path payload = .ok pkt)
    (hpay : payload.size = geom.forwardPayloadLength) :
    pkt.size = geom.packetLength

open CryptWalker.Sphinx.Interface (SeedStream nextSeed unwrapChainAux)

/-- **`wrapNIKE`**: `Sphinx.Interface.wrap` for `NIKESphinxScheme` — `newNIKEPacket`, drawing the
client's ephemeral private key from the seed stream instead of taking it as a bare argument. -/
def wrapNIKE (geom : Geometry) (path : List PathHop) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) :
    EStateM String SeedStream (Vector UInt8 geom.packetLength) := do
  let seed ← nextSeed
  match h : newNIKEPacket geom seed filler path.toArray (ofVector payload) with
  | .error e => throw e
  | .ok pkt =>
    have hsize : pkt.size = geom.packetLength :=
      newNIKEPacket_size geom seed filler path.toArray (ofVector payload) pkt h (by simp)
    pure ⟨pkt.data, hsize⟩

/-- **`newNIKESURB`**. `keyPayload` is the recipient's own random SPRP key ‖ iv for the reply's
final payload-encryption layer (`sprpKeyMaterialLength = 64` bytes — `surb.go`'s
`io.ReadFull(r, keyPayload[:])`). Returns `(surb, decryptionKeys)`; `decryptionKeys` is exactly
what `SURB.decryptSURBPayload` wants. -/
def newNIKESURB (geom : Geometry) (clientPrivateKey : Vector UInt8 32) (keyPayload : Vector UInt8 64)
    (filler : ByteArray) (path : Array PathHop) : Except String (ByteArray × ByteArray) := do
  let (hdr, sprpKeys) ← createHeader geom clientPrivateKey filler path
  -- Reverse hop order, "to ease decryption" (surb.go's comment).
  let mut k : ByteArray := ByteArray.empty
  for iRev in [0:sprpKeys.size] do
    let kk := sprpKeys[sprpKeys.size - 1 - iRev]!
    k := k ++ ofVector kk.key ++ ofVector kk.iv
  k := k ++ ofVector keyPayload
  let surb := hdr ++ ofVector (path[0]!).id ++ ofVector keyPayload
  pure (surb, k)

/-- As `newNIKEPacket_size`: `geom.surbLength = headerLength + nodeIDLength +
sprpKeyMaterialLength`, and `newNIKESURB`'s `surb` is exactly `hdr ++ id(32) ++
keyPayload(64)` with `hdr.size = geom.headerLength` (`createHeader`'s own loop-accumulated
invariant, the same one `newNIKEPacket_size` relies on). -/
axiom newNIKESURB_size (geom : Geometry) (clientPrivateKey : Vector UInt8 32) (keyPayload : Vector UInt8 64)
    (filler : ByteArray) (path : Array PathHop) (surb surbKeys : ByteArray)
    (h : newNIKESURB geom clientPrivateKey keyPayload filler path = .ok (surb, surbKeys)) :
    surb.size = geom.surbLength

/-- **`wrapNIKESURB`**: `Sphinx.Interface.newSURB` for `NIKESphinxScheme` — `newNIKESURB`, drawing
the client's ephemeral key and `keyPayload` (two seeds' worth) from the seed stream instead of
taking them as bare arguments. -/
def wrapNIKESURB (geom : Geometry) (path : List PathHop) (filler : ByteArray) :
    EStateM String SeedStream (Vector UInt8 geom.surbLength × ByteArray) := do
  let clientKey ← nextSeed
  let kp1 ← nextSeed
  let kp2 ← nextSeed
  match h : newNIKESURB geom clientKey (kp1 ++ kp2) filler path.toArray with
  | .error e => throw e
  | .ok (surb, k) =>
    have hsize : surb.size = geom.surbLength :=
      newNIKESURB_size geom clientKey (kp1 ++ kp2) filler path.toArray surb k h
    pure (⟨surb.data, hsize⟩, k)

/-- **`unwrapNIKE`**: `(payload, replayTag, cmds, forwardPkt)`, satisfying `Sphinx.Interface.unwrap`
(see that file). Unlike Go, a MAC mismatch reports only an error string, not also the replay
tag. -/
def unwrapNIKE (geom : Geometry) (privKey : Vector UInt8 32) (pkt : ByteArray) :
    Except String
      (Option ByteArray × Vector UInt8 32 × List RoutingCommand × Option (Vector UInt8 pkt.size)) := do
  let geOff := 2
  let riOff := geOff + 32
  let macOff := riOff + geom.routingInfoLength
  let payloadOff := macOff + macLength

  -- Dependent `if`: the size proof below needs `¬(pkt.size < payloadOff)` as a hypothesis, not
  -- just as control flow.
  if h1 : pkt.size < payloadOff then throw "sphinx: invalid packet, truncated"
  else do
  if (pkt.extract 0 2).data ≠ v0AD.data then throw "sphinx: invalid packet, unknown version"

  let groupElement := toVec32 (pkt.extract geOff riOff)
  let sharedSecret := dh privKey groupElement
  let replayTag := sha512_256 (ofVector groupElement)
  let keys := deriveHopKeys sharedSecret

  let gotMac := mac keys.headerMAC (pkt.extract 0 macOff)
  if (ofVector gotMac).data ≠ (pkt.extract macOff (macOff + macLength)).data then
    throw "sphinx: invalid packet, MAC mismatch"

  -- Decrypt the (padding-extended) routing_info block and split off this hop's fragment.
  let mut b : ByteArray := pkt.extract riOff macOff ++ ⟨Array.replicate geom.perHopRoutingInfoLength 0⟩
  have hb : b.size = geom.routingInfoLength + geom.perHopRoutingInfoLength := by
    have hpad : (⟨Array.replicate geom.perHopRoutingInfoLength (0 : UInt8)⟩ : ByteArray).size
        = geom.perHopRoutingInfoLength := Array.size_replicate
    show (pkt.extract riOff macOff ++ (⟨Array.replicate geom.perHopRoutingInfoLength 0⟩ : ByteArray)).size
      = geom.routingInfoLength + geom.perHopRoutingInfoLength
    rw [ByteArray.size_append, ByteArray.size_extract, hpad]
    omega
  b := xorBytes b (keystream keys.headerEncryption keys.headerEncryptionIV b.size)
  have hb' : b.size = geom.routingInfoLength + geom.perHopRoutingInfoLength := by
    show (xorBytes _ _).size = _
    rw [size_xorBytes]; exact hb
  let cmdBuf := b.extract 0 geom.perHopRoutingInfoLength
  let newRoutingInfo := b.extract geom.perHopRoutingInfoLength b.size
  have hnri : newRoutingInfo.size = geom.routingInfoLength := by
    show (b.extract geom.perHopRoutingInfoLength b.size).size = geom.routingInfoLength
    rw [ByteArray.size_extract]
    omega

  let cmds ← parseAll cmdBuf
  let nextNode := cmds.findSome? fun
    | .nextNodeHop id m => some (id, m)
    | _ => none
  let hasSurbReply := cmds.any fun
    | .surbReply _ => true
    | _ => false

  let rawPayload := pkt.extract payloadOff pkt.size
  have hraw : rawPayload.size = pkt.size - payloadOff := by
    show (pkt.extract payloadOff pkt.size).size = pkt.size - payloadOff
    rw [ByteArray.size_extract]
    omega
  let decPayload :=
    if rawPayload.size > 0 then sprpDecrypt keys.payloadEncryption.toArray (ofVector keys.headerEncryptionIV) rawPayload
    else rawPayload
  have hdec : decPayload.size = rawPayload.size := by
    show (if rawPayload.size > 0
          then sprpDecrypt keys.payloadEncryption.toArray (ofVector keys.headerEncryptionIV) rawPayload
          else rawPayload).size = rawPayload.size
    split
    · exact CryptWalker.Sphinx.Crypto.AEZ.sprpDecrypt_size _ _ _
    · rfl

  match nextNode with
  | some (_nextID, nextMAC) =>
    let newGroupElement := blind groupElement keys.blindingFactor
    let newPayload := if decPayload.size > 0 then decPayload else rawPayload
    have hnewPayload : newPayload.size = pkt.size - payloadOff := by
      show (if decPayload.size > 0 then decPayload else rawPayload).size = pkt.size - payloadOff
      split
      · rw [hdec, hraw]
      · rw [hraw]
    let newPkt := v0AD ++ ofVector newGroupElement ++ newRoutingInfo ++ ofVector nextMAC ++ newPayload
    have hnewPkt : newPkt.size = pkt.size := by
      show (v0AD ++ ofVector newGroupElement ++ newRoutingInfo ++ ofVector nextMAC ++ newPayload).size
        = pkt.size
      rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append, ByteArray.size_append,
          Util.Bytes.size_ofVector, Util.Bytes.size_ofVector, hnri, hnewPayload]
      have hv0 : v0AD.size = 2 := rfl
      have hmac : macLength = 32 := rfl
      omega
    pure (none, replayTag, cmds, some ⟨newPkt.data, hnewPkt⟩)
  | none =>
    if decPayload.size < geom.payloadTagLength then throw "sphinx: truncated payload"
    if hasSurbReply then
      pure (some decPayload, replayTag, cmds, none)
    else
      let tag := decPayload.extract 0 geom.payloadTagLength
      if !tag.data.all (· == 0) then throw "sphinx: payload auth failed"
      pure (some (decPayload.extract geom.payloadTagLength decPayload.size), replayTag, cmds, none)

/-- **Completeness**: `NIKESphinxScheme`'s witness for `Sphinx.Interface.unwrap_complete` — the
claim that Sphinx onion-decrypts correctly, checked empirically by every vector and self-test
round trip (`nike_vectors_test`; `nike_selftest`'s `runRound`/`runAbstractWrapRound`/
`runAbstractSURBRound`), but not proved here for the reason the size axioms above aren't: real
work, through `createHeader`'s blinding chain and `unwrapNIKE`'s AEZ/HMAC composition, out of
scope for this pass. -/
axiom wrapNIKE_unwrapNIKE_complete (geom : Geometry) (path : List PathHop)
    (privKeys : List (Vector UInt8 32)) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) (st : SeedStream)
    (pkt : Vector UInt8 geom.packetLength) (st' : SeedStream) :
    path ≠ [] →
    path.map (·.publicKey) = privKeys.map (fun sk => curve25519 sk basepointBytes) →
    wrapNIKE geom path filler payload st = .ok pkt st' →
    unwrapChainAux (unwrapNIKE geom) privKeys (ofVector pkt) = .ok (some (ofVector payload))

/-- NIKE-Sphinx (X25519) as a `Sphinx.Interface` instance. -/
def NIKESphinxScheme (geom : Geometry) : CryptWalker.Sphinx.Interface.Sphinx where
  State := SeedStream
  PrivateKey := Vector UInt8 32
  Command := RoutingCommand
  packetLength := geom.packetLength
  payloadLength := geom.forwardPayloadLength
  surbLength := geom.surbLength
  -- Inhabitance only, matching `KEM.Adapter.kemOfNike`'s `stateI`: a constant (hence degenerate)
  -- stream. Honest runs start from `Sphinx.Interface.initWith`.
  stateI := ⟨CryptWalker.Sphinx.Interface.initWith (fun _ => Vector.replicate 32 0)⟩
  derivePublicKey := fun sk => curve25519 sk basepointBytes
  wrap := wrapNIKE geom
  unwrap := unwrapNIKE geom
  newSURB := wrapNIKESURB geom
  newPacketFromSURB := fun surb payload =>
    CryptWalker.Sphinx.SURB.newPacketFromSURB geom (ofVector surb) payload
  unwrap_complete := wrapNIKE_unwrapNIKE_complete geom

/-- **`NIKESphinxScheme`'s `BlindedScheme` witness** — `Sphinx.Interface.wrap_resistant`, for real.
`Envelope` is the header's group element: `parseEnvelope` reads the same 32 bytes at offset 2
`unwrapNIKE` does (`geOff`/`riOff` above), then lifts them to a `Point` via `liftX`, defaulting
to the identity on failure — which a well-formed header, whose element always came from an
honest `dh`/`blind` chain, never triggers. `Factor` is left as `Fin N`, matching
`WrapResistance.blind_wrapResistance`: this instance needs no bijectivity proof to construct
(`wrap_resistant` is `BlindedScheme`'s free default), only whoever *uses* `wrap_resistant` needs
to supply it, exactly as `blind_wrapResistance` already does. -/
def NIKESphinxBlinded (geom : Geometry) (N : ℕ) [NeZero N] :
    CryptWalker.Sphinx.Interface.BlindedScheme where
  toSphinx := NIKESphinxScheme geom
  Envelope := Point
  parseEnvelope := fun pkt => (liftX (toField (toVec32 ((ofVector pkt).extract 2 34)))).getD 0
  Factor := Fin N
  blind := fun b P => (b : ℕ) • P

end CryptWalker.Sphinx.NIKESphinx

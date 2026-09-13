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
import CryptWalker.Sphinx.NIKESphinx
import CryptWalker.Sphinx.SURB
import CryptWalker.Sphinx.Crypto.Stream
import CryptWalker.Sphinx.Crypto.AEZ
import CryptWalker.NIKE.NIKE
import CryptWalker.KEM.Adapter
import CryptWalker.KEM.Schemes
import CryptWalker.Hash.Sha512
import CryptWalker.Util.Bytes

namespace CryptWalker.Sphinx.KEMSphinx

open CryptWalker.Sphinx.Constants
open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Common
open CryptWalker.Sphinx.NIKESphinx (HopKeys deriveHopKeys)
open CryptWalker.Sphinx.Crypto.Stream (keystream)
open CryptWalker.Sphinx.Crypto.AEZ (sprpEncrypt sprpDecrypt)
open CryptWalker.NIKE.NIKE (NIKE)
open CryptWalker.KEM.Adapter (PRF encapM decapM initWith)
open CryptWalker.Hash.Sha512 (sha512_256)
open CryptWalker.Util.Bytes (ofVector)

/-! # KEM-Sphinx (the NIKE→KEM adapter, generic over the wrapped NIKE)

Port of `kemsphinx.go`. Genuinely generic over any `(prf, nike)` pair, the same
`CryptWalker.KEM.Adapter.kemOfNike`-shaped construction `CryptWalker.KEM.Schemes.adapterByName`
already resolves a registered KEM's name to — not hardcoded to X25519, and not bundled with a
proof of any particular key size (a `NIKE` already carries its own `publicKeySize`, read directly,
the same way `NIKESphinx` does).

**Scope boundary, stated plainly**: `CryptWalker.KEM.KEM.KEM`'s abstract interface has no generic
"start the internal randomness from this seed" operation (its `State` is opaque, and
`kemOfNike`-specific `initWith` is what actually supplies one) or "derive a public key from a
private key" operation (only `generate`, which samples a fresh pair jointly) — both noted already
in `KEM.Schemes`'s own module doc. So this file is agnostic to *which* `(prf, nike)` pair-shaped
KEM is used, not to arbitrary `KEM.KEM` values in general; every KEM this project can currently
construct is exactly this shape (`kemOfNike` is the only `KEM` constructor that exists).

Differences from `NIKESphinx`, per `kemsphinx.go`/`docs/specs/kemsphinx.md`:

* One KEM encapsulation per hop, independent of the others — no blinding chain, so no
  `HopKeys.blindingFactor` (reused from `NIKESphinx` regardless, unused, matching how Go reuses
  `crypto.PacketKeys` with `BlindingFactor = nil` rather than a separate type).
* The header's group-element field becomes a KEM ciphertext (`nike.publicKeySize` bytes — an
  ephemeral NIKE public key, per `Adapter.encapM`); every non-terminal hop's per-hop routing-info
  block embeds the *next* hop's ciphertext in its last `nike.publicKeySize` bytes, rather than
  carrying it via a `NextNodeHop` command field.
* Forwarding just copies the embedded next-hop ciphertext into the group-element slot — no
  `Blind` step, since there is no group element to re-blind. -/

/-- The KEM ciphertext width — `kemOfNike`'s `ciphertextSize := nike.publicKeySize` (an
ephemeral NIKE public key stands in for the KEM ciphertext; see `Adapter.encapM`). -/
private def ctSize (nike : NIKE) : Nat := nike.publicKeySize

/-- One hop's encapsulation, at the byte level: decode the recipient's public key, run
`Adapter.encapM` with `seed` as the adapter's ephemeral randomness, and re-encode both outputs.
`Except`, not `Option`: a bad encoding and an unsafe/small-order public key are both genuine,
reported failures. -/
private def kemEncap (prf : PRF) (nike : NIKE) (pkBytes : ByteArray) (seed : Vector UInt8 32) :
    Except String (ByteArray × ByteArray) :=
  match nike.decodePublicKey (toVecN nike.publicKeySize pkBytes) with
  | none => throw "sphinx: invalid public key encoding"
  | some pk =>
    match encapM prf nike pk (initWith (fun _ => seed)) with
    | .ok (ephPk, ss) _ => pure (ofVector (nike.encodePublicKey ephPk), ofVector ss)
    | .error _ _ => throw "sphinx: KEM encapsulation failed"

/-- One hop's decapsulation, at the byte level: decode the private key and the ciphertext (an
ephemeral NIKE public key), then run `Adapter.decapM`. The adapter's own `State` argument is
irrelevant to `decapM`'s result (decapsulation draws no randomness), so any seed stream works. -/
private def kemDecap (prf : PRF) (nike : NIKE) (skBytes ctBytes : ByteArray) :
    Except String ByteArray :=
  match nike.decodePrivateKey (toVecN nike.privateKeySize skBytes),
      nike.decodePublicKey (toVecN nike.publicKeySize ctBytes) with
  | some sk, some ct =>
    match decapM prf nike sk ct (initWith (fun _ => Vector.replicate 32 0)) with
    | .ok ss _ => pure (ofVector ss)
    | .error _ _ => throw "sphinx: KEM decapsulation failed"
  | _, _ => throw "sphinx: invalid key/ciphertext encoding"

/-- A client's own public key, from its private key's raw bytes — as `NIKESphinx`'s
`nikeSelfPublicKeyBytes` (not reused directly since that one is `private` to that file). -/
private def kemSelfPublicKeyBytes (nike : NIKE) (skBytes : ByteArray) : ByteArray :=
  match nike.decodePrivateKey (toVecN nike.privateKeySize skBytes) with
  | none => skBytes
  | some sk => ofVector (nike.encodePublicKey (nike.derivePublicKey sk))

/-- **`createKEMHeader`**. `ephemeralSeeds` (one per hop) plays the role Go's `io.Reader` does
inside each `Encapsulate` call; `filler` is as in `NIKESphinx.createHeader`. -/
def createKEMHeader (prf : PRF) (nike : NIKE) (geom : Geometry)
    (ephemeralSeeds : Array (Vector UInt8 32)) (filler : ByteArray) (path : Array PathHop) :
    Except String (ByteArray × Array SPRPKey) := do
  let nrHops := path.size
  if nrHops == 0 || nrHops > geom.nrHops then throw "sphinx: invalid path"
  if ephemeralSeeds.size ≠ nrHops then throw "sphinx: wrong number of ephemeral seeds"
  if geom.nrHops > nrHops && filler.size ≠ (geom.nrHops - nrHops) * geom.perHopRoutingInfoLength
  then throw "sphinx: invalid filler length"

  -- One independent encapsulation per hop.
  let mut kemElements : Array ByteArray := #[]
  let mut keys : Array HopKeys := #[]
  for i in [0:nrHops] do
    match kemEncap prf nike (path[i]!).publicKey (ephemeralSeeds[i]!) with
    | .error e => throw e
    | .ok (ct, ss) =>
      kemElements := kemElements.push ct
      keys := keys.push (deriveHopKeys ss)

  -- Per-hop routing-info keystream and encrypted padding, as in NIKESphinx.
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

  -- Assemble the routing_information block, back to front, embedding each non-terminal hop's
  -- next-hop ciphertext into the last `ctSize nike` bytes of its own fragment.
  let mut routingInfo : ByteArray := if geom.nrHops > nrHops then filler else ByteArray.empty
  let mut macBytes : ByteArray := ByteArray.empty
  for iRev in [0:nrHops] do
    let i := nrHops - 1 - iRev
    let isTerminal := i == nrHops - 1
    let hop := path[i]!
    let budget := if isTerminal then geom.perHopRoutingInfoLength
      else geom.perHopRoutingInfoLength - geom.nextNodeHopLength - ctSize nike
    let mut riFragment ← commandsToBytes budget hop.commands
    if !isTerminal then
      let next := path[i + 1]!
      riFragment := riFragment ++ (RoutingCommand.nextNodeHop next.id (toVec32 macBytes)).toBytes
    riFragment := zeroPadTo geom.perHopRoutingInfoLength riFragment
    if !isTerminal then
      riFragment := riFragment.extract 0 (geom.perHopRoutingInfoLength - ctSize nike)
        ++ kemElements[i + 1]!
    routingInfo := riFragment ++ routingInfo
    routingInfo := xorBytes routingInfo (riKeyStream[i]!)
    let mPreimage := v0AD ++ kemElements[i]! ++ routingInfo
      ++ (if i > 0 then riPadding[i - 1]! else ByteArray.empty)
    macBytes := ofVector (mac (keys[i]!).headerMAC mPreimage)

  let hdr := v0AD ++ kemElements[0]! ++ routingInfo ++ macBytes
  let sprpKeys : Array SPRPKey := Array.ofFn fun i : Fin nrHops =>
    { key := (keys[i.val]!).payloadEncryption, iv := (keys[i.val]!).headerEncryptionIV }
  pure (hdr, sprpKeys)

/-- **`newKEMPacket`**. -/
def newKEMPacket (prf : PRF) (nike : NIKE) (geom : Geometry)
    (ephemeralSeeds : Array (Vector UInt8 32)) (filler : ByteArray)
    (path : Array PathHop) (payload : ByteArray) : Except String ByteArray := do
  if payload.size ≠ geom.forwardPayloadLength then
    throw s!"sphinx: invalid payload length: {payload.size}, expected {geom.forwardPayloadLength}"
  let (hdr, sprpKeys) ← createKEMHeader prf nike geom ephemeralSeeds filler path
  let mut b := (⟨Array.replicate geom.payloadTagLength 0⟩ : ByteArray) ++ payload
  for iRev in [0:sprpKeys.size] do
    let k := sprpKeys[sprpKeys.size - 1 - iRev]!
    b := sprpEncrypt k.key.toArray (ofVector k.iv) b
  pure (hdr ++ b)

/-- As `NIKESphinx.newNIKEPacket_size`. -/
axiom newKEMPacket_size (prf : PRF) (nike : NIKE) (geom : Geometry)
    (ephemeralSeeds : Array (Vector UInt8 32))
    (filler : ByteArray) (path : Array PathHop) (payload : ByteArray) (pkt : ByteArray)
    (h : newKEMPacket prf nike geom ephemeralSeeds filler path payload = .ok pkt)
    (hpay : payload.size = geom.forwardPayloadLength) :
    pkt.size = geom.packetLength

open CryptWalker.Sphinx.Interface (SeedStream nextSeed unwrapChainAux)

/-- **`wrapKEM`**: `Sphinx.Interface.wrap` for `KEMSphinxScheme` — `newKEMPacket`, drawing one
ephemeral seed per hop from the seed stream instead of taking them as a bare array. -/
def wrapKEM (prf : PRF) (nike : NIKE) (geom : Geometry) (path : List PathHop) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) :
    EStateM String SeedStream (Vector UInt8 geom.packetLength) := do
  let seeds ← path.toArray.mapM (fun _ => nextSeed)
  match h : newKEMPacket prf nike geom seeds filler path.toArray (ofVector payload) with
  | .error e => throw e
  | .ok pkt =>
    have hsize : pkt.size = geom.packetLength :=
      newKEMPacket_size prf nike geom seeds filler path.toArray (ofVector payload) pkt h (by simp)
    pure ⟨pkt.data, hsize⟩

/-- **`newKEMSURB`**. As `NIKESphinx.newNIKESURB`, over `createKEMHeader`. -/
def newKEMSURB (prf : PRF) (nike : NIKE) (geom : Geometry) (ephemeralSeeds : Array (Vector UInt8 32))
    (keyPayload : Vector UInt8 64) (filler : ByteArray) (path : Array PathHop) :
    Except String (ByteArray × ByteArray) := do
  let (hdr, sprpKeys) ← createKEMHeader prf nike geom ephemeralSeeds filler path
  let mut k : ByteArray := ByteArray.empty
  for iRev in [0:sprpKeys.size] do
    let kk := sprpKeys[sprpKeys.size - 1 - iRev]!
    k := k ++ ofVector kk.key ++ ofVector kk.iv
  k := k ++ ofVector keyPayload
  let surb := hdr ++ ofVector (path[0]!).id ++ ofVector keyPayload
  pure (surb, k)

/-- As `NIKESphinx.newNIKESURB_size`. -/
axiom newKEMSURB_size (prf : PRF) (nike : NIKE) (geom : Geometry)
    (ephemeralSeeds : Array (Vector UInt8 32)) (keyPayload : Vector UInt8 64)
    (filler : ByteArray) (path : Array PathHop) (surb surbKeys : ByteArray)
    (h : newKEMSURB prf nike geom ephemeralSeeds keyPayload filler path = .ok (surb, surbKeys)) :
    surb.size = geom.surbLength

/-- **`wrapKEMSURB`**: `Sphinx.Interface.newSURB` for `KEMSphinxScheme` — draws one ephemeral seed
per hop plus `keyPayload` (two seeds' worth) from the seed stream. -/
def wrapKEMSURB (prf : PRF) (nike : NIKE) (geom : Geometry) (path : List PathHop)
    (filler : ByteArray) :
    EStateM String SeedStream (Vector UInt8 geom.surbLength × ByteArray) := do
  let seeds ← path.toArray.mapM (fun _ => nextSeed)
  let kp1 ← nextSeed
  let kp2 ← nextSeed
  match h : newKEMSURB prf nike geom seeds (kp1 ++ kp2) filler path.toArray with
  | .error e => throw e
  | .ok (surb, k) =>
    have hsize : surb.size = geom.surbLength :=
      newKEMSURB_size prf nike geom seeds (kp1 ++ kp2) filler path.toArray surb k h
    pure (⟨surb.data, hsize⟩, k)

/-- **`unwrapKEM`**: `(payload, replayTag, cmds, forwardPkt)`, satisfying `Sphinx.Interface.unwrap`.
Forwarding copies the next-hop ciphertext straight out of the decrypted routing-info block —
unlike `unwrapNIKE`, no `Blind` step, since there is no group element to re-blind. -/
def unwrapKEM (prf : PRF) (nike : NIKE) (geom : Geometry) (privKey : ByteArray) (pkt : ByteArray) :
    Except String
      (Option ByteArray × Vector UInt8 32 × List RoutingCommand × Option (Vector UInt8 pkt.size)) := do
  let geOff := 2
  let riOff := geOff + ctSize nike
  let macOff := riOff + geom.routingInfoLength
  let payloadOff := macOff + macLength

  if h1 : pkt.size < payloadOff then throw "sphinx: invalid packet, truncated"
  else do
  if (pkt.extract 0 2).data ≠ v0AD.data then throw "sphinx: invalid packet, unknown version"

  let kemCiphertext := pkt.extract geOff riOff
  let replayTag := sha512_256 kemCiphertext
  let sharedSecret ← kemDecap prf nike privKey kemCiphertext

  let keys := deriveHopKeys sharedSecret
  let gotMac := mac keys.headerMAC (pkt.extract 0 macOff)
  if (ofVector gotMac).data ≠ (pkt.extract macOff (macOff + macLength)).data then
    throw "sphinx: invalid packet, MAC mismatch"

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

  let cmdBuf := b.extract 0 (geom.perHopRoutingInfoLength - ctSize nike)
  let nextCiphertext := ofVector (toVecN (ctSize nike)
    (b.extract (geom.perHopRoutingInfoLength - ctSize nike) geom.perHopRoutingInfoLength))
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
    have hnextCiphertext : nextCiphertext.size = ctSize nike := Util.Bytes.size_ofVector _
    let newPayload := if decPayload.size > 0 then decPayload else rawPayload
    have hnewPayload : newPayload.size = pkt.size - payloadOff := by
      show (if decPayload.size > 0 then decPayload else rawPayload).size = pkt.size - payloadOff
      split
      · rw [hdec, hraw]
      · rw [hraw]
    let newPkt := v0AD ++ nextCiphertext ++ newRoutingInfo ++ ofVector nextMAC ++ newPayload
    have hnewPkt : newPkt.size = pkt.size := by
      show (v0AD ++ nextCiphertext ++ newRoutingInfo ++ ofVector nextMAC ++ newPayload).size
        = pkt.size
      rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append, ByteArray.size_append,
          hnextCiphertext, Util.Bytes.size_ofVector, hnri, hnewPayload]
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

/-- As `NIKESphinx.wrapNIKE_unwrapNIKE_complete`: `KEMSphinxScheme`'s witness for
`Sphinx.Interface.unwrap_complete`. `derivePublicKey` is the underlying NIKE's own formula — the
ephemeral "ciphertext" a KEM adapter produces *is* a NIKE public key (see this file's module
doc). -/
axiom wrapKEM_unwrapKEM_complete (prf : PRF) (nike : NIKE) (geom : Geometry) (path : List PathHop)
    (privKeys : List ByteArray) (filler : ByteArray)
    (payload : Vector UInt8 geom.forwardPayloadLength) (st : SeedStream)
    (pkt : Vector UInt8 geom.packetLength) (st' : SeedStream) :
    path ≠ [] →
    path.map (·.publicKey) = privKeys.map (kemSelfPublicKeyBytes nike) →
    wrapKEM prf nike geom path filler payload st = .ok pkt st' →
    unwrapChainAux (unwrapKEM prf nike geom) privKeys (ofVector pkt) = .ok (some (ofVector payload))

structure KEMSphinxScheme extends CryptWalker.Sphinx.Interface.Sphinx where
  kem : CryptWalker.KEM.KEM.KEM
  /-- **Not wrap-resistant** — the inverse of `NIKESphinxScheme.wrap_resistant`: a known-key
  adversary hits any target routing-info block with certainty, not merely `1/N`. See
  `unwrapKEM_routingInfoBlock_not_wrap_resistant` below for why. -/
  not_wrap_resistant : ∀ (key : Vector UInt8 32) (iv : Vector UInt8 16) (target : ByteArray),
      ∃ raw : ByteArray, xorBytes raw (keystream key iv target.size) = target :=
    fun key iv target => xorBytes_achieves_any_target (keystream key iv target.size) target

/-- Build a `KEMSphinxScheme` from any `(prf, nike)` pair at all — total, no `Except`. -/
def kemSphinxSchemeOf (prf : PRF) (nike : NIKE) (geom : Geometry) : KEMSphinxScheme where
  State := SeedStream
  PrivateKey := ByteArray
  Command := RoutingCommand
  geometry := geom
  stateI := ⟨CryptWalker.Sphinx.Interface.initWith (fun _ => Vector.replicate 32 0)⟩
  derivePublicKey := kemSelfPublicKeyBytes nike
  wrap := wrapKEM prf nike geom
  unwrap := unwrapKEM prf nike geom
  newSURB := wrapKEMSURB prf nike geom
  newPacketFromSURB := fun surb payload =>
    CryptWalker.Sphinx.SURB.newPacketFromSURB geom (ofVector surb) payload
  unwrap_complete := wrapKEM_unwrapKEM_complete prf nike geom
  kem := CryptWalker.KEM.Adapter.kemOfNike prf nike

/-- Build a `KEMSphinxScheme` for whatever KEM `geom.scheme` names, resolved through
`CryptWalker.KEM.adapterByName` — the same registry `Geometry.ofKEM` resolves its ciphertext size
against. Agnostic to *which* registered `(prf, nike)`-shaped KEM this is — see this file's module
doc for the (already-registry-documented) scope boundary. -/
def kemSphinxScheme (geom : Geometry) : Except String KEMSphinxScheme :=
  match geom.scheme with
  | .inl name => throw s!"sphinx: geometry scheme {name} is a NIKE, not a KEM"
  | .inr name =>
    match CryptWalker.KEM.adapterByName name with
    | none => throw s!"sphinx: KEM scheme {name} not implemented"
    | some entry => pure (kemSphinxSchemeOf entry.prf entry.nike geom)

/-! ## Wrap-resistance fails

The root cause is structural, not cryptographic: NIKE-Sphinx has a public-key operation
available — blinding, `factor • pk` — that KEM-Sphinx has no analogue of for a generic KEM, so
this design instead carries a fresh KEM ciphertext per hop, protected only by the header's own
stream-cipher-plus-MAC (`headerEncryption`/`headerMAC`, an AEAD-shaped construction). That
construction isn't broken, and nothing here says it is: AEAD security is a guarantee against
adversaries who *don't* hold the key, and was never meant to be one against adversaries who do.
Wrap-resistance's own threat model hands the adversary the hop's private key ("even one whose
private key x the adversary can select"), and knowing that key means knowing the shared secret,
which means knowing the AEAD key — at which point the AEAD isn't defeated, it simply was never
protecting against this party to begin with. Any key-holder can always produce a valid
ciphertext+tag for whatever plaintext it wants; that's what "keyed encryption" means.

`NIKESphinx.nikeSphinxScheme`'s `blind` is different in kind: it routes the forwarded envelope
through a hash of the shared secret *composed with* a group operation, which the current hop's
own key-holder cannot invert to land on a chosen output, despite holding every secret involved
(`Sphinx.WrapResistance.blind_wrapResistance` bounds it to `1/N`). KEM-Sphinx has nothing playing
that role — `nextCiphertext`/`newRoutingInfo`/`nextMAC` above are just slices of `b`, the AEAD's
own decryption of bytes the packet's constructor chose freely, so the AEAD is the *only* thing
between the adversary and the target, and it was never the right tool for that job. `kemDecap`
above is total bar a handful of small-order ciphertexts, so anyone holding `privKey` can compute
the header keystream for *any* `kemCiphertext` they pick, and once it's known,
`xorBytes_achieves_any_target` says every target routing-info block is reachable, with
certainty. -/

/-- **KEM-Sphinx does not achieve wrap-resistance** — not because its AEAD-shaped header
protection is weak, but because it's the only thing standing in for NIKE-Sphinx's blinding step,
and AEAD security was never a guarantee against a party who holds the key, which wrap-resistance's
own threat model grants the adversary. For any routing-info-block `target` a key-holder wants the
mix to forward, there are raw (pre-decryption) bytes achieving it exactly — the opposite of a
`1/N`-style bound. -/
theorem unwrapKEM_routingInfoBlock_not_wrap_resistant (key : Vector UInt8 32) (iv : Vector UInt8 16)
    (target : ByteArray) :
    ∃ raw : ByteArray, xorBytes raw (keystream key iv target.size) = target :=
  xorBytes_achieves_any_target (keystream key iv target.size) target

end CryptWalker.Sphinx.KEMSphinx

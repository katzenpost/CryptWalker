/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.constants
import CryptWalker.NIKE.Schemes
import CryptWalker.KEM.Schemes

namespace CryptWalker.Sphinx.Geometry

-- `Geometry` repeats the namespace, as `NIKE`/`KEM`/`Sphinx` do theirs; harmless (see
-- `sphinx.lean`'s own suppression of this same linter).
set_option linter.dupNamespace false

open CryptWalker.Sphinx.Constants

/-! # Sphinx packet geometry

Port of `katzenpost/core/sphinx/geo/geo.go` + `geo_impl.go`'s `geometryFactory`: given a hop
count, a target payload size, and the chosen scheme, compute every fixed byte offset Sphinx's
header/routing-info/packet layout needs.

`ofNIKE`/`ofKEM` take a bare scheme name (as Go's config format does) and resolve it against
`CryptWalker.NIKE.byName`/`CryptWalker.KEM.byName`, so a returned `Geometry`'s stored name and
derived sizes can never disagree. `Geometry.scheme : String ⊕ String` (`Sum.inl`/`Sum.inr`)
replaces Go's separate nullable `NIKEName`/`KEMName`, making "exactly one of NIKE or KEM" a fact
of the type rather than a runtime invariant.

Dropped relative to Go's `Geometry`: `Marshal`/`Display`/`Hash`/`String` (I/O-and-display
conveniences, orthogonal to the packet crypto this project is porting). -/

structure Geometry where
  /-- Which scheme this geometry's sizes were derived for, by its canonical `hpqc` name —
  `Sum.inl` for a NIKE, `Sum.inr` for a KEM. Replaces Go's `NIKEName`/`KEMName` pair. -/
  scheme                       : String ⊕ String
  packetLength                : Nat
  nrHops                      : Nat
  headerLength                 : Nat
  routingInfoLength            : Nat
  perHopRoutingInfoLength      : Nat
  surbLength                   : Nat
  sphinxPlaintextHeaderLength  : Nat
  payloadTagLength             : Nat
  forwardPayloadLength         : Nat
  userForwardPayloadLength     : Nat
  nextNodeHopLength            : Nat
  sprpKeyMaterialLength        : Nat
  deriving Repr

/-- `geometryFactory.deriveForwardPayloadLength`: the payload size a SURB-carrying packet needs,
given the size the caller actually wants delivered. -/
private def deriveForwardPayloadLength (surbLen userForwardPayloadLength : Nat) : Nat :=
  userForwardPayloadLength + sphinxPlaintextHeaderLength + surbLen

private def buildNIKE (name : String) (nikePublicKeySize userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) : Geometry :=
  let perHop := nextNodeHopLength + surbReplyLength
  let routingInfo := perHop * nrHops
  let header := adLength + nikePublicKeySize + routingInfo + macLength
  let surb := header + nodeIDLength + sprpKeyMaterialLength
  let forwardPayload :=
    if withSURB then deriveForwardPayloadLength surb userForwardPayloadLength
    else userForwardPayloadLength
  { scheme := .inl name
    packetLength := header + payloadTagLength + forwardPayload
    nrHops
    headerLength := header
    routingInfoLength := routingInfo
    perHopRoutingInfoLength := perHop
    surbLength := surb
    sphinxPlaintextHeaderLength := sphinxPlaintextHeaderLength
    payloadTagLength := payloadTagLength
    forwardPayloadLength := forwardPayload
    userForwardPayloadLength := userForwardPayloadLength
    nextNodeHopLength := nextNodeHopLength
    sprpKeyMaterialLength := sprpKeyMaterialLength }

private def buildKEM (name : String) (kemCiphertextSize userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) : Geometry :=
  let perHop := nextNodeHopLength + surbReplyLength + kemCiphertextSize
  let routingInfo := perHop * nrHops
  let header := adLength + kemCiphertextSize + routingInfo + macLength
  let surb := header + nodeIDLength + sprpKeyMaterialLength
  let forwardPayload :=
    if withSURB then deriveForwardPayloadLength surb userForwardPayloadLength
    else userForwardPayloadLength
  { scheme := .inr name
    packetLength := header + payloadTagLength + forwardPayload
    nrHops
    headerLength := header
    routingInfoLength := routingInfo
    perHopRoutingInfoLength := perHop
    surbLength := surb
    sphinxPlaintextHeaderLength := sphinxPlaintextHeaderLength
    payloadTagLength := payloadTagLength
    forwardPayloadLength := forwardPayload
    userForwardPayloadLength := userForwardPayloadLength
    nextNodeHopLength := nextNodeHopLength
    sprpKeyMaterialLength := sprpKeyMaterialLength }

/-- `GeometryFromUserForwardPayloadLength`, ported with `Validate`'s scheme-name check folded in:
`nikeSchemeName` resolves against `CryptWalker.NIKE.byName`, and the public-key size comes only
from that lookup, never from a caller-supplied number. -/
def ofNIKE (nikeSchemeName : String) (userForwardPayloadLength : Nat) (withSURB : Bool)
    (nrHops : Nat) : Except String Geometry :=
  match CryptWalker.NIKE.byName nikeSchemeName with
  | none => throw s!"geometry has invalid NIKE Scheme {nikeSchemeName}"
  | some scheme =>
    pure (buildNIKE nikeSchemeName scheme.publicKeySize userForwardPayloadLength withSURB nrHops)

/-- `KEMGeometryFromUserForwardPayloadLength`, ported the same way — see `ofNIKE`. -/
def ofKEM (kemSchemeName : String) (userForwardPayloadLength : Nat) (withSURB : Bool)
    (nrHops : Nat) : Except String Geometry :=
  match CryptWalker.KEM.byName kemSchemeName with
  | none => throw s!"geometry has invalid KEM Scheme {kemSchemeName}"
  | some scheme =>
    pure (buildKEM kemSchemeName scheme.ciphertextSize userForwardPayloadLength withSURB nrHops)

/-- The reverse of `ofNIKE`: given a target *total packet size* rather than a target payload
size, solve for the `userForwardPayloadLength` that hits it exactly, then build the geometry the
usual way. Not a katzenpost port — `geo.go`/`geo_impl.go` have no such factory, only the forward
direction. `headerLength`/`surbLength` depend only on the scheme and hop count, never on the
payload length (`buildNIKE`'s own definition), so `probe` (built with a throwaway `0` payload)
reads them off safely before `overhead` is known and the real payload size is solved for. Unlike
Go's `int`-based arithmetic, which would silently go negative for a too-small target, `Nat`
forces an explicit check: this throws rather than truncating. -/
def ofNIKETargetSize (nikeSchemeName : String) (targetPacketLength : Nat) (withSURB : Bool)
    (nrHops : Nat) : Except String Geometry :=
  match CryptWalker.NIKE.byName nikeSchemeName with
  | none => throw s!"geometry has invalid NIKE Scheme {nikeSchemeName}"
  | some scheme =>
    -- `probe`'s own `packetLength`, at the throwaway payload `0`, is exactly the fixed overhead
    -- (header + tag + whatever SURB reservation `withSURB` adds) — no need to re-derive that sum.
    let probe := buildNIKE nikeSchemeName scheme.publicKeySize 0 withSURB nrHops
    if targetPacketLength < probe.packetLength then
      throw s!"geometry: target packet size {targetPacketLength} too small for \
        {probe.packetLength}-byte overhead"
    else
      pure (buildNIKE nikeSchemeName scheme.publicKeySize
        (targetPacketLength - probe.packetLength) withSURB nrHops)

/-- As `ofNIKETargetSize`, for the KEM side — see there. -/
def ofKEMTargetSize (kemSchemeName : String) (targetPacketLength : Nat) (withSURB : Bool)
    (nrHops : Nat) : Except String Geometry :=
  match CryptWalker.KEM.byName kemSchemeName with
  | none => throw s!"geometry has invalid KEM Scheme {kemSchemeName}"
  | some scheme =>
    let probe := buildKEM kemSchemeName scheme.ciphertextSize 0 withSURB nrHops
    if targetPacketLength < probe.packetLength then
      throw s!"geometry: target packet size {targetPacketLength} too small for \
        {probe.packetLength}-byte overhead"
    else
      pure (buildKEM kemSchemeName scheme.ciphertextSize
        (targetPacketLength - probe.packetLength) withSURB nrHops)

open CryptWalker.NIKE.NIKE (NIKE)
open CryptWalker.KEM.KEM (KEM)

/-- What it means for `geom` to have actually been built for `nike` via `buildNIKE`: `buildNIKE`'s
field equations, spelled out directly. Every `ofNIKE` result satisfies this for the `nike` it
resolved (`ofNIKE_validForNIKE`). Needed because `createHeader`/`newNIKEPacket`/`newNIKESURB`
accept any `(nike, geom)` pair — nothing in their types pins the two together. -/
@[reducible] def Geometry.ValidForNIKE (geom : Geometry) (nike : NIKE) : Prop :=
  geom.nextNodeHopLength = CryptWalker.Sphinx.Constants.nextNodeHopLength ∧
  geom.perHopRoutingInfoLength = geom.nextNodeHopLength + surbReplyLength ∧
  geom.routingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops ∧
  geom.headerLength = adLength + nike.publicKeySize + geom.routingInfoLength + macLength ∧
  geom.packetLength = geom.headerLength + geom.payloadTagLength + geom.forwardPayloadLength ∧
  geom.surbLength = geom.headerLength + nodeIDLength + CryptWalker.Sphinx.Constants.sprpKeyMaterialLength

/-- As `Geometry.ValidForNIKE`, for the KEM side (`buildKEM`): the ciphertext slot's width is
`kem.ciphertextSize`, folded into `perHopRoutingInfoLength` too, since `createKEMHeader` embeds a
full ciphertext at every hop, not just the header's leading element. -/
@[reducible] def Geometry.ValidForKEM (geom : Geometry) (kem : KEM) : Prop :=
  geom.nextNodeHopLength = CryptWalker.Sphinx.Constants.nextNodeHopLength ∧
  geom.perHopRoutingInfoLength = geom.nextNodeHopLength + surbReplyLength + kem.ciphertextSize ∧
  geom.routingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops ∧
  geom.headerLength = adLength + kem.ciphertextSize + geom.routingInfoLength + macLength ∧
  geom.packetLength = geom.headerLength + geom.payloadTagLength + geom.forwardPayloadLength ∧
  geom.surbLength = geom.headerLength + nodeIDLength + CryptWalker.Sphinx.Constants.sprpKeyMaterialLength

/-- As `ofNIKE`, for a caller that already holds a concrete `nike` rather than a name to look up
against `byName` — e.g. a self-test exercising a specific registered scheme's implementation
directly. `label` only ends up in the result's `scheme` field (for display/debugging); unlike
`ofNIKE` it plays no role in the computation, so building this needs no `byName` witness, and
(unlike `ofNIKE`) it never fails. -/
def ofNIKEWith (label : String) (nike : NIKE) (userForwardPayloadLength : Nat) (withSURB : Bool)
    (nrHops : Nat) : Geometry :=
  buildNIKE label nike.publicKeySize userForwardPayloadLength withSURB nrHops

/-- `ofNIKEWith`'s result is `ValidForNIKE nike` unconditionally — it's built from `nike.
publicKeySize` directly, not resolved by name, so there's nothing to prove beyond unfolding. -/
theorem ofNIKEWith_validForNIKE (label : String) (nike : NIKE) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) :
    (ofNIKEWith label nike userForwardPayloadLength withSURB nrHops).ValidForNIKE nike :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- As `ofNIKE_payloadTagLength`, for `ofNIKEWith`. -/
theorem ofNIKEWith_payloadTagLength (label : String) (nike : NIKE) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) :
    (ofNIKEWith label nike userForwardPayloadLength withSURB nrHops).payloadTagLength =
      CryptWalker.Sphinx.Constants.payloadTagLength := rfl

/-- As `ofNIKEWith`, for the KEM side. -/
def ofKEMWith (label : String) (kem : KEM) (userForwardPayloadLength : Nat) (withSURB : Bool)
    (nrHops : Nat) : Geometry :=
  buildKEM label kem.ciphertextSize userForwardPayloadLength withSURB nrHops

theorem ofKEMWith_validForKEM (label : String) (kem : KEM) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) :
    (ofKEMWith label kem userForwardPayloadLength withSURB nrHops).ValidForKEM kem :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem ofKEMWith_payloadTagLength (label : String) (kem : KEM) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) :
    (ofKEMWith label kem userForwardPayloadLength withSURB nrHops).payloadTagLength =
      CryptWalker.Sphinx.Constants.payloadTagLength := rfl

theorem ofNIKE_validForNIKE (nikeSchemeName : String) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry) (nike : NIKE)
    (h : ofNIKE nikeSchemeName userForwardPayloadLength withSURB nrHops = .ok geom)
    (hn : CryptWalker.NIKE.byName nikeSchemeName = some nike) :
    geom.ValidForNIKE nike := by
  unfold ofNIKE at h
  rw [hn] at h
  injection h with h
  subst h
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem ofKEM_validForKEM (kemSchemeName : String) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry) (kem : KEM)
    (h : ofKEM kemSchemeName userForwardPayloadLength withSURB nrHops = .ok geom)
    (hk : CryptWalker.KEM.byName kemSchemeName = some kem) :
    geom.ValidForKEM kem := by
  unfold ofKEM at h
  rw [hk] at h
  injection h with h
  subst h
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- `payloadTagLength` (`Constants.payloadTagLength`) is a pure protocol constant — `buildKEM`
sets it the same way regardless of which `kem` resolved, so unlike `ValidForKEM` this needs no
`byName` witness. Lets a caller holding only `ofKEM`'s success proof discharge
`wrapKEM_unwrapKEM_complete_valid`'s `h16` hypothesis. -/
theorem ofKEM_payloadTagLength (kemSchemeName : String) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry)
    (h : ofKEM kemSchemeName userForwardPayloadLength withSURB nrHops = .ok geom) :
    geom.payloadTagLength = CryptWalker.Sphinx.Constants.payloadTagLength := by
  unfold ofKEM at h
  split at h
  · injection h
  · injection h with h; subst h; rfl

/-- As `ofKEM_payloadTagLength`, for the NIKE side. -/
theorem ofNIKE_payloadTagLength (nikeSchemeName : String) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry)
    (h : ofNIKE nikeSchemeName userForwardPayloadLength withSURB nrHops = .ok geom) :
    geom.payloadTagLength = CryptWalker.Sphinx.Constants.payloadTagLength := by
  unfold ofNIKE at h
  split at h
  · injection h
  · injection h with h; subst h; rfl

/-- `ofNIKETargetSize` actually hits the target it was asked for — no Go equivalent exists to
mirror (Go's forward-only factories are never checked, internally, against their own arithmetic
at all; see `geometry.lean`'s module doc history). Pure `Nat` arithmetic once the `Except`/`if`
branches are resolved. -/
theorem ofNIKETargetSize_packetLength (nikeSchemeName : String) (targetPacketLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry)
    (h : ofNIKETargetSize nikeSchemeName targetPacketLength withSURB nrHops = .ok geom) :
    geom.packetLength = targetPacketLength := by
  unfold ofNIKETargetSize at h
  split at h
  · injection h
  · rename_i scheme _
    dsimp only at h
    split at h
    · injection h
    · injection h with h
      subst h
      unfold buildNIKE deriveForwardPayloadLength at *
      dsimp only at *
      cases withSURB <;> simp_all; omega

/-- As `ofNIKETargetSize_packetLength`, for the KEM side. -/
theorem ofKEMTargetSize_packetLength (kemSchemeName : String) (targetPacketLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry)
    (h : ofKEMTargetSize kemSchemeName targetPacketLength withSURB nrHops = .ok geom) :
    geom.packetLength = targetPacketLength := by
  unfold ofKEMTargetSize at h
  split at h
  · injection h
  · rename_i scheme _
    dsimp only at h
    split at h
    · injection h
    · injection h with h
      subst h
      unfold buildKEM deriveForwardPayloadLength at *
      dsimp only at *
      cases withSURB <;> simp_all; omega

end CryptWalker.Sphinx.Geometry

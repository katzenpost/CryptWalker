/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.constants
import CryptWalker.NIKE.Schemes
import CryptWalker.KEM.Schemes

namespace CryptWalker.Sphinx.Geometry

-- `Geometry` repeats the namespace name.
set_option linter.dupNamespace false

open CryptWalker.Sphinx.Constants

/-! # Sphinx packet geometry

Every fixed byte offset of the header, routing-info, and packet layout, computed from a hop
count, a payload size, and a NIKE or KEM. -/

structure Geometry where
  /-- The scheme name: `Sum.inl` for a NIKE, `Sum.inr` for a KEM. -/
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

/-- The payload size a SURB-carrying packet needs to deliver `userForwardPayloadLength` bytes. -/
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

/-- Geometry for a NIKE named `nikeSchemeName`, with the given user payload length. -/
def ofNIKE (nikeSchemeName : String) (userForwardPayloadLength : Nat) (withSURB : Bool)
    (nrHops : Nat) : Except String Geometry :=
  match CryptWalker.NIKE.byName nikeSchemeName with
  | none => throw s!"geometry has invalid NIKE Scheme {nikeSchemeName}"
  | some scheme =>
    pure (buildNIKE nikeSchemeName scheme.publicKeySize userForwardPayloadLength withSURB nrHops)

/-- Geometry for a KEM named `kemSchemeName`, with the given user payload length. -/
def ofKEM (kemSchemeName : String) (userForwardPayloadLength : Nat) (withSURB : Bool)
    (nrHops : Nat) : Except String Geometry :=
  match CryptWalker.KEM.byName kemSchemeName with
  | none => throw s!"geometry has invalid KEM Scheme {kemSchemeName}"
  | some scheme =>
    pure (buildKEM kemSchemeName scheme.ciphertextSize userForwardPayloadLength withSURB nrHops)

/-- Geometry for a NIKE whose total packet length is `targetPacketLength`. Fails if it is smaller
than the fixed overhead. -/
def ofNIKETargetSize (nikeSchemeName : String) (targetPacketLength : Nat) (withSURB : Bool)
    (nrHops : Nat) : Except String Geometry :=
  match CryptWalker.NIKE.byName nikeSchemeName with
  | none => throw s!"geometry has invalid NIKE Scheme {nikeSchemeName}"
  | some scheme =>
    -- `probe`'s packet length at payload `0` is the fixed overhead.
    let probe := buildNIKE nikeSchemeName scheme.publicKeySize 0 withSURB nrHops
    if targetPacketLength < probe.packetLength then
      throw s!"geometry: target packet size {targetPacketLength} too small for \
        {probe.packetLength}-byte overhead"
    else
      pure (buildNIKE nikeSchemeName scheme.publicKeySize
        (targetPacketLength - probe.packetLength) withSURB nrHops)

/-- As `ofNIKETargetSize`, for a KEM. -/
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

/-- `geom` has the field values `buildNIKE` gives for `nike`. -/
@[reducible] def Geometry.ValidForNIKE (geom : Geometry) (nike : NIKE) : Prop :=
  geom.nextNodeHopLength = CryptWalker.Sphinx.Constants.nextNodeHopLength ∧
  geom.perHopRoutingInfoLength = geom.nextNodeHopLength + surbReplyLength ∧
  geom.routingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops ∧
  geom.headerLength = adLength + nike.publicKeySize + geom.routingInfoLength + macLength ∧
  geom.packetLength = geom.headerLength + geom.payloadTagLength + geom.forwardPayloadLength ∧
  geom.surbLength = geom.headerLength + nodeIDLength + CryptWalker.Sphinx.Constants.sprpKeyMaterialLength

/-- `geom` has the field values `buildKEM` gives for `kem`. -/
@[reducible] def Geometry.ValidForKEM (geom : Geometry) (kem : KEM) : Prop :=
  geom.nextNodeHopLength = CryptWalker.Sphinx.Constants.nextNodeHopLength ∧
  geom.perHopRoutingInfoLength = geom.nextNodeHopLength + surbReplyLength + kem.ciphertextSize ∧
  geom.routingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops ∧
  geom.headerLength = adLength + kem.ciphertextSize + geom.routingInfoLength + macLength ∧
  geom.packetLength = geom.headerLength + geom.payloadTagLength + geom.forwardPayloadLength ∧
  geom.surbLength = geom.headerLength + nodeIDLength + CryptWalker.Sphinx.Constants.sprpKeyMaterialLength

/-- As `ofNIKE`, for a NIKE given directly rather than by name. `label` is only stored. -/
def ofNIKEWith (label : String) (nike : NIKE) (userForwardPayloadLength : Nat) (withSURB : Bool)
    (nrHops : Nat) : Geometry :=
  buildNIKE label nike.publicKeySize userForwardPayloadLength withSURB nrHops

/-- `ofNIKEWith nike` is valid for `nike`. -/
theorem ofNIKEWith_validForNIKE (label : String) (nike : NIKE) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) :
    (ofNIKEWith label nike userForwardPayloadLength withSURB nrHops).ValidForNIKE nike :=
  ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- `ofNIKEWith` sets `payloadTagLength`. -/
theorem ofNIKEWith_payloadTagLength (label : String) (nike : NIKE) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) :
    (ofNIKEWith label nike userForwardPayloadLength withSURB nrHops).payloadTagLength =
      CryptWalker.Sphinx.Constants.payloadTagLength := rfl

/-- As `ofNIKEWith`, for a KEM. -/
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

/-- `ofKEM` sets `payloadTagLength`. -/
theorem ofKEM_payloadTagLength (kemSchemeName : String) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry)
    (h : ofKEM kemSchemeName userForwardPayloadLength withSURB nrHops = .ok geom) :
    geom.payloadTagLength = CryptWalker.Sphinx.Constants.payloadTagLength := by
  unfold ofKEM at h
  split at h
  · injection h
  · injection h with h; subst h; rfl

/-- `ofNIKE` sets `payloadTagLength`. -/
theorem ofNIKE_payloadTagLength (nikeSchemeName : String) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry)
    (h : ofNIKE nikeSchemeName userForwardPayloadLength withSURB nrHops = .ok geom) :
    geom.payloadTagLength = CryptWalker.Sphinx.Constants.payloadTagLength := by
  unfold ofNIKE at h
  split at h
  · injection h
  · injection h with h; subst h; rfl

/-- `ofNIKETargetSize` produces a geometry with exactly the target packet length. -/
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

/-- As `ofNIKETargetSize_packetLength`, for a KEM. -/
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

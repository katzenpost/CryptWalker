/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Constants
import CryptWalker.NIKE.Schemes
import CryptWalker.KEM.Schemes

namespace CryptWalker.Sphinx.Geometry

open CryptWalker.Sphinx.Constants

/-! # Sphinx packet geometry

Port of `katzenpost/core/sphinx/geo/geo.go` + `geo_impl.go`'s `geometryFactory`: given a hop
count, a target payload size, and the chosen scheme, compute every fixed byte offset Sphinx's
header/routing-info/packet layout needs.

Go's `Geometry` carries `NIKEName`/`KEMName string` fields, resolved through
`hpqc/nike/schemes.ByName`/`hpqc/kem/schemes.ByName` at construction time
(`GeometryFromUserForwardPayloadLength`/`KEMGeometryFromUserForwardPayloadLength` both take an
already-resolved `nike.Scheme`/`kem.Scheme`, so the *name* stored in the resulting `Geometry` is
just that scheme's own `.Name()`) and re-checked by `Validate` ("geometry has invalid NIKE Scheme
%s") wherever a `Geometry` arrives from outside the process (a config file, an untrusted peer).

This file used to invent its own scheme identity here — first a bare `Nat` size, then a
`Geometry`-local `NIKEScheme`/`KEMScheme` enum, then a `CryptWalker.NIKE.Schemes.RegistryEntry`
value the caller constructed directly — none of which is the right layer for it to live at
(scheme identity is a project-wide concept, `hpqc/nike/schemes`/`hpqc/kem/schemes` are used far
beyond Sphinx) or safe against a mismatch (a hand-built `RegistryEntry` could still pair
`hpqcName := "x448"` with the X25519 implementation — nothing checked the two agreed). `ofNIKE`/
`ofKEM` now take a bare scheme *name*, exactly as Go's config format does, and resolve it against
`CryptWalker.NIKE.byName`/`CryptWalker.KEM.byName` — the project's one real
registry — failing with Go's own `Validate` message if the name isn't registered. There is no
longer any way to reach a `Geometry` whose stored name and derived sizes disagree, because there
is no longer a code path that accepts the two as independent inputs.

`Geometry.scheme : String ⊕ String` (`Sum.inl` for a NIKE's `hpqc` name, `Sum.inr` for a KEM's)
replaces Go's separate nullable `NIKEName`/`KEMName`: a `Sum` makes "exactly one of NIKE or KEM"
a fact of the type, not a runtime invariant `Validate` has to separately check for.

Still dropped relative to Go's `Geometry`: `Marshal`/`Display`/`Hash`/`String` (I/O-and-display
conveniences, orthogonal to the packet crypto this project is porting). -/

structure Geometry where
  /-- Which scheme this geometry's sizes were derived for, by its canonical `hpqc` name —
  `Sum.inl` for a NIKE (`CryptWalker.NIKE.byName` resolves it back to the
  implementation), `Sum.inr` for a KEM (`CryptWalker.KEM.byName`). Replaces Go's
  `NIKEName`/`KEMName` pair — see the module doc. -/
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

/-- `GeometryFromUserForwardPayloadLength`, ported with `Validate`'s scheme-name check folded in
up front rather than left for a caller to remember to run separately: `nikeSchemeName` is
resolved against `CryptWalker.NIKE.byName` (case-insensitively, as Go's `ByName` does),
and the derived public-key size comes *only* from that lookup, never from a caller-supplied
number — so a `Geometry` this returns is, by construction, never mismatched. -/
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

open CryptWalker.NIKE.NIKE (NIKE)
open CryptWalker.KEM.KEM (KEM)

/-- What it means for `geom` to have actually been built for `nike` via `buildNIKE` — exactly
`buildNIKE`'s own field equations, spelled out directly rather than through the existence of some
unnamed `ofNIKE` call. Every `Geometry.ofNIKE` result satisfies this for the `nike` it resolved
(`ofNIKE_validForNIKE`). `NIKESphinx.lean`'s `nike`/`geom`-generic functions (`createHeader`,
`newNIKEPacket`, `newNIKESURB`) accept *any* `(nike, geom)` pair — nothing in their types pins them
together — so their size theorems need this as an explicit hypothesis to relate `geom`'s fixed
fields to whichever specific `nike` a caller actually hands them. -/
@[reducible] def Geometry.ValidForNIKE (geom : Geometry) (nike : NIKE) : Prop :=
  geom.nextNodeHopLength = CryptWalker.Sphinx.Constants.nextNodeHopLength ∧
  geom.perHopRoutingInfoLength = geom.nextNodeHopLength + surbReplyLength ∧
  geom.routingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops ∧
  geom.headerLength = adLength + nike.publicKeySize + geom.routingInfoLength + macLength ∧
  geom.packetLength = geom.headerLength + geom.payloadTagLength + geom.forwardPayloadLength ∧
  geom.surbLength = geom.headerLength + nodeIDLength + CryptWalker.Sphinx.Constants.sprpKeyMaterialLength

/-- As `Geometry.ValidForNIKE`, for the KEM side (`buildKEM`): the group-element/ciphertext slot's
width is `kem.ciphertextSize` rather than a NIKE's `publicKeySize`, and it's folded into
`perHopRoutingInfoLength` too (`KEMSphinx.createKEMHeader` embeds a full ciphertext at every hop,
not just the header's leading element). -/
@[reducible] def Geometry.ValidForKEM (geom : Geometry) (kem : KEM) : Prop :=
  geom.nextNodeHopLength = CryptWalker.Sphinx.Constants.nextNodeHopLength ∧
  geom.perHopRoutingInfoLength = geom.nextNodeHopLength + surbReplyLength + kem.ciphertextSize ∧
  geom.routingInfoLength = geom.perHopRoutingInfoLength * geom.nrHops ∧
  geom.headerLength = adLength + kem.ciphertextSize + geom.routingInfoLength + macLength ∧
  geom.packetLength = geom.headerLength + geom.payloadTagLength + geom.forwardPayloadLength ∧
  geom.surbLength = geom.headerLength + nodeIDLength + CryptWalker.Sphinx.Constants.sprpKeyMaterialLength

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

/-- `payloadTagLength` is a pure protocol constant (`Constants.payloadTagLength`, the width of the
all-zero tag a correctly-decrypted payload ends in) — `buildKEM` sets it the same way regardless
of which `kem` resolved, so unlike `ValidForKEM` this needs no `byName` witness at all. Lets a
caller holding only `ofKEM`'s success proof (not which specific `KEM` it resolved to) discharge
`wrapKEM_unwrapKEM_complete_valid`'s `h16` hypothesis. -/
theorem ofKEM_payloadTagLength (kemSchemeName : String) (userForwardPayloadLength : Nat)
    (withSURB : Bool) (nrHops : Nat) (geom : Geometry)
    (h : ofKEM kemSchemeName userForwardPayloadLength withSURB nrHops = .ok geom) :
    geom.payloadTagLength = CryptWalker.Sphinx.Constants.payloadTagLength := by
  unfold ofKEM at h
  split at h
  · injection h
  · injection h with h; subst h; rfl

end CryptWalker.Sphinx.Geometry

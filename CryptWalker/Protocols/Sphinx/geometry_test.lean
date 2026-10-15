/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Lean.Data.Json
import CryptWalker.Protocols.Sphinx.geometry_cbor
import CryptWalker.Util.newhex

/-! # Sphinx geometry tests

Checks `ofNIKE`/`ofKEM`, the CBOR encoding, `hash` and `validate` against
`testdata/sphinx_geometry.json`, made by `scripts/gen_geometry_vectors` from katzenpost's
`core/sphinx/geo`. -/

open Lean
open Cborg
open CryptWalker.Util.newhex
open CryptWalker.Protocols.Sphinx.Geometry

def hexField (j : Json) (k : String) : Except String ByteArray := do
  let s ← (← j.getObjVal? k).getStr?
  match hexStringToByteArray s with
  | some b => pure b
  | none => throw s!"field {k}: not valid hex"

def natField (j : Json) (k : String) : Except String Nat := do
  (← j.getObjVal? k).getNat?

def geometryOfJson (j : Json) : Except String Geometry := do
  return {
    packetLength := ← natField j "PacketLength"
    nrHops := ← natField j "NrHops"
    headerLength := ← natField j "HeaderLength"
    routingInfoLength := ← natField j "RoutingInfoLength"
    perHopRoutingInfoLength := ← natField j "PerHopRoutingInfoLength"
    surbLength := ← natField j "SURBLength"
    sphinxPlaintextHeaderLength := ← natField j "SphinxPlaintextHeaderLength"
    payloadTagLength := ← natField j "PayloadTagLength"
    forwardPayloadLength := ← natField j "ForwardPayloadLength"
    userForwardPayloadLength := ← natField j "UserForwardPayloadLength"
    nextNodeHopLength := ← natField j "NextNodeHopLength"
    sprpKeyMaterialLength := ← natField j "SPRPKeyMaterialLength"
    nikeName := ← (← j.getObjVal? "NIKEName").getStr?
    kemName := ← (← j.getObjVal? "KEMName").getStr? }

def checkVector (j : Json) : Except String Unit := do
  let isKEM ← (← j.getObjVal? "is_kem").getBool?
  let payload ← natField j "user_forward_payload_length"
  let withSURB ← (← j.getObjVal? "with_surb").getBool?
  let hops ← natField j "nr_hops"
  let want ← geometryOfJson (← j.getObjVal? "geometry")
  let cbor ← hexField j "cbor"
  let canonical ← hexField j "canonical_cbor"
  let hash ← hexField j "hash"
  let name := if isKEM then want.kemName else want.nikeName
  let built ← if isKEM then ofKEM name payload withSURB hops else ofNIKE name payload withSURB hops
  let label := s!"{name} payload={payload} surb={withSURB} hops={hops}"
  if built != want then throw s!"{label}: built geometry differs"
  if (serialise want).data != cbor.data then throw s!"{label}: encoding differs"
  if want.canonical.data != canonical.data then throw s!"{label}: canonical encoding differs"
  for (which, bytes) in [("encoding", cbor), ("canonical encoding", canonical)] do
    match deserialise (α := Geometry) bytes with
    | .error e => throw s!"{label}: {which} decode failed: {e.msg}"
    | .ok g => if g != want then throw s!"{label}: {which} decodes differently"
  if want.hash.toArray != hash.data then throw s!"{label}: hash differs"
  want.validate.mapError (s!"{label}: validate: " ++ ·)

def invalid (base : Geometry) : List (String × Geometry) :=
  [ ("no scheme", { base with nikeName := "", kemName := "" }),
    ("both schemes", { base with kemName := "MLKEM768" }),
    ("unknown NIKE", { base with nikeName := "nope" }),
    ("zero PacketLength", { base with packetLength := 0 }),
    ("zero NrHops", { base with nrHops := 0 }),
    ("zero HeaderLength", { base with headerLength := 0 }),
    ("zero RoutingInfoLength", { base with routingInfoLength := 0 }),
    ("zero PerHopRoutingInfoLength", { base with perHopRoutingInfoLength := 0 }) ]

def main : IO UInt32 := do
  let raw ← IO.FS.readFile "testdata/sphinx_geometry.json"
  let arr ← IO.ofExcept (Json.parse raw >>= Json.getArr?)
  let mut failures := 0
  for j in arr do
    if let .error e := checkVector j then
      IO.eprintln e
      failures := failures + 1
  let base ← IO.ofExcept (ofNIKE "x25519" 2000 true 5)
  for (label, g) in invalid base do
    if g.validate matches .ok () then
      IO.eprintln s!"validate accepted: {label}"
      failures := failures + 1
  if failures == 0 then
    IO.println s!"sphinx geometry: {arr.size} vectors, {(invalid base).length} invalid cases ok"
    pure 0
  else
    IO.eprintln s!"sphinx geometry: {failures} failures"
    pure 1

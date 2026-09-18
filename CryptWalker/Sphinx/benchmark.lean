/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.bench_registry
import CryptWalker.Sphinx.types
import CryptWalker.Sphinx.nike_sphinx_theorems
import CryptWalker.Sphinx.kem_sphinx_theorems
import CryptWalker.Util.Bytes
import Bench

/-! # Sphinx packet-creation / unwrap benchmarks

Modeled on katzenpost's `core/sphinx/sphinx_benchmark_test.go` (`BenchmarkSphinxCreatePackets`/
`BenchmarkSphinxUnwrap`): for every case in `BenchRegistry.sphinxBenchCases`, time packet creation
(`newNIKEPacket`/`newKEMPacket`, the same functions `sphinx.NewPacket` wraps) and, separately, a
single hop's `unwrapNIKE`/`unwrapKEM` against one pre-built packet — matching Go's own
`prepareSphinxBenchmark`, which also only unwraps the first hop, not a full chain. Node/path
generation happens outside the timed region in both cases (Go's `b.StopTimer()`/`b.StartTimer()`
split), so only the primitive under test is measured.

Unlike Go, no per-iteration defensive copy of the packet is needed for the unwrap benchmark —
`ByteArray`/`Vector` are value-semantic from the caller's side, so the same built packet can be
reused directly across iterations.

Uses a reduced iteration count (`N := 50`, not `Bench.new`'s default 1000): a 5-hop packet's AEZ +
HMAC + HKDF + AES-CTR cost is far higher per call than the single curve-multiply
`NIKE.benchmark` times, and this file runs 12 cases × 2 (create + unwrap) = 24 timed loops. -/

open Bench
open CryptWalker.Sphinx.Geometry (Geometry ofNIKE ofKEM)
open CryptWalker.Sphinx.Types
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.NIKESphinx (newNIKEPacket unwrapNIKE)
open CryptWalker.Sphinx.KEMSphinx (newKEMPacket unwrapKEM)
open CryptWalker.Sphinx.BenchRegistry
open CryptWalker.NIKE.NIKE (NIKE)
open CryptWalker.KEM.KEM (KEM)
open CryptWalker.Util.Bytes (ofVector toVecN)

private def wbCipher := CryptWalker.WideBlockCipher.AEZ.aez
private def macS := CryptWalker.MAC.HMAC.hmacSha256MAC
private def kdfS := CryptWalker.KDF.HKDF.hkdfSha256Expand
private def streamS := CryptWalker.StreamCipher.AES256CTR.aes256CTR

/-- Iterations per timed loop — see the module doc for why this is lower than `Bench.new`'s
default. -/
private def iterCount : Nat := 50

private def randomVector (n : Nat) : IO (Vector UInt8 n) := do
  let bs ← IO.getRandomBytes (USize.ofNat n)
  pure (Vector.ofFn fun i : Fin n => bs[i.val]!)

private def randomBytes (n : Nat) : IO ByteArray := IO.getRandomBytes (USize.ofNat n)

structure Node where
  id : Vector UInt8 32
  priv : Vector UInt8 32
  pub : ByteArray
  deriving Inhabited

/-- As `nike_selftest.lean`/`kem_selftest.lean`'s `derivePubBytes`: derive a node's public key
generically over whichever `NIKE`/`KEM` value is in play, via `derivePublicKey`/`encodePublicKey`
rather than any one scheme's raw arithmetic — needed since the ladder and group formulations
encode public keys differently. -/
private def derivePubBytesNIKE (nike : NIKE) (priv : Vector UInt8 32) : IO ByteArray := do
  match nike.decodePrivateKey (toVecN nike.privateKeySize (ofVector priv)) with
  | none => throw (IO.userError "derivePubBytesNIKE: decodePrivateKey failed")
  | some sk => pure (ofVector (nike.encodePublicKey (nike.derivePublicKey sk)))

private def derivePubBytesKEM (kem : KEM) (priv : Vector UInt8 32) : IO ByteArray := do
  match kem.decodePrivateKey (toVecN kem.privateKeySize (ofVector priv)) with
  | none => throw (IO.userError "derivePubBytesKEM: decodePrivateKey failed")
  | some sk => pure (ofVector (kem.encodePublicKey (kem.derivePublicKey sk)))

private def newNodeNIKE (nike : NIKE) : IO Node := do
  let priv ← randomVector 32
  let id ← randomVector 32
  let pub ← derivePubBytesNIKE nike priv
  pure { id, priv, pub }

private def newNodeKEM (kem : KEM) : IO Node := do
  let priv ← randomVector 32
  let id ← randomVector 32
  let pub ← derivePubBytesKEM kem priv
  pure { id, priv, pub }

/-- Plain forward path: `nodeDelay` on every hop but the last, `recipient` on the last — no SURB
reply. Every bench case here measures plain forward packets, matching katzenpost's own benchmark
table (its `isSURB` knob is never set in `sphinx_benchmark_test.go`'s actual cases). -/
private def buildPath (nodes : Array Node) : IO (Array PathHop) := do
  let n := nodes.size
  let mut path : Array PathHop := #[]
  for i in [0:n] do
    let node := nodes[i]!
    let cmds : List RoutingCommand ←
      if i < n - 1 then
        pure [.nodeDelay (UInt32.ofNat (1000 + i))]
      else do
        let rid ← randomVector 32
        pure [.recipient rid]
    path := path.push { id := node.id, publicKey := node.pub, commands := cmds }
  pure path

/-! ## NIKE-Sphinx -/

def benchNIKECreate (label : String) (nike : NIKE) (payloadSize nrHops : Nat) : IO Unit := do
  match ofNIKE label payloadSize false nrHops with
  | .error e => IO.eprintln s!"{label}: geometry failed: {e}"
  | .ok geom =>
    let mut b : Bench := { Bench.new with N := iterCount }
    for _ in [0:b.N] do
      let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNodeNIKE nike)
      let path ← buildPath nodes
      let clientPriv ← randomVector 32
      let payload ← randomBytes geom.forwardPayloadLength
      b ← b.start
      match newNIKEPacket nike wbCipher macS kdfS streamS geom (ofVector clientPriv)
          ByteArray.empty path payload with
      | .error e => IO.eprintln s!"newNIKEPacket failed: {e}"
      | .ok _ => pure ()
      b ← b.stop
    b.report s!"create {label} ({payloadSize}B, {nrHops} hops)"

def benchNIKEUnwrap (label : String) (nike : NIKE) (payloadSize nrHops : Nat) : IO Unit := do
  match ofNIKE label payloadSize false nrHops with
  | .error e => IO.eprintln s!"{label}: geometry failed: {e}"
  | .ok geom =>
    let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNodeNIKE nike)
    let path ← buildPath nodes
    let clientPriv ← randomVector 32
    let payload ← randomBytes geom.forwardPayloadLength
    match newNIKEPacket nike wbCipher macS kdfS streamS geom (ofVector clientPriv)
        ByteArray.empty path payload with
    | .error e => IO.eprintln s!"{label}: setup newNIKEPacket failed: {e}"
    | .ok pkt =>
      let privKey := nodes[0]!.priv
      let mut b : Bench := { Bench.new with N := iterCount }
      for _ in [0:b.N] do
        b ← b.start
        match unwrapNIKE nike wbCipher macS kdfS streamS geom (ofVector privKey) pkt with
        | .error e => IO.eprintln s!"unwrapNIKE failed: {e}"
        | .ok _ => pure ()
        b ← b.stop
      b.report s!"unwrap {label} ({payloadSize}B, {nrHops} hops)"

/-! ## KEM-Sphinx -/

def benchKEMCreate (label : String) (kem : KEM) (payloadSize nrHops : Nat) : IO Unit := do
  match ofKEM label payloadSize false nrHops with
  | .error e => IO.eprintln s!"{label}: geometry failed: {e}"
  | .ok geom =>
    let mut b : Bench := { Bench.new with N := iterCount }
    for _ in [0:b.N] do
      let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNodeKEM kem)
      let path ← buildPath nodes
      let seeds ← nodes.mapM (fun _ => randomVector 32)
      let payload ← randomBytes geom.forwardPayloadLength
      b ← b.start
      match newKEMPacket kem wbCipher macS kdfS streamS geom seeds ByteArray.empty path payload with
      | .error e => IO.eprintln s!"newKEMPacket failed: {e}"
      | .ok _ => pure ()
      b ← b.stop
    b.report s!"create {label} ({payloadSize}B, {nrHops} hops)"

def benchKEMUnwrap (label : String) (kem : KEM) (payloadSize nrHops : Nat) : IO Unit := do
  match ofKEM label payloadSize false nrHops with
  | .error e => IO.eprintln s!"{label}: geometry failed: {e}"
  | .ok geom =>
    let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNodeKEM kem)
    let path ← buildPath nodes
    let seeds ← nodes.mapM (fun _ => randomVector 32)
    let payload ← randomBytes geom.forwardPayloadLength
    match newKEMPacket kem wbCipher macS kdfS streamS geom seeds ByteArray.empty path payload with
    | .error e => IO.eprintln s!"{label}: setup newKEMPacket failed: {e}"
    | .ok pkt =>
      let privKey := nodes[0]!.priv
      let mut b : Bench := { Bench.new with N := iterCount }
      for _ in [0:b.N] do
        b ← b.start
        match unwrapKEM kem wbCipher macS kdfS streamS geom (ofVector privKey) pkt with
        | .error e => IO.eprintln s!"unwrapKEM failed: {e}"
        | .ok _ => pure ()
        b ← b.stop
      b.report s!"unwrap {label} ({payloadSize}B, {nrHops} hops)"

def main : IO Unit := do
  IO.println "-- packet creation --"
  for c in sphinxBenchCases do
    match c.kind with
    | .nike n nike => benchNIKECreate n nike c.payloadSize c.nrHops
    | .kem n kem => benchKEMCreate n kem c.payloadSize c.nrHops
  IO.println ""
  IO.println "-- unwrap --"
  for c in sphinxBenchCases do
    match c.kind with
    | .nike n nike => benchNIKEUnwrap n nike c.payloadSize c.nrHops
    | .kem n kem => benchKEMUnwrap n kem c.payloadSize c.nrHops

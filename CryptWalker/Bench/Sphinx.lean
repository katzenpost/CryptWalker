/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.bench_registry
import CryptWalker.Sphinx.types
import CryptWalker.Sphinx.nike_sphinx_theorems
import CryptWalker.Sphinx.kem_sphinx_theorems
import CryptWalker.Util.Bytes
import LeanBench

/-! # Sphinx packet-creation / unwrap benchmarks

Modeled on katzenpost's `core/sphinx/sphinx_benchmark_test.go` (`BenchmarkSphinxCreatePackets`/
`BenchmarkSphinxUnwrap`): for every case in `BenchRegistry.sphinxBenchCases`, time packet creation
(`newNIKEPacket`/`newKEMPacket`) and, separately, a single hop's `unwrapNIKE`/`unwrapKEM` against
one pre-built packet. Node/path generation runs in LeanBench's `setup?`/`beforeEach?` hooks, outside
the timed region, so only the primitive under test is measured. -/

namespace CryptWalker.Bench.Sphinx

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

private def randomVector (n : Nat) : IO (Vector UInt8 n) := do
  let bs ← IO.getRandomBytes (USize.ofNat n)
  pure (Vector.ofFn fun i : Fin n => bs[i.val]!)

private def randomBytes (n : Nat) : IO ByteArray := IO.getRandomBytes (USize.ofNat n)

structure Node where
  id : Vector UInt8 32
  priv : ByteArray
  pub : ByteArray
  deriving Inhabited

private def newNodeNIKE (nike : NIKE) : IO Node := do
  let priv ← randomVector 32
  let id ← randomVector 32
  match nike.decodePrivateKey (toVecN nike.privateKeySize (ofVector priv)) with
  | none => throw (IO.userError "newNodeNIKE: decodePrivateKey failed")
  | some sk => pure { id, priv := ofVector priv, pub := ofVector (nike.encodePublicKey (nike.derivePublicKey sk)) }

/-- Keys from `kem.generate`: padded random bytes aren't a working ML-KEM private key. -/
private def newNodeKEM (kem : KEM) : IO Node := do
  let id ← randomVector 32
  match kem.generate (kem.stateFromSeed (← randomVector 32)) with
  | .error _ _ => throw (IO.userError "newNodeKEM: kem.generate failed")
  | .ok ⟨pk, sk, _⟩ _ =>
    pure { id, priv := ofVector (kem.encodePrivateKey sk), pub := ofVector (kem.encodePublicKey pk) }

/-- Plain forward path: `nodeDelay` on every hop but the last, `recipient` on the last. -/
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

/-- One packet's worth of inputs, plus the first hop's private key. -/
private structure Inputs where
  path : Array PathHop
  clientSecret : Array (Vector UInt8 32)
  payload : ByteArray
  firstPriv : ByteArray
  deriving Inhabited

private def cfg (tag : String) : LeanBench.BenchConfig :=
  { suite := some "sphinx", tags := [tag], samples := 10, warmup := 2 }

/-- Create and unwrap benches for one scheme, given how to build inputs and run each operation. -/
private def pair (name : String) (mkInputs : IO Inputs)
    (create : Inputs → Except String ByteArray) (unwrap : Inputs → ByteArray → Except String Unit) :
    IO (Array LeanBench.Bench) := do
  let inputs ← IO.mkRef (default : Inputs)
  let pkt ← IO.mkRef ByteArray.empty
  let run {α} (e : Except String α) : IO α := IO.ofExcept (e.mapError (s!"{name}: " ++ ·))
  pure #[
    { name := s!"create {name}", config := cfg "create"
      beforeEach? := some do inputs.set (← mkInputs)
      action := do discard <| run (create (← inputs.get)) },
    { name := s!"unwrap {name}", config := cfg "unwrap"
      setup? := some do
        let i ← mkInputs
        inputs.set i
        pkt.set (← run (create i))
      action := do run (unwrap (← inputs.get) (← pkt.get)) }]

def nikeBenches (nike : NIKE) (geom : Geometry) (name : String) : IO (Array LeanBench.Bench) :=
  pair name
    (do
      let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNodeNIKE nike)
      pure { path := ← buildPath nodes, clientSecret := #[← randomVector 32]
             payload := ← randomBytes geom.forwardPayloadLength, firstPriv := nodes[0]!.priv })
    (fun i => newNIKEPacket nike wbCipher macS kdfS streamS geom (ofVector i.clientSecret[0]!)
      ByteArray.empty i.path i.payload)
    (fun i pkt => discard <| unwrapNIKE nike wbCipher macS kdfS streamS geom i.firstPriv pkt)

def kemBenches (kem : KEM) (geom : Geometry) (name : String) : IO (Array LeanBench.Bench) :=
  pair name
    (do
      let nodes ← (List.range geom.nrHops).toArray.mapM (fun _ => newNodeKEM kem)
      pure { path := ← buildPath nodes, clientSecret := ← nodes.mapM (fun _ => randomVector 32)
             payload := ← randomBytes geom.forwardPayloadLength, firstPriv := nodes[0]!.priv })
    (fun i => newKEMPacket kem wbCipher macS kdfS streamS geom i.clientSecret ByteArray.empty
      i.path i.payload)
    (fun i pkt => discard <| unwrapKEM kem wbCipher macS kdfS streamS geom i.firstPriv pkt)

/-- Every Sphinx bench: create and unwrap for each case in `sphinxBenchCases`. -/
def benches : IO (Array LeanBench.Bench) :=
  sphinxBenchCases.toArray.flatMapM fun c => do
    match c.kind with
    | .nike n nike => nikeBenches nike (← IO.ofExcept (ofNIKE n c.payloadSize false c.nrHops)) c.name
    | .kem n kem => kemBenches kem (← IO.ofExcept (ofKEM n c.payloadSize false c.nrHops)) c.name

end CryptWalker.Bench.Sphinx

/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Pigeonhole.Protocol
import Cslib.Foundations.Semantics.LTS.TraceEq

/-! # The Pigeonhole replica and its wire-level exchange as labelled transition systems

`Replica.step` and `Protocol.rpc` are plain functions. This file puts them on cslib's `LTS`, so the
protocol's guarantees become statements in the vocabulary cslib provides for reasoning about
systems:

* `replicaLTS`: the abstract replica. A state is a store; a label is a request together with the
  reply it got; `s ─(r, reply)→ s'` when `step s r = (s', reply)`. It is `Deterministic`.
* **Invariants** (`TrInv`, `MTrInv`, `CanReach`): "every stored box verifies" holds in every state
  reachable from the empty store (`replicaLTS_reachable_valid`), by cslib's `mtrInv_of_trInv` from
  the single-step fact `Replica.step_valid`.
* `rpcLTS`: the system a client sees, with each request MKEM-encrypted, sent, decrypted, handled
  and the reply MKEM-sealed and opened. A step exists only where the exchange completes.
* **Simulation** (`IsSimulation`): `rpcLTS` is simulated by `replicaLTS` under the identity on
  stores (`rpcLTS_simulated`), which is `rpc_sound` restated. So anything a client can observe is
  something the abstract replica could do, and `traces_subset` says it for whole runs. Safety
  properties of the replica (the invariant above) therefore hold for the encrypted system
  (`rpcLTS_reachable_valid`).

The converse (every abstract behaviour is realisable over the wire) is not claimed: exchanges may
fail, and whether they do depends on keys and randomness. -/

namespace CryptWalker.Pigeonhole.Semantics

open Cslib Cslib.LTS
open CryptWalker.Sign.Sign (Signature)
open CryptWalker.KEM.MKEM (MKEM)
open CryptWalker.Pigeonhole.Replica
open CryptWalker.Pigeonhole.Protocol

variable {Sg : Signature} [DecidableEq Sg.PublicKey]

/-- The abstract replica. -/
def replicaLTS (boxSize : Nat) : LTS (Store Sg) (Request Sg × Reply Sg) :=
  ⟨fun s l s' => step boxSize s l.1 = (s', l.2)⟩

instance (boxSize : Nat) : (replicaLTS (Sg := Sg) boxSize).Deterministic :=
  ⟨fun _ _ _ _ h2 h3 => congrArg Prod.fst (h2.symm.trans h3)⟩

/-- Every step of the replica preserves "every stored box verifies". -/
theorem replicaLTS_trInv (boxSize : Nat) : (replicaLTS (Sg := Sg) boxSize).TrInv Valid := by
  intro s l s' h hs
  have := step_valid boxSize s hs l.1
  rw [h] at this
  exact this

/-- **Every store the replica can reach from empty is valid**, whatever requests arrived. -/
theorem replicaLTS_reachable_valid (boxSize : Nat) (s : Store Sg)
    (h : (replicaLTS (Sg := Sg) boxSize).CanReach Store.empty s) : Valid s := by
  obtain ⟨μs, hμ⟩ := h
  exact LTS.mtrInv_of_trInv (replicaLTS_trInv boxSize) Store.empty μs s hμ valid_empty

variable (M : MKEM) (W : Wire Sg)

/-- The system as a client sees it: each step is one MKEM exchange that completed, with some
randomness, addressed to some recipients of which replica `i` is the one holding `skj`. -/
def rpcLTS (boxSize : Nat) : LTS (Store Sg) (Request Sg × Reply Sg) :=
  ⟨fun s l s' => ∃ (cs rs : M.State) (pubs : List {pk : M.PublicKey // M.Safe pk}) (i : Nat)
      (_ : i < pubs.length) (skj : M.PrivateKey),
    pubs[i] = ⟨M.derivePublicKey skj, M.derive_safe skj⟩ ∧
      rpc M W boxSize cs rs pubs i skj s l.1 = .ok (s', l.2)⟩

/-- **`rpc_sound`, as a simulation.** Every step of the wire-level system is a step of the
abstract replica, with the same request, the same reply, and the same resulting store. -/
theorem rpcLTS_simulated (boxSize : Nat) :
    IsSimulation (rpcLTS M W boxSize) (replicaLTS boxSize) (fun s t => s = t) := by
  rintro s t rfl l s' ⟨cs, rs, pubs, i, hi, skj, hsk, hrpc⟩
  have := rpc_sound M W boxSize cs rs pubs i hi skj hsk s l.1 _ hrpc
  exact ⟨s', congrArg (fun r => r) (by rw [← this]), rfl⟩

/-- Every run of the wire-level system is a run of the abstract replica. -/
theorem rpcLTS_traces_subset (boxSize : Nat) (s : Store Sg) :
    (rpcLTS M W boxSize).traces s ⊆ (replicaLTS boxSize).traces s :=
  IsSimulation.traces_subset (rpcLTS_simulated M W boxSize) rfl

/-- Every step over the wire preserves validity. -/
theorem rpcLTS_trInv (boxSize : Nat) : (rpcLTS M W boxSize).TrInv Valid := by
  rintro s l s' ⟨cs, rs, pubs, i, hi, skj, hsk, hrpc⟩ hs
  have h := rpc_sound M W boxSize cs rs pubs i hi skj hsk s l.1 _ hrpc
  have hv := step_valid boxSize s hs l.1
  rw [← h] at hv
  exact hv

/-- The invariant carries over: every store reachable over the wire from empty is valid. -/
theorem rpcLTS_reachable_valid (boxSize : Nat) (s : Store Sg)
    (h : (rpcLTS M W boxSize).CanReach Store.empty s) : Valid s := by
  obtain ⟨μs, hμ⟩ := h
  exact LTS.mtrInv_of_trInv (rpcLTS_trInv M W boxSize) Store.empty μs s hμ valid_empty

end CryptWalker.Pigeonhole.Semantics

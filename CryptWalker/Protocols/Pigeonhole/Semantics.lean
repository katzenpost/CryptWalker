/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Protocols.Pigeonhole.Protocol
import Cslib.Foundations.Semantics.LTS.TraceEq

/-! # Pigeonhole replica and wire-level exchange as labelled transition systems

States are stores; labels are (request, reply) pairs. The wire-level system `rpcLTS` is simulated
by the abstract replica `replicaLTS`. -/

namespace CryptWalker.Protocols.Pigeonhole.Semantics

open Cslib Cslib.LTS
open CryptWalker.Sign.Sign (Signature)
open CryptWalker.MKEM.MKEM (MKEM)
open CryptWalker.Protocols.Pigeonhole.Replica
open CryptWalker.Protocols.Pigeonhole.Protocol

variable {Sg : Signature} [DecidableEq Sg.PublicKey]

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

/-- Every store reachable from empty is valid. -/
theorem replicaLTS_reachable_valid (boxSize : Nat) (s : Store Sg)
    (h : (replicaLTS (Sg := Sg) boxSize).CanReach Store.empty s) : Valid s := by
  obtain ⟨μs, hμ⟩ := h
  exact LTS.mtrInv_of_trInv (replicaLTS_trInv boxSize) Store.empty μs s hμ valid_empty

variable (M : MKEM) (W : Wire Sg)

/-- The system as a client sees it: each step is one completed `rpc` exchange. -/
def rpcLTS (boxSize : Nat) : LTS (Store Sg) (Request Sg × Reply Sg) :=
  ⟨fun s l s' => ∃ (cs rs : M.State) (pubs : List {pk : M.PublicKey // M.Safe pk}) (i : Nat)
      (_ : i < pubs.length) (skj : M.PrivateKey),
    pubs[i] = ⟨M.derivePublicKey skj, M.derive_safe skj⟩ ∧
      rpc M W boxSize cs rs pubs i skj s l.1 = .ok (s', l.2)⟩

/-- Every wire-level step is a step of the abstract replica. -/
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

/-- Every store reachable over the wire from empty is valid. -/
theorem rpcLTS_reachable_valid (boxSize : Nat) (s : Store Sg)
    (h : (rpcLTS M W boxSize).CanReach Store.empty s) : Valid s := by
  obtain ⟨μs, hμ⟩ := h
  exact LTS.mtrInv_of_trInv (rpcLTS_trInv M W boxSize) Store.empty μs s hμ valid_empty

end CryptWalker.Protocols.Pigeonhole.Semantics

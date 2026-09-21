/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cslib.Foundations.Semantics.LTS.TraceEq

/-! # Pigeonhole over Echomix: who can link a client to a box? (§6, prototype)

A first model of three rows of §6's collusion table, on cslib's labelled transition systems.

**The system.** One round = the set of clients online, the client whose network is disrupted (if
any), who performs an operation, on which box, through which courier. The *secret* is the actor
for a target box `b0`: in world `w`, every operation on `b0` is done by `w`. An **adversary is a
view**, a function from a round to what its roles observe (the paper: gateways and the global
passive adversary cannot tell decoys from real messages, so nobody sees the actor directly).
Collusion is a product of views. Two worlds are **indistinguishable** to a view when the LTSs of
observations are trace equivalent (`Cslib.LTS.TraceEq`). The environment (`Env`) says which
connectivity patterns can occur; the results are relative to it, so they say exactly what an attack
needs from the environment.

**Possibilistic, not probabilistic.** This captures what is *ruled out* (an intersection attack is
the intersection of online sets over the rounds where `b0` is operated), not how many observations
it takes: retries, timing and mixing delays are outside it.

## The rows

* `Gateway + Replica` (attack): `gatewayReplica_indist_iff`. Indistinguishable iff no possible
  online set separates the two clients.
* `Mixes + Replica` (no useful attack): `mixesReplica_indist_of_saturated`, provided every gateway
  always has a client online. `gatewayReplica_not_indist` shows the same clients are
  distinguishable once the adversary also gets *client-level* connectivity, so the row depends on
  the implicit global passive adversary not seeing that.
* `Courier + Replica` (attack, with the global passive adversary's view of disruptions):
  `courierReplica_indist_of_swap` (no attack without it) and `courierReplicaGPA_not_indist`
  (attack with it). -/

namespace CryptWalker.Pigeonhole.ThreatModel

open Cslib Cslib.LTS

/-! ### One-state LTSs

Every world below has a single state: what varies is which labels are allowed. -/

section Stateless

variable {L : Type}

/-- Every label satisfying `g` can happen at any time. -/
def stateless (g : L → Prop) : LTS Unit L := ⟨fun _ l _ => g l⟩

lemma mTr_stateless (g : L → Prop) (os : List L) :
    (stateless g).MTr () os () ↔ ∀ o ∈ os, g o := by
  induction os with
  | nil => exact ⟨fun _ o ho => by simp at ho, fun _ => LTS.MTr.refl⟩
  | cons o os ih =>
    rw [LTS.MTr.cons_iff]
    simp only [List.mem_cons, forall_eq_or_imp]
    constructor
    · rintro ⟨s2, h1, h2⟩
      exact ⟨h1, ih.mp (by cases s2; exact h2)⟩
    · rintro ⟨h1, h2⟩
      exact ⟨(), h1, ih.mpr h2⟩

lemma mem_traces_stateless (g : L → Prop) (os : List L) :
    os ∈ (stateless g).traces () ↔ ∀ o ∈ os, g o :=
  ⟨fun ⟨s', h⟩ => by cases s'; exact (mTr_stateless g os).mp h,
   fun h => ⟨(), (mTr_stateless g os).mpr h⟩⟩

lemma traceEq_stateless {g₁ g₂ : L → Prop} :
    TraceEq (stateless g₁) (stateless g₂) () () ↔ ∀ o, g₁ o ↔ g₂ o := by
  constructor
  · intro h o
    have := Set.ext_iff.mp h [o]
    simpa [mem_traces_stateless] using this
  · intro h
    ext os
    simp only [mem_traces_stateless]
    exact ⟨fun H o ho => (h o).mp (H o ho), fun H o ho => (h o).mpr (H o ho)⟩

/-- Observe an LTS through `π`: each transition is relabelled by what `π` shows of its label. -/
def pushforward {S : Type} {O : Type} (π : L → O) (lts : LTS S L) : LTS S O :=
  ⟨fun s o s' => ∃ l, π l = o ∧ lts.Tr s l s'⟩

lemma pushforward_stateless {O : Type} (π : L → O) (g : L → Prop) :
    pushforward π (stateless g) = stateless (fun o => ∃ l, π l = o ∧ g l) := rfl

end Stateless

/-! ### The system -/

/-- One round of the system. Nobody outside the client sees `actor`. -/
structure Round (C B K : Type) where
  online : Set C
  disrupted : Option C
  actor : C
  box : B
  courier : K

/-- The patterns of (clients online, client disrupted) that can occur. -/
abbrev Env (C : Type) := Set (Set C × Option C)

variable {C G B K : Type}

/-- World `w`: the actor for the target box `b0` is always `w`; the actor for any other box is
free. The actor must be online, and the round must be one the environment allows. -/
def guard (env : Env C) (b0 : B) (w : C) (r : Round C B K) : Prop :=
  (r.online, r.disrupted) ∈ env ∧ r.actor ∈ r.online ∧ (r.box = b0 → r.actor = w)

def world (env : Env C) (b0 : B) (w : C) : LTS Unit (Round C B K) := stateless (guard env b0 w)

/-- A view cannot tell worlds `a` and `a'` apart: the observation systems are trace equivalent. -/
def Indist {O : Type} (π : Round C B K → O) (env : Env C) (b0 : B) (a a' : C) : Prop :=
  TraceEq (pushforward π (world env b0 a)) (pushforward π (world env b0 a')) () ()

lemma indist_iff {O : Type} (π : Round C B K → O) (env : Env C) (b0 : B) (a a' : C) :
    Indist π env b0 a a' ↔
      ∀ o, (∃ r, π r = o ∧ guard env b0 a r) ↔ (∃ r, π r = o ∧ guard env b0 a' r) := by
  unfold Indist world
  rw [pushforward_stateless, pushforward_stateless, traceEq_stateless]

/-! ### Views -/

/-- Gateway (or a global passive adversary that attributes connectivity to clients) + replica:
who is online, which box is operated, through which courier. -/
def gatewayReplica (r : Round C B K) : Set C × B × K := (r.online, r.box, r.courier)

/-- Mixes + replica: the mixes see which *gateways* are active, not which clients. -/
def mixesReplica (gw : C → G) (r : Round C B K) : Set G × B × K :=
  (gw '' r.online, r.box, r.courier)

open Classical in
/-- The operation was resent: the actor's own network was disrupted, so the reply was lost. -/
noncomputable def resent (r : Round C B K) : Bool := decide (r.disrupted = some r.actor)

open Classical in
/-- Courier + replica, for a compromised pair `k0`: which box, and whether the envelope was
resent (the courier links resends, the replica knows the box). Rounds through other couriers
show nothing. -/
noncomputable def courierReplica (k0 : K) (r : Round C B K) : Option (B × Bool) :=
  if r.courier = k0 then some (r.box, resent r) else none

/-- Courier + replica + the global passive adversary's view of network disruptions. -/
noncomputable def courierReplicaGPA (k0 : K) (r : Round C B K) : Option (B × Bool) × Option C :=
  (courierReplica k0 r, r.disrupted)

/-! ### Gateway + replica: the intersection attack -/

/-- **`Gateway + Replica`.** The adversary cannot separate `a` from `a'` exactly when no possible
online set contains one and not the other: the anonymity set of the reader of `b0` is the clients
the environment cannot tell apart by connectivity. -/
theorem gatewayReplica_indist_iff [Nonempty K] (env : Env C) (b0 : B) (a a' : C) :
    Indist (gatewayReplica : Round C B K → _) env b0 a a' ↔
      ∀ S d, (S, d) ∈ env → (a ∈ S ↔ a' ∈ S) := by
  rw [indist_iff]
  obtain ⟨k0⟩ := ‹Nonempty K›
  constructor
  · intro h S d hSd
    constructor
    · intro haS
      obtain ⟨r, hr, hg⟩ := (h (S, b0, k0)).mp ⟨⟨S, d, a, b0, k0⟩, rfl, hSd, haS, fun _ => rfl⟩
      have hS : r.online = S := congrArg Prod.fst hr
      have := hg.2.1
      rw [hS] at this
      have hb : r.box = b0 := (congrArg (fun p => p.2.1) hr)
      rw [hg.2.2 hb] at this
      exact this
    · intro haS
      obtain ⟨r, hr, hg⟩ := (h (S, b0, k0)).mpr ⟨⟨S, d, a', b0, k0⟩, rfl, hSd, haS, fun _ => rfl⟩
      have hS : r.online = S := congrArg Prod.fst hr
      have := hg.2.1
      rw [hS] at this
      have hb : r.box = b0 := (congrArg (fun p => p.2.1) hr)
      rw [hg.2.2 hb] at this
      exact this
  · intro h o
    constructor
    · rintro ⟨r, hr, hd, hact, hb⟩
      by_cases hbox : r.box = b0
      · have hra : r.actor = a := hb hbox
        have ha' : a' ∈ r.online := (h _ _ hd).mp (hra ▸ hact)
        exact ⟨{ r with actor := a' }, hr, hd, ha', fun _ => rfl⟩
      · exact ⟨r, hr, hd, hact, fun hh => absurd hh hbox⟩
    · rintro ⟨r, hr, hd, hact, hb⟩
      by_cases hbox : r.box = b0
      · have hra : r.actor = a' := hb hbox
        have ha : a ∈ r.online := (h _ _ hd).mpr (hra ▸ hact)
        exact ⟨{ r with actor := a }, hr, hd, ha, fun _ => rfl⟩
      · exact ⟨r, hr, hd, hact, fun hh => absurd hh hbox⟩

/-- If some possible online set separates `a` from `a'`, the adversary tells them apart. -/
theorem gatewayReplica_not_indist [Nonempty K] (env : Env C) (b0 : B) {a a' : C} {S : Set C}
    {d : Option C} (hSd : (S, d) ∈ env) (hsep : ¬ (a ∈ S ↔ a' ∈ S)) :
    ¬ Indist (gatewayReplica : Round C B K → _) env b0 a a' :=
  fun h => hsep ((gatewayReplica_indist_iff env b0 a a').mp h S d hSd)

/-! ### Mixes + replica -/

/-- **`Mixes + Replica`.** Same shape, one level coarser: the adversary sees which *gateways* have
a client online, so `a` and `a'` are separated only if some gateway pattern occurs with one online
and not the other. -/
theorem mixesReplica_indist_iff [Nonempty K] (gw : C → G) (env : Env C) (b0 : B) (a a' : C) :
    Indist (mixesReplica gw : Round C B K → _) env b0 a a' ↔
      ∀ T : Set G, (∃ S d, (S, d) ∈ env ∧ a ∈ S ∧ gw '' S = T) ↔
        (∃ S d, (S, d) ∈ env ∧ a' ∈ S ∧ gw '' S = T) := by
  rw [indist_iff]
  obtain ⟨k0⟩ := ‹Nonempty K›
  constructor
  · intro h T
    constructor
    · rintro ⟨S, d, hSd, haS, hT⟩
      obtain ⟨r, hr, hg⟩ := (h (T, b0, k0)).mp
        ⟨⟨S, d, a, b0, k0⟩, by simp [mixesReplica, hT], hSd, haS, fun _ => rfl⟩
      simp only [mixesReplica, Prod.mk.injEq] at hr
      obtain ⟨hT', hb, _⟩ := hr
      have ha' : a' ∈ r.online := by
        have := hg.2.1; rwa [hg.2.2 hb] at this
      exact ⟨r.online, r.disrupted, hg.1, ha', hT'⟩
    · rintro ⟨S, d, hSd, haS, hT⟩
      obtain ⟨r, hr, hg⟩ := (h (T, b0, k0)).mpr
        ⟨⟨S, d, a', b0, k0⟩, by simp [mixesReplica, hT], hSd, haS, fun _ => rfl⟩
      simp only [mixesReplica, Prod.mk.injEq] at hr
      obtain ⟨hT', hb, _⟩ := hr
      have ha : a ∈ r.online := by
        have := hg.2.1; rwa [hg.2.2 hb] at this
      exact ⟨r.online, r.disrupted, hg.1, ha, hT'⟩
  · intro h o
    obtain ⟨T, b, k⟩ := o
    constructor
    · rintro ⟨r, hr, hd, hact, hb⟩
      simp only [mixesReplica, Prod.mk.injEq] at hr
      obtain ⟨hT, hbb, hkk⟩ := hr
      by_cases hbox : r.box = b0
      · have hra : r.actor = a := hb hbox
        obtain ⟨S', d', hS', ha'S', hT'⟩ := (h T).mp ⟨r.online, r.disrupted, hd, hra ▸ hact, hT⟩
        exact ⟨⟨S', d', a', r.box, r.courier⟩, by simp [mixesReplica, hT', hbb, hkk], hS', ha'S',
          fun _ => rfl⟩
      · exact ⟨r, by simp [mixesReplica, hT, hbb, hkk], hd, hact, fun hh => absurd hh hbox⟩
    · rintro ⟨r, hr, hd, hact, hb⟩
      simp only [mixesReplica, Prod.mk.injEq] at hr
      obtain ⟨hT, hbb, hkk⟩ := hr
      by_cases hbox : r.box = b0
      · have hra : r.actor = a' := hb hbox
        obtain ⟨S', d', hS', haS', hT'⟩ := (h T).mpr ⟨r.online, r.disrupted, hd, hra ▸ hact, hT⟩
        exact ⟨⟨S', d', a, r.box, r.courier⟩, by simp [mixesReplica, hT', hbb, hkk], hS', haS',
          fun _ => rfl⟩
      · exact ⟨r, by simp [mixesReplica, hT, hbb, hkk], hd, hact, fun hh => absurd hh hbox⟩

/-- **No useful attack, given a large enough user base.** If every gateway always has a client
online, the mixes' view of connectivity is constant, so `Mixes + Replica` cannot separate any two
clients who are ever online. -/
theorem mixesReplica_indist_of_saturated [Nonempty K] (gw : C → G) (env : Env C) (b0 : B)
    {a a' : C} (hsat : ∀ S d, (S, d) ∈ env → gw '' S = Set.univ)
    (ha : ∃ S d, (S, d) ∈ env ∧ a ∈ S) (ha' : ∃ S d, (S, d) ∈ env ∧ a' ∈ S) :
    Indist (mixesReplica gw : Round C B K → _) env b0 a a' := by
  rw [mixesReplica_indist_iff]
  intro T
  constructor
  · rintro ⟨S, d, hSd, _, hT⟩
    obtain ⟨S', d', hS', haS'⟩ := ha'
    exact ⟨S', d', hS', haS', (hsat S' d' hS').trans ((hsat S d hSd).symm.trans hT).symm.symm⟩
  · rintro ⟨S, d, hSd, _, hT⟩
    obtain ⟨S', d', hS', haS'⟩ := ha
    exact ⟨S', d', hS', haS', (hsat S' d' hS').trans ((hsat S d hSd).symm.trans hT).symm.symm⟩

/-! ### Symmetry: what an adversary cannot see, it cannot use -/

/-- Rename clients by `σ` throughout a round. -/
def swapRound (σ : C → C) (r : Round C B K) : Round C B K :=
  ⟨σ '' r.online, r.disrupted.map σ, σ r.actor, r.box, r.courier⟩

/-- If the environment is closed under renaming by an involution `σ` that sends `a` to `a'`, and
the view does not change under that renaming, the view cannot tell `a` from `a'`. -/
theorem indist_of_symmetry {O : Type} (π : Round C B K → O) (env : Env C) (b0 : B) (a a' : C)
    (σ : C → C) (hσ : ∀ x, σ (σ x) = x) (hσa : σ a = a')
    (henv : ∀ S d, (S, d) ∈ env → (σ '' S, d.map σ) ∈ env)
    (hπ : ∀ r, π (swapRound σ r) = π r) : Indist π env b0 a a' := by
  rw [indist_iff]
  have key : ∀ w w', σ w = w' → ∀ r : Round C B K, guard env b0 w r →
      guard env b0 w' (swapRound σ r) := by
    rintro w w' hw r ⟨hd, hact, hb⟩
    exact ⟨henv _ _ hd, Set.mem_image_of_mem σ hact, fun hbox => by simp [swapRound, hb hbox, hw]⟩
  intro o
  constructor
  · rintro ⟨r, hr, hg⟩
    exact ⟨swapRound σ r, (hπ r).trans hr, key a a' hσa r hg⟩
  · rintro ⟨r, hr, hg⟩
    exact ⟨swapRound σ r, (hπ r).trans hr, key a' a (by rw [← hσa, hσ]) r hg⟩

/-! ### Courier + replica -/

lemma resent_swap (σ : C → C) (hσ : ∀ x, σ (σ x) = x) (r : Round C B K) :
    resent (swapRound σ r) = resent r := by
  have hinj : ∀ x y, σ x = σ y → x = y := fun x y h => by rw [← hσ x, h, hσ]
  have : (r.disrupted.map σ = some (σ r.actor)) ↔ (r.disrupted = some r.actor) := by
    cases hd : r.disrupted with
    | none => simp
    | some y =>
      simp only [Option.map_some, Option.some.injEq]
      exact ⟨hinj y r.actor, fun h => h ▸ rfl⟩
  simp only [resent, swapRound]
  exact decide_eq_decide.mpr this

/-- **`Courier + Replica`, without the global passive adversary's view of disruptions.** The
adversary learns which boxes are operated and which envelopes are resent, but resending looks the
same whichever of two interchangeable clients was disrupted, so it cannot tell them apart. -/
theorem courierReplica_indist_of_swap (k0 : K) (env : Env C) (b0 : B) (a a' : C)
    (σ : C → C) (hσ : ∀ x, σ (σ x) = x) (hσa : σ a = a')
    (henv : ∀ S d, (S, d) ∈ env → (σ '' S, d.map σ) ∈ env) :
    Indist (courierReplica k0 : Round C B K → _) env b0 a a' :=
  indist_of_symmetry _ env b0 a a' σ hσ hσa henv (fun r => by
    unfold courierReplica
    rw [resent_swap σ hσ r]
    rfl)

/-- **`Courier + Replica` with the global passive adversary's view of disruptions.** If `a` can
be online and disrupted, the courier sees a resend on `b0` exactly when the disrupted client is the
reader, and the adversary reads off who: it tells `a` from any `a' ≠ a`. -/
theorem courierReplicaGPA_not_indist (k0 : K) (env : Env C) (b0 : B) {a a' : C} (hne : a ≠ a')
    {S : Set C} (hS : (S, some a) ∈ env) (haS : a ∈ S) :
    ¬ Indist (courierReplicaGPA k0 : Round C B K → _) env b0 a a' := by
  classical
  rw [indist_iff]
  intro h
  obtain ⟨r, hr, hg⟩ := (h (some (b0, true), some a)).mp
    ⟨⟨S, some a, a, b0, k0⟩, by simp [courierReplicaGPA, courierReplica, resent], hS, haS,
      fun _ => rfl⟩
  simp only [courierReplicaGPA, courierReplica, Prod.mk.injEq] at hr
  obtain ⟨h1, h2⟩ := hr
  by_cases hc : r.courier = k0
  · rw [if_pos hc] at h1
    simp only [Option.some.injEq, Prod.mk.injEq] at h1
    obtain ⟨hb, hres⟩ := h1
    have hd : r.disrupted = some r.actor := by simpa [resent] using hres
    have hact : r.actor = a := Option.some.inj (hd.symm.trans h2)
    exact hne (hact.symm.trans (hg.2.2 hb))
  · rw [if_neg hc] at h1; exact absurd h1 (by simp)

/-! ### A concrete instance

Two clients behind one gateway, connected alone or together. -/

/-- Online sets `{0}`, `{1}`, `{0, 1}`; nothing disrupted. -/
def env2 : Env (Fin 2) := {({0}, none), ({1}, none), (Set.univ, none)}

/-- `Mixes + Replica` cannot tell the two clients apart... -/
example : Indist (mixesReplica (fun _ : Fin 2 => ()) : Round (Fin 2) Unit Unit → _) env2 () 0 1 := by
  apply mixesReplica_indist_of_saturated
  · rintro S d hSd
    simp only [env2, Set.mem_insert_iff, Set.mem_singleton_iff, Prod.mk.injEq] at hSd
    rcases hSd with ⟨rfl, _⟩ | ⟨rfl, _⟩ | ⟨rfl, _⟩ <;> ext u <;> simp
  · exact ⟨{0}, none, by simp [env2], by simp⟩
  · exact ⟨{1}, none, by simp [env2], by simp⟩

/-- ...but `Gateway + Replica` can, because `{0}` contains one and not the other. -/
example : ¬ Indist (gatewayReplica : Round (Fin 2) Unit Unit → _) env2 () 0 1 :=
  gatewayReplica_not_indist env2 () (S := {0}) (d := none) (by simp [env2]) (by simp)

end CryptWalker.Pigeonhole.ThreatModel

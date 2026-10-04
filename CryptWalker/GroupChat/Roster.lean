/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Data.List.Infix
import Mathlib.Tactic.Ring
import Mathlib.Tactic.Push

/-! # Rosters: following another member's numbering

See "Rosters" in the group chat spec, and katzenqt's `rosters.py` (`grow`, `follow`), which this
follows. Every member numbers the members it knows, and nobody states a number. A member's roster
grows when one of its messages acknowledges a stream far enough to cover an `Introduction` there,
and when it introduces someone itself. Everyone else works out its roster by replaying its
messages, stopping at the first acknowledgement that reaches further than they have read.

Positions count from 1; an acknowledgement `(i, r)` says the sender has read `r` boxes of the
stream at its roster index `i`. What a member knows of a stream is `K y q`: whether it has the
message at position `q` of `y`'s stream.

* `follow_eq_of_complete`: a watcher that has every message below how far it has read computes
  exactly what full knowledge would, so the answer does not depend on who is asking.
* `watch_prefix`: hence its copy of a roster is a prefix of the owner's, for any group size and
  any number of messages, provided the owner numbered with complete knowledge too.
* `incomplete_breaks_watch`: a new member handed only rosters (the spec's `ReplyWho`) does not
  have the Introductions before where it starts reading, and misplaces a member. This is the
  counterexample TLC finds in `tla/protocol/MC_GroupChat_SpecReply.cfg`. -/

namespace CryptWalker.GroupChat.Roster

/-- A message, as far as rosters are concerned. -/
structure Msg (M : Type) where
  acks : List (ℕ × ℕ)
  intro : Option M
  deriving DecidableEq

variable {M : Type} [DecidableEq M]

/-- Members introduced on a stream at positions `1..r` that `K` has, in stream order. -/
def introsOn (s : List (Msg M)) (K : ℕ → Bool) (r : ℕ) : List M :=
  ((s.take r).zipIdx 1).filterMap fun p => if K p.2 then p.1.intro else none

/-- Append each member not already present, in order. -/
def appendNew : List M → List M → List M
  | s, [] => s
  | s, x :: xs => appendNew (if x ∈ s then s else s ++ [x]) xs

variable (streams : M → List (Msg M))

/-- The members one message numbers through its acknowledgements: by the introducer's place in
the roster, then by position on its stream. `seq` is the roster before the message. -/
def grow (K : M → ℕ → Bool) (seq : List M) (acks : List (ℕ × ℕ)) : List M :=
  (seq.zipIdx).foldl (fun acc p =>
    match acks.lookup p.2 with
    | some r => appendNew acc (introsOn (streams p.1) (K p.1) r)
    | none => acc) seq

/-- Number the member a message introduces, unless already numbered. -/
def addIntro (s : List M) : Option M → List M
  | some n => if n ∈ s then s else s ++ [n]
  | none => s

/-- One message applied to a roster: what its acknowledgements number, then whom it introduces. -/
def step (K : M → ℕ → Bool) (seq : List M) (msg : Msg M) : List M :=
  addIntro (if msg.acks = [] then seq else grow streams K seq msg.acks) msg.intro

/-- Whether every stream an acknowledgement names has been read as far as it reaches. -/
def readable (R : M → ℕ) (seq : List M) (acks : List (ℕ × ℕ)) : Bool :=
  acks.all fun a => match seq[a.1]? with
    | some y => decide (a.2 ≤ R y)
    | none => false

/-- A watcher's copy of a roster: replay the owner's messages from `seq`, stopping at the first
acknowledgement it cannot yet read (`rosters.follow`). -/
def follow (K : M → ℕ → Bool) (R : M → ℕ) : List M → List (Msg M) → List M
  | seq, [] => seq
  | seq, msg :: rest =>
    if msg.acks ≠ [] ∧ readable R seq msg.acks = false then seq
    else follow K R (step streams K seq msg) rest

/-- Knowing everything: what the owner, numbering as it sends, works from. -/
def all : M → ℕ → Bool := fun _ _ => true

/-- `K` has every message below how far `R` says it has read. -/
def Complete (K : M → ℕ → Bool) (R : M → ℕ) : Prop := ∀ y q, q ≤ R y → K y q = true

/-! ## Rosters only grow -/

theorem prefix_appendNew : ∀ (s more : List M), s <+: appendNew s more
  | s, [] => List.prefix_refl s
  | s, x :: xs => by
    simp only [appendNew]
    refine List.IsPrefix.trans ?_ (prefix_appendNew _ xs)
    split_ifs
    · exact List.prefix_refl s
    · exact List.prefix_append s [x]

theorem prefix_grow (K : M → ℕ → Bool) (seq : List M) (acks : List (ℕ × ℕ)) :
    seq <+: grow streams K seq acks := by
  unfold grow
  suffices h : ∀ (l : List (M × ℕ)) (acc : List M), seq <+: acc → seq <+: l.foldl (fun acc p =>
      match acks.lookup p.2 with
      | some r => appendNew acc (introsOn (streams p.1) (K p.1) r)
      | none => acc) acc from h _ _ (List.prefix_refl _)
  intro l
  induction l with
  | nil => intro acc h; exact h
  | cons p ps ih =>
    intro acc h
    apply ih
    dsimp only
    split
    · exact h.trans (prefix_appendNew _ _)
    · exact h

theorem prefix_addIntro (s : List M) (o : Option M) : s <+: addIntro s o := by
  cases o with
  | none => exact List.prefix_refl s
  | some n =>
    simp only [addIntro]
    split_ifs
    · exact List.prefix_refl s
    · exact List.prefix_append s [n]

theorem prefix_step (K : M → ℕ → Bool) (seq : List M) (msg : Msg M) :
    seq <+: step streams K seq msg := by
  unfold step
  have h1 : seq <+: (if msg.acks = [] then seq else grow streams K seq msg.acks) := by
    split_ifs
    · exact List.prefix_refl _
    · exact prefix_grow streams K seq msg.acks
  exact h1.trans (prefix_addIntro _ _)

/-- **A watcher's copy is a prefix of the full replay**: stopping early only loses entries at the
end, because each message only appends. -/
theorem follow_prefix (K : M → ℕ → Bool) (R : M → ℕ) :
    ∀ (seq : List M) (msgs : List (Msg M)),
      follow streams K R seq msgs <+: msgs.foldl (step streams K) seq
  | seq, [] => List.prefix_refl _
  | seq, msg :: rest => by
    simp only [follow, List.foldl_cons]
    split_ifs
    · -- stopped here: everything after only appends
      suffices h : ∀ (l : List (Msg M)) (s : List M), s <+: l.foldl (step streams K) s from
        (prefix_step streams K seq msg).trans (h rest _)
      intro l
      induction l with
      | nil => intro s; exact List.prefix_refl s
      | cons m ms ih => intro s; exact (prefix_step streams K s m).trans (ih _)
    · exact follow_prefix K R _ rest

/-! ## Complete knowledge makes the answer independent of who asks -/

omit [DecidableEq M] in
theorem introsOn_congr (s : List (Msg M)) {K K' : ℕ → Bool} {r : ℕ}
    (h : ∀ q, q ≤ r → K q = K' q) : introsOn s K r = introsOn s K' r := by
  unfold introsOn
  apply List.filterMap_congr
  intro p hp
  have hq : p.2 ≤ r := by
    rcases List.mem_iff_getElem.1 hp with ⟨k, hk, rfl⟩
    simp only [List.getElem_zipIdx, List.length_zipIdx, List.length_take] at hk ⊢
    omega
  rw [h _ hq]

theorem mem_of_lookup {acks : List (ℕ × ℕ)} {i r : ℕ} (h : acks.lookup i = some r) :
    (i, r) ∈ acks := by
  induction acks with
  | nil => simp [List.lookup] at h
  | cons a t ih =>
    obtain ⟨k, v⟩ := a
    by_cases hk : i = k
    · subst hk; simp [List.lookup] at h; subst h; exact List.mem_cons_self ..
    · have : (i == k) = false := by simpa using hk
      simp only [List.lookup, this] at h
      exact List.mem_cons_of_mem _ (ih h)

/-- Under complete knowledge, every acknowledgement a watcher can read sees exactly the
Introductions full knowledge would. -/
theorem grow_eq_of_complete {K : M → ℕ → Bool} {R : M → ℕ} (hK : Complete K R)
    {seq : List M} {acks : List (ℕ × ℕ)} (hr : readable R seq acks = true) :
    grow streams K seq acks = grow streams all seq acks := by
  unfold grow
  suffices h : ∀ (l : List (M × ℕ)), (∀ p ∈ l, seq[p.2]? = some p.1) → ∀ acc : List M,
      l.foldl (fun acc p =>
        match acks.lookup p.2 with
        | some r => appendNew acc (introsOn (streams p.1) (K p.1) r)
        | none => acc) acc =
      l.foldl (fun acc p =>
        match acks.lookup p.2 with
        | some r => appendNew acc (introsOn (streams p.1) (all p.1) r)
        | none => acc) acc by
    apply h
    intro p hp
    rcases List.mem_iff_getElem.1 hp with ⟨k, hk, rfl⟩
    simp [List.getElem_zipIdx]
  intro l
  induction l with
  | nil => intro _ acc; rfl
  | cons p ps ih =>
    intro hl acc
    simp only [List.foldl_cons]
    rw [ih (fun q hq => hl q (List.mem_cons_of_mem _ hq))]
    congr 1
    cases hlook : acks.lookup p.2 with
    | none => rfl
    | some r =>
      simp only
      congr 1
      apply introsOn_congr
      intro q hq
      -- the acknowledgement of p's stream is readable, so it reaches no further than read
      have hmem : (p.2, r) ∈ acks := mem_of_lookup hlook
      have hall := List.all_eq_true.1 hr _ hmem
      rw [hl p (List.mem_cons_self ..)] at hall
      simp only [decide_eq_true_eq] at hall
      rw [hK p.1 q (le_trans hq hall)]; rfl

theorem step_eq_of_complete {K : M → ℕ → Bool} {R : M → ℕ} (hK : Complete K R)
    {seq : List M} {msg : Msg M} (hr : msg.acks = [] ∨ readable R seq msg.acks = true) :
    step streams K seq msg = step streams all seq msg := by
  unfold step
  by_cases ha : msg.acks = []
  · simp [ha]
  · rw [if_neg ha, if_neg ha, grow_eq_of_complete streams hK (hr.resolve_left ha)]

/-- **Watching does not depend on the watcher**, given complete knowledge: its copy is what
full knowledge would give, replayed as far as it can read. -/
theorem follow_eq_of_complete {K : M → ℕ → Bool} {R : M → ℕ} (hK : Complete K R) :
    ∀ (seq : List M) (msgs : List (Msg M)),
      follow streams K R seq msgs = follow streams all R seq msgs
  | seq, [] => rfl
  | seq, msg :: rest => by
    simp only [follow]
    split_ifs with h
    · rfl
    · push Not at h
      have hr : msg.acks = [] ∨ readable R seq msg.acks = true := by
        by_cases ha : msg.acks = []
        · exact Or.inl ha
        · exact Or.inr (by simpa using h ha)
      rw [step_eq_of_complete streams hK hr]
      exact follow_eq_of_complete hK _ rest

/-- **What a watcher can tell of a roster is right as far as it goes.** The owner numbered with
complete knowledge as it sent each message (so its roster is the full replay of all its messages);
the watcher has every message below how far it has read, starts from the same base, and has read
some prefix of the owner's messages. Then its copy is a prefix of the owner's roster. -/
theorem watch_prefix {K : M → ℕ → Bool} {R : M → ℕ} (hK : Complete K R)
    (base : List M) (msgs sent : List (Msg M)) (hpre : msgs <+: sent) :
    follow streams K R base msgs <+: sent.foldl (step streams all) base := by
  rw [follow_eq_of_complete streams hK]
  obtain ⟨tail, rfl⟩ := hpre
  rw [List.foldl_append]
  refine (follow_prefix streams all R base msgs).trans ?_
  suffices h : ∀ (l : List (Msg M)) (s : List M), s <+: l.foldl (step streams all) s from h _ _
  intro l
  induction l with
  | nil => intro s; exact List.prefix_refl s
  | cons m ms ih => intro s; exact (prefix_step streams all s m).trans (ih _)

/-! ## Without the Introductions, a new member misplaces a member -/

/-- Founders `a = 0` and `b = 1`; `a` introduces `c = 2` and then `d = 3`; `b` acknowledges both
boxes of `a`'s stream, which numbers `c` then `d`. -/
def exStreams : Fin 4 → List (Msg (Fin 4))
  | 0 => [⟨[], some 2⟩, ⟨[], some 3⟩]
  | 1 => [⟨[(0, 2)], none⟩]
  | _ => []

/-- `d` was handed rosters and began reading `a`'s stream at its own Introduction: it has box 2 of
`a`'s stream but not box 1, where `c` was introduced. -/
def exKnowsD : Fin 4 → ℕ → Bool
  | 0, q => q = 2
  | _, _ => true

def exReadD : Fin 4 → ℕ
  | 0 => 2
  | 1 => 1
  | _ => 0

theorem incomplete_breaks_watch :
    (exStreams 1).foldl (step exStreams all) [0, 1] = [0, 1, 2, 3] ∧
    follow exStreams exKnowsD exReadD [0, 1] (exStreams 1) = [0, 1, 3] ∧
    ¬ (follow exStreams exKnowsD exReadD [0, 1] (exStreams 1) <+:
        (exStreams 1).foldl (step exStreams all) [0, 1]) := by
  decide

end CryptWalker.GroupChat.Roster

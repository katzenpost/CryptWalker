/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Tactic
import CryptWalker.GroupChat.Roster
import CryptWalker.GroupChat.Member.Group
import CryptWalker.GroupChat.Member.DictProofs
import CryptWalker.GroupChat.Member.ReaderProofs

/-! # What a member guarantees

The guarantees of "Opportunistic acknowledgements and backfill" in the group chat spec, about the
member of `Member/Group.lean`.

* `resolve_sound`: whoever a member names at an index of a roster is whoever the owner put there,
  whenever what it holds is true of the world: `Roster.lean`'s theorem, carried over to the
  member's rosters by `Rosters.toWatcher`.
* `acksOf_runs`, `acksOf_safe`: every acknowledgement a member sends names the end of the unbroken
  run its reader of that stream has read, so a box it read along with every box before it.
* `takeAcks_credit`: an acknowledgement of our own stream counts only for a box the Sent-box check
  finds.
* `controlOf_consecutive`: a control message numbers members at consecutive indexes from the next
  one free, counting what is composed and not yet written.
* `introduction_index`: an `Introduction` gives the new member the index the reply promised it,
  when nothing composed before it is still to be written (the spec's "Waiting"), and
  `introduction_index_pending`: otherwise it gives a later one.
* `retain_spec`: retention drops plaintext only once every member still read has acknowledged
  it, or the policy has expired it; `backfill_once`: a box is rewritten at most once an epoch. -/

namespace CryptWalker.GroupChat.Member

/-! ## Rosters -/

def Entry.toVal (e : Entry) : Roster.Val Key Index :=
  match e.key, e.introduced with
  | some k, _ => .key k
  | none, some (i, b) => .intro i b
  | none, none => .unknown

/-- A member's rosters as `Roster.lean`'s watcher. -/
def Rosters.toWatcher (r : Rosters) : Roster.Watcher Key Index where
  entries x k := ((r.entries.getD x {}).get? k).map Entry.toVal
  introductions i b := r.introductions.get? (i, b)
  started x := r.started.get? x

theorem resolveAux_some (r : Rosters) :
    ∀ fuel seen x k n, r.resolveAux fuel seen x k = some n →
      ∃ f, Roster.resolve r.toWatcher f x k = some n := by
  intro fuel
  induction fuel with
  | zero =>
    intro seen x k n h
    unfold Rosters.resolveAux at h
    split at h
    · next e he =>
      refine ⟨0, ?_⟩
      unfold Roster.resolve
      simp only [Rosters.toWatcher, he, Option.map_some]
      cases hk : e.key with
      | some m => simp [Entry.toVal, hk] at h ⊢; exact h
      | none =>
        rw [hk] at h
        cases hi : e.introduced with
        | none => simp [hi] at h
        | some ib => obtain ⟨i, b⟩ := ib; simpa [Entry.toVal, hk, hi] using h
    · simp at h
  | succ f ih =>
    intro seen x k n h
    unfold Rosters.resolveAux at h
    split at h
    · next e he =>
      refine ⟨0, ?_⟩
      unfold Roster.resolve
      simp only [Rosters.toWatcher, he, Option.map_some]
      cases hk : e.key with
      | some m => simp [Entry.toVal, hk] at h ⊢; exact h
      | none =>
        rw [hk] at h
        cases hi : e.introduced with
        | none => simp [hi] at h
        | some ib => obtain ⟨i, b⟩ := ib; simpa [Entry.toVal, hk, hi] using h
    · next he =>
      simp only at h
      split at h
      · next i top hs =>
        split_ifs at h with hc
        obtain ⟨f', hf'⟩ := ih _ i k n h
        refine ⟨f' + 1, ?_⟩
        unfold Roster.resolve
        simp only [Rosters.toWatcher, he, Option.map_none, hs]
        have : k ≤ top := by simp at hc; omega
        simp only [this, if_true]
        exact hf'
      · simp at h

/-- **Whoever a member names is right**, whenever what it holds is true of the world. -/
theorem resolve_sound {r : Rosters} {W : Roster.World Key Index} (h : Roster.Sound r.toWatcher W)
    {x : Key} {k : Nat} {n : Key} (hr : r.resolve x k = some n) : W.roster x k = some n := by
  obtain ⟨f, hf⟩ := resolveAux_some r _ _ x k n hr
  exact Roster.resolve_sound h f x k n hf

/-! ## Acknowledgements sent -/

/-- What `acksOf` keeps true as it goes. -/
def AcksTrue (g : Group) (acks : List (Nat × Index)) : Prop :=
  ∀ x ∈ acks, ∃ m r, (x.1, some m) ∈ g.rosters.known g.me ∧ g.readers.get? m = some r ∧
    r.run = some x.2

theorem acksOf_fold (g : Group) :
    ∀ (es : List (Nat × Option Key)) (acc : List (Nat × Index) × Pending × Ledger),
      (∀ e ∈ es, e ∈ g.rosters.known g.me) → AcksTrue g acc.1 →
      AcksTrue g (es.foldl (fun (acc : List (Nat × Index) × Pending × Ledger) (e : Nat × Option Key) =>
        match e.2.bind g.readers.get? with
        | none => acc
        | some r =>
          match acc.2.2.owed r.stream r.run with
          | none => acc
          | some owed =>
            (acc.1 ++ [(e.1, owed)],
              { acc.2.1 with acks := acc.2.1.acks.set r.stream (acc.2.2.published.get? r.stream, owed) },
              acc.2.2.publish r.stream owed)) acc).1
  | [], _, _, h => h
  | e :: es, acc, hes, h => by
    simp only [List.foldl_cons]
    apply acksOf_fold g es _ (fun e' he' => hes e' (List.mem_cons_of_mem _ he'))
    have he := hes e List.mem_cons_self
    split
    · exact h
    · next r hr =>
      split
      · exact h
      · next owed ho =>
        intro x hx
        rcases List.mem_append.1 hx with hx | hx
        · exact h x hx
        · simp only [List.mem_singleton] at hx
          subst hx
          obtain ⟨k, v⟩ := e
          cases v with
          | none => simp at hr
          | some m =>
            refine ⟨m, r, he, by simpa using hr, ?_⟩
            unfold Ledger.owed at ho
            split at ho
            · simp at ho
            · next run hrun => split_ifs at ho; cases ho; exact hrun

/-- **Every acknowledgement a member sends is the run of its reader of that stream.** -/
theorem acksOf_runs (g : Group) (p : Pending) : AcksTrue g (g.acksOf p).1 :=
  acksOf_fold g _ _ (fun _ h => h) (by simp [AcksTrue])

/-- **What a member acknowledges it has read**, with every box before it, given each reader's
history. -/
theorem acksOf_safe (g : Group) (p : Pending) (hist : Key → History)
    (inv : ∀ m r, g.readers.get? m = some r → Inv r (hist m)) :
    ∀ x ∈ (g.acksOf p).1, ∃ m, (x.1, some m) ∈ g.rosters.known g.me ∧ Safe (hist m) (some x.2) := by
  intro x hx
  obtain ⟨m, r, hk, hr, hrun⟩ := acksOf_runs g p x hx
  exact ⟨m, hk, hrun ▸ run_safe (inv m r hr)⟩

/-! ## Acknowledgements taken -/

@[simp] theorem takeAck_sent (sender : Key) (g : Group) (a : Nat × Index) :
    (g.takeAck sender a).sent = g.sent := by
  unfold Group.takeAck; split <;> (try split_ifs) <;> (try split) <;> rfl

@[simp] theorem takeAck_rosters (sender : Key) (g : Group) (a : Nat × Index) :
    (g.takeAck sender a).rosters = g.rosters := by
  unfold Group.takeAck; split <;> (try split_ifs) <;> (try split) <;> rfl

@[simp] theorem takeAck_readCap (sender : Key) (g : Group) (a : Nat × Index) :
    (g.takeAck sender a).readCap = g.readCap := by
  unfold Group.takeAck; split <;> (try split_ifs) <;> (try split) <;> rfl

theorem takeAck_credit (sender : Key) (g : Group) (a : Nat × Index) (m : Key) :
    (g.takeAck sender a).ledger.ackedBy.get? m = g.ledger.ackedBy.get? m ∨
      (m = sender ∧ g.rosters.resolve sender a.1 = some g.me ∧ (g.sent.check a.2).isSome) := by
  unfold Group.takeAck
  split
  · next acked hacked =>
    split_ifs with hme
    · split
      · next seq hseq =>
        by_cases hm : sender = m
        · subst hm; exact Or.inr ⟨rfl, hme ▸ hacked, by simp [hseq]⟩
        · left; simp [Ledger.acked, Dict.get?_set_ne _ _ hm]
      · exact Or.inl rfl
    · exact Or.inl rfl
  · exact Or.inl rfl

/-- **An acknowledgement of our own stream counts only for a box we wrote**: how far a member is
counted as having read changes only for the sender, and only by an acknowledgement the Sent-box
check finds. -/
theorem takeAcks_credit (sender : Key) :
    ∀ (acks : List (Nat × Index)) (g : Group) (m : Key),
      (acks.foldl (Group.takeAck sender) g).ledger.ackedBy.get? m = g.ledger.ackedBy.get? m ∨
        (m = sender ∧ ∃ a ∈ acks, g.rosters.resolve sender a.1 = some g.me ∧ (g.sent.check a.2).isSome)
  | [], _, _ => Or.inl rfl
  | a :: as, g, m => by
    simp only [List.foldl_cons]
    rcases takeAcks_credit sender as (g.takeAck sender a) m with h | ⟨hm, b, hb, hres, hchk⟩
    · rcases takeAck_credit sender g a m with h' | h'
      · exact Or.inl (h.trans h')
      · exact Or.inr ⟨h'.1, a, List.mem_cons_self, h'.2⟩
    · have e1 : (g.takeAck sender a).rosters = g.rosters := takeAck_rosters _ _ _
      have e2 : (g.takeAck sender a).sent = g.sent := takeAck_sent _ _ _
      have e3 : (g.takeAck sender a).me = g.me := by unfold Group.me; rw [takeAck_readCap]
      rw [e1, e3] at hres
      rw [e2] at hchk
      exact Or.inr ⟨hm, b, List.mem_cons_of_mem _ hb, hres, hchk⟩

theorem check_some {s : SentBox} {i : Index} {seq : Nat} (h : s.check i = some seq) :
    ∃ r, (i, r) ∈ s.records.pairs ∧ r.seq = seq := by
  unfold SentBox.check at h
  obtain ⟨r, hr, rfl⟩ := Option.map_eq_some_iff.1 h
  exact ⟨r, Dict.get?_eq_some hr, rfl⟩

/-! ## Numbering -/

theorem controlOf_fold (g : Group) :
    ∀ (as : List At) (acc : Nat × Numbers × List (Nat × Option At) × List At),
      acc.2.1.map (·.1) = List.range' g.size (acc.1 - g.size) → g.size ≤ acc.1 →
      acc.2.2.1.map (·.1) = acc.2.1.map (·.1) →
      (as.foldl g.controlStep acc).2.1.map (·.1) =
          List.range' g.size ((as.foldl g.controlStep acc).1 - g.size) ∧
        (as.foldl g.controlStep acc).2.2.1.map (·.1) = (as.foldl g.controlStep acc).2.1.map (·.1)
  | [], _, h1, _, h3 => ⟨h1, h3⟩
  | a :: as, acc, h1, h2, h3 => by
    simp only [List.foldl_cons]
    apply controlOf_fold g as
    · unfold Group.controlStep
      split
      · exact h1
      · simp only [List.map_append, h1, List.map_cons, List.map_nil]
        rw [show acc.1 + 1 - g.size = (acc.1 - g.size) + 1 by omega, List.range'_concat]
        congr 2; omega
    · unfold Group.controlStep; split <;> (try simp only) <;> omega
    · unfold Group.controlStep
      split
      · exact h3
      · simp [h3]

/-- **A control message numbers members at consecutive indexes from the next one free**, counting
what is composed and not yet written, and its pending numbering assigns the same ones. -/
theorem controlOf_consecutive (g : Group) :
    g.controlOf.1.numbers.map (·.1) = List.range' g.size g.controlOf.1.numbers.length ∧
      g.controlOf.2.1.numbers.map (·.1) = g.controlOf.1.numbers.map (·.1) := by
  obtain ⟨h1, h2⟩ := controlOf_fold g g.unnumbered (g.size, [], [], g.unnumbered) (by simp) le_rfl rfl
  refine ⟨?_, h2⟩
  show (g.unnumbered.foldl g.controlStep _).2.1.map (·.1) = List.range' g.size (g.unnumbered.foldl g.controlStep _).2.1.length
  rw [h1]
  have := congrArg List.length h1
  simp only [List.length_map, List.length_range'] at this
  rw [this]

theorem size_eq (g : Group) (hp : ∀ p ∈ g.pending.values, p.numbers = []) :
    g.size = g.rosters.size g.me := by
  unfold Group.size
  have : g.pending.values.flatMap (·.numbers) = [] := by
    simp only [List.flatMap_eq_nil_iff]; exact hp
  rw [this]; rfl

theorem reply_newcomer (g : Group) (s : Index) : (g.reply s).newcomer = g.rosters.size g.me := by
  unfold Group.reply Rosters.size; rfl

/-- **An `Introduction` gives the new member the index the reply promised**, when everything
composed before it has been written. -/
theorem introduction_index (g : Group) (name : String) (readCap : ByteArray) (s : Index)
    (hp : ∀ p ∈ g.pending.values, p.numbers = []) (hn : g.numbered (keyOf readCap) = false) :
    (g.introductionOf name readCap).1.numbers = [((g.reply s).newcomer, none)] := by
  simp [Group.introductionOf, hn, size_eq g hp, reply_newcomer]

theorem size_ge (g : Group) {p : Pending} (hp : p ∈ g.pending.values) {n : Nat} {a : Option At}
    (hn : (n, a) ∈ p.numbers) : n + 1 ≤ g.size := by
  unfold Group.size
  have hmem : (n, a) ∈ g.pending.values.flatMap (·.numbers) := List.mem_flatMap.2 ⟨p, hp, hn⟩
  generalize g.pending.values.flatMap (·.numbers) = l at hmem
  generalize g.rosters.size g.me = b
  induction l generalizing b with
  | nil => simp at hmem
  | cons x xs ih =>
    simp only [List.foldl_cons]
    rcases List.mem_cons.1 hmem with rfl | hmem
    · have : ∀ (l : List (Nat × Option At)) (c : Nat), c ≤ l.foldl (fun m (x : Nat × Option At) => max m (x.1 + 1)) c := by
        intro l; induction l with
        | nil => intro c; exact le_rfl
        | cons y ys ihy => intro c; simp only [List.foldl_cons]; exact le_trans (le_max_left _ _) (ihy _)
      exact le_trans (le_max_right _ _) (this xs _)
    · exact ih hmem _

/-- **Without waiting, the promise breaks**: a reply built while a composed message still holds the
index the reply promises makes the `Introduction` give the new member a later one. -/
theorem introduction_index_pending (g : Group) (name : String) (readCap : ByteArray) (s : Index)
    {p : Pending} (hp : p ∈ g.pending.values) {a : Option At} (hn : ((g.reply s).newcomer, a) ∈ p.numbers)
    (hnew : g.numbered (keyOf readCap) = false) :
    ∃ k, (g.introductionOf name readCap).1.numbers = [(k, none)] ∧ (g.reply s).newcomer < k := by
  refine ⟨g.size, by simp [Group.introductionOf, hnew], ?_⟩
  have := size_ge g hp hn
  omega

/-! ## Retention and backfill -/

/-- **Retention drops plaintext only when the spec allows**: every record after it was a record
before, with the same box, order and kind, and its plaintext is unchanged, or gone because every
member still read had acknowledged it or the policy expired it. Records older than the window are
gone. -/
theorem retain_spec (s : SentBox) (epoch : Nat) (policy : Retention) (acked : Nat → Bool) :
    ∀ e ∈ (s.retain epoch policy acked).records.pairs, ∃ r0, (e.1, r0) ∈ s.records.pairs ∧
      epoch ≤ r0.written + policy.window ∧ e.2.seq = r0.seq ∧ e.2.control = r0.control ∧
      e.2.written = r0.written ∧
      (e.2.plaintext = r0.plaintext ∨ (e.2.plaintext = none ∧
        ((∃ keep, policy.keepSent = some keep ∧ r0.control = false ∧ r0.written + keep ≤ epoch) ∨
          (policy.discardAcked = true ∧ acked r0.seq = true)))) := by
  intro e he
  unfold SentBox.retain at he
  obtain ⟨r0, hr0, he2⟩ := Dict.mem_mapValues.1 he
  obtain ⟨hmem, hw⟩ := Dict.mem_filter.1 hr0
  refine ⟨r0, hmem, by simpa using hw, ?_⟩
  rw [he2]
  dsimp only
  split_ifs with hx
  · refine ⟨rfl, rfl, rfl, Or.inr ⟨rfl, ?_⟩⟩
    simp only [Bool.or_eq_true, Bool.and_eq_true] at hx
    rcases hx with hx | hx
    · left
      revert hx
      cases hk : policy.keepSent with
      | none => simp
      | some keep => intro hx; simp at hx; exact ⟨keep, rfl, hx.1, hx.2⟩
    · exact Or.inr hx
  · exact ⟨rfl, rfl, rfl, Or.inl rfl⟩

theorem backfill_of {s : SentBox} {epoch : Nat} (h : s.backfilled = some epoch) :
    (s.backfill epoch).2 = [] := by
  unfold SentBox.backfill; simp [h]

/-- **A box is rewritten at most once an epoch.** -/
theorem backfill_once (s : SentBox) (epoch : Nat) : ((s.backfill epoch).1.backfill epoch).2 = [] := by
  apply backfill_of
  unfold SentBox.backfill
  split_ifs with h <;> simp [h]

end CryptWalker.GroupChat.Member

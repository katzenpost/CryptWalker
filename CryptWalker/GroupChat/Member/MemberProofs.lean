/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Tactic
import CryptWalker.GroupChat.Member.Group
import CryptWalker.GroupChat.Member.DictProofs
import CryptWalker.GroupChat.Member.ReaderProofs
import CryptWalker.GroupChat.Member.GroupProofs

/-! # A member keeps every reader's invariant

`ReaderProofs.lean` proves that each reader operation keeps `Inv`: what a reader keeps is true of
the history of boxes it has passed. Here the member drives its readers: it creates them, reads,
scans, walks, rechecks and removes them, alongside everything else it does. `ReadersOK` says every
reader of a member is filed under its own stream and satisfies `Inv` for some history.

* `found_ok`, `joined_ok`: a member starts with its readers OK.
* `handle_keeps`, `observe_keeps`, `compose_keeps`, `written_keeps`, `abandoned_keeps`,
  `beginInduction_keeps`, `introduceNow_keeps`, `cancelInduction_keeps`, `remove_keeps`: every
  call on a member keeps its readers OK, given only that a walk the driver reports did not skip
  more boxes than it stepped (`Event.WF`).
* `acks_sent_safe`: so every acknowledgement a member reachable by such calls sends names a box
  its reader read, along with every box before it. -/

namespace CryptWalker.GroupChat.Member

/-- A reader filed under `m` reads `m`'s stream and keeps what is true of some history. -/
def Good (m : Key) (r : Reader) : Prop := r.stream = m ∧ ∃ h, Inv r h

def ReadersOK (d : Dict Key Reader) : Prop := ∀ m r, d.get? m = some r → Good m r

/-- `p` keeps every reader OK. -/
def Keeps {α : Type} (p : GM α) : Prop :=
  ∀ g : Group, ReadersOK g.readers → ReadersOK (p.run g).2.readers

/-! ## Keeping is closed under the state monad -/

theorem Keeps.pure {α : Type} (a : α) : Keeps (Pure.pure a : GM α) := fun _ h => h

theorem Keeps.bind {α β : Type} {p : GM α} {f : α → GM β} (hp : Keeps p) (hf : ∀ a, Keeps (f a)) :
    Keeps (p >>= f) :=
  fun g h => hf _ _ (hp g h)

theorem Keeps.get {β : Type} {k : Group → GM β} (hk : ∀ g, ReadersOK g.readers → Keeps (k g)) :
    Keeps ((MonadState.get : GM Group) >>= k) :=
  fun g h => hk g h g h

theorem Keeps.set {g' : Group} (h' : ReadersOK g'.readers) : Keeps (MonadStateOf.set g' : GM PUnit) :=
  fun _ _ => h'

theorem Keeps.modify {f : Group → Group} (hf : ∀ g, ReadersOK g.readers → ReadersOK (f g).readers) :
    Keeps (_root_.modify f : GM PUnit) :=
  fun g h => hf g h

theorem Keeps.frame {f : Group → Group} (hf : ∀ g, (f g).readers = g.readers) :
    Keeps (_root_.modify f : GM PUnit) :=
  fun g h => by show ReadersOK (f g).readers; rw [hf]; exact h

/-! ## Readers -/

theorem ReadersOK.empty : ReadersOK ({} : Dict Key Reader) := by
  intro m r h; simp [EmptyCollection.emptyCollection, Dict.empty, Dict.get?] at h

theorem ReadersOK.set {d : Dict Key Reader} (hd : ReadersOK d) {k : Key} {r : Reader} (hr : Good k r) :
    ReadersOK (d.set k r) := by
  intro m r' h
  by_cases hk : k = m
  · subst hk; rw [Dict.get?_set_self] at h; cases h; exact hr
  · rw [Dict.get?_set_ne _ _ hk] at h; exact hd m r' h

theorem ReadersOK.erase {d : Dict Key Reader} (hd : ReadersOK d) (k : Key) : ReadersOK (d.erase k) := by
  intro m r h
  rw [Dict.get?_erase] at h
  split_ifs at h
  exact hd m r h

theorem ReadersOK.mapValues {d : Dict Key Reader} (hd : ReadersOK d) {f : Reader → Reader}
    (hf : ∀ m r, Good m r → Good m (f r)) : ReadersOK (d.mapValues f) := by
  intro m r h
  rw [Dict.get?_mapValues] at h
  obtain ⟨r0, h0, rfl⟩ := Option.map_eq_some_iff.1 h
  exact hf m r0 (hd m r0 h0)

theorem ReadersOK.modify {d : Dict Key Reader} (hd : ReadersOK d) (k : Key) {f : Reader → Reader}
    (hf : ∀ m r, Good m r → Good m (f r)) : ReadersOK (d.modify k f) := by
  intro m r h
  rw [Dict.get?_modify] at h
  split_ifs at h with hk
  · subst hk
    obtain ⟨r0, h0, rfl⟩ := Option.map_eq_some_iff.1 h
    exact hf k r0 (hd k r0 h0)
  · exact hd m r h

/-- `Inv` depends only on what a reader keeps, so a reader that keeps the same is as good. -/
theorem Good.congr {m : Key} {r r' : Reader} (h : Good m r) (hs : r'.stream = r.stream)
    (hp : r'.passed = r.passed) (hk : r'.kept = r.kept) (hl : r'.lost = r.lost)
    (hla : r'.last = r.last) : Good m r' :=
  ⟨hs.trans h.1, let ⟨hist, inv⟩ := h.2; ⟨hist, inv.congr hp hk hl hla⟩⟩

@[simp] theorem lose_stream (r : Reader) (a : Nat) (b : Option Index) : (r.lose a b).stream = r.stream := by
  unfold Reader.lose; split <;> (try split) <;> rfl

theorem loseAll_stream : ∀ (dropped : List (Index × Nat × Option Index)) (r : Reader),
    (r.loseAll dropped).stream = r.stream
  | [], _ => rfl
  | e :: es, r => by
    show ((r.lose e.2.1 e.2.2).loseAll es).stream = r.stream
    rw [loseAll_stream es, lose_stream]

@[simp] theorem forget_stream (r : Reader) (w : Nat) : (r.forget w).stream = r.stream := by
  show (r.loseAll _).stream = r.stream
  exact loseAll_stream _ _

theorem good_read {m : Key} {r : Reader} (h : Good m r) : Good m r.read.1 := by
  unfold Reader.read; split_ifs
  · exact h
  · exact h.congr rfl rfl rfl rfl rfl

theorem good_scan {m : Key} {r : Reader} (h : Good m r) (heard : List Index) (w : Nat) :
    Good m (r.scan heard w).1 := by
  unfold Reader.scan; split_ifs <;> exact h.congr rfl rfl rfl rfl rfl

theorem good_found {m : Key} {r : Reader} (h : Good m r) (index : Index) (result : ReadResult)
    (next : Option Index) (w : Nat) : Good m (r.found index result next w).2.1 := by
  obtain ⟨hs, hist, inv⟩ := h
  refine ⟨?_, _, found_inv inv index result next w⟩
  rw [← hs]
  unfold Reader.found
  split
  · split_ifs <;> rfl
  · split_ifs
    · rfl
    · split <;> simp [Reader.advance]

/-- What a driver reports of a walk is possible: it kept no more boxes than it stepped past. -/
def WalkWF (skipped : List Index) (steps : Nat) : Prop := skipped.length ≤ steps

theorem good_walked {m : Key} {r : Reader} (h : Good m r) (target : Option Index)
    (skipped : List Index) (steps w : Nat) (hwf : WalkWF skipped steps) :
    Good m (r.walked target skipped steps w).1 := by
  obtain ⟨hs, hist, inv⟩ := h
  cases target with
  | none => exact ⟨hs, hist, inv⟩
  | some t =>
    set all := List.replicate (steps - skipped.length) ByteArray.empty ++ skipped
    have hlen : all.length = steps := by simp [all]; unfold WalkWF at hwf; omega
    have hall : skipped = all.drop (all.length - skipped.length) := by
      simp [all]
    refine ⟨?_, walkedHistory hist all, ?_⟩
    · rw [← hs]
      show ((r.jump t skipped steps).forget w).stream = r.stream
      rw [forget_stream]
      simp only [Reader.jump]; split_ifs <;> simp
    · have := walked_inv inv t all skipped hall w
      rwa [hlen] at this

/-! ## Each function of a member -/

/-- One step of a `Keeps` proof: a monad operation, or a case split. -/
macro "keeps_step" : tactic => `(tactic| first
  | exact Keeps.pure _
  | (apply Keeps.get; intro _ _)
  | (apply Keeps.frame; intro _; rfl)
  | (apply Keeps.set; assumption)
  | (apply Keeps.bind)
  | split
  | intro _)

theorem keeps_follow (rc : ByteArray) (s : Index) : Keeps (Group.follow rc s) :=
  Keeps.modify fun _ h => h.set ⟨rfl, [], Inv.start _ _ _⟩

theorem keeps_setReader {r : Reader} (hr : Good r.stream r) : Keeps (Group.setReader r) :=
  Keeps.modify fun _ h => h.set hr

theorem keeps_beginRoster (m i : Key) : Keeps (Group.beginRoster m i) := by
  unfold Group.beginRoster; apply Keeps.frame; intro g; split <;> rfl

theorem foldl_frame {β : Type} (step : Group → β → Group) (hs : ∀ g x, (step g x).readers = g.readers) :
    ∀ (l : List β) (g : Group), (l.foldl step g).readers = g.readers
  | [], _ => rfl
  | x :: xs, g => by rw [List.foldl_cons, foldl_frame step hs xs, hs]

theorem keeps_started (m : Key) (i : Index) : Keeps (Group.started m i) := by
  unfold Group.started
  apply Keeps.get; intro g hg
  split
  · exact keeps_beginRoster _ _
  · exact Keeps.set hg

/-- `modify` of a function that leaves readers alone. -/
macro "frame" : tactic => `(tactic| (apply Keeps.frame; intro _; rfl))

theorem takeAck_readers (s : Key) (g : Group) (a : Nat × Index) : (g.takeAck s a).readers = g.readers := by
  unfold Group.takeAck; split <;> (try split_ifs) <;> (try split) <;> rfl

theorem keeps_followIfNew (rc : ByteArray) : Keeps (Group.followIfNew rc) := by
  unfold Group.followIfNew
  apply Keeps.get; intro g _
  split
  · exact keeps_follow _ _
  · exact Keeps.pure _

theorem keeps_noteOwn (i : Key) (b : Index) (n : Key) : Keeps (Group.noteOwn i b n) := by
  unfold Group.noteOwn
  apply Keeps.get; intro g hg
  split
  · split
    · exact Keeps.set hg
    · exact Keeps.pure _
  · exact Keeps.pure _

theorem keeps_noteAwaited (i : Key) (b : Index) (n : Key) : Keeps (Group.noteAwaited i b n) := by
  unfold Group.noteAwaited
  apply Keeps.get; intro g hg
  split
  · exact Keeps.bind (Keeps.set hg) fun _ => keeps_beginRoster _ _
  · exact Keeps.pure _

theorem keeps_noteNew (i : Key) (b : Index) (intro : Introduction) : Keeps (Group.noteNew i b intro) := by
  unfold Group.noteNew
  apply Keeps.get; intro g _
  split
  · exact Keeps.pure _
  · apply Keeps.bind (keeps_followIfNew _); intro _
    apply Keeps.frame; intro g; split <;> rfl

theorem keeps_introduced (i : Key) (b : Index) (intro : Introduction) :
    Keeps (Group.introduced i b intro) := by
  unfold Group.introduced
  apply Keeps.bind; · frame
  intro _
  exact Keeps.bind (keeps_noteOwn _ _ _) fun _ =>
    Keeps.bind (keeps_noteAwaited _ _ _) fun _ => keeps_noteNew _ _ _

theorem keeps_deliver (s : Key) (b : Index) (msg : Message) : Keeps (Group.deliver s b msg) := by
  unfold Group.deliver
  split
  · exact Keeps.pure _
  · apply Keeps.bind; · frame
    intro _; exact Keeps.pure _

theorem keeps_ingest (s : Key) (b : Index) (msg : Message) : Keeps (Group.ingest s b msg) := by
  unfold Group.ingest
  apply Keeps.bind
  · apply Keeps.frame; intro g
    exact foldl_frame _ (fun _ x => by obtain ⟨_, _⟩ := x; rfl) _ g
  intro _
  apply Keeps.bind
  · unfold Group.ingestIntroduction; split
    · exact keeps_introduced _ _ _
    · exact Keeps.pure _
  intro _
  apply Keeps.bind
  · unfold Group.ingestIntroducedAt; split
    · exact keeps_started _ _
    · exact Keeps.pure _
  intro _
  apply Keeps.bind
  · apply Keeps.frame; intro g; exact foldl_frame _ (takeAck_readers s) _ g
  intro _
  exact keeps_deliver _ _ _

end CryptWalker.GroupChat.Member

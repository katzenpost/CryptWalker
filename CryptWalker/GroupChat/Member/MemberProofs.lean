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
* `acks_sent_safe`: so every acknowledgement a member reachable by such calls (`Reachable`) sends
  names a box its reader read, along with every box before it. -/

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

theorem Keeps.map {α β : Type} {p : GM α} (f : α → β) (hp : Keeps p) : Keeps (f <$> p) :=
  fun g h => hp g h

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

theorem good_scan {m : Key} {r : Reader} (h : Good m r) (heard : List Nat) (w : Nat) :
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

theorem takeAck_readers (s : Key) (g : Group) (a : Nat × Nat) : (g.takeAck s a).readers = g.readers := by
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

theorem Good.self {m : Key} {r : Reader} (h : Good m r) : Good r.stream r := h.1 ▸ h

theorem good_get {d : Dict Key Reader} (hd : ReadersOK d) {m : Key} {r : Reader}
    (h : d.get? m = some r) : Good r.stream r := (hd m r h).self

theorem keeps_scanStream (s : Key) : Keeps (Group.scanStream s) := by
  unfold Group.scanStream
  apply Keeps.get; intro g hg
  split
  · exact Keeps.pure _
  · next r hr =>
    have hgood := good_scan (good_get hg hr) (g.heard s) g.recheck
    split
    next r' es heq =>
      rw [heq] at hgood
      exact Keeps.bind (keeps_setReader hgood.self) fun _ => Keeps.pure _

theorem keeps_boxRead (s : Key) (b : Index) (res : ReadResult) (n : Option Index) :
    Keeps (Group.boxRead s b res n) := by
  unfold Group.boxRead
  apply Keeps.get; intro g hg
  split
  · exact Keeps.pure _
  · next r hr =>
    have hgood := good_found (good_get hg hr) b res n g.recheck
    split
    next msg r' es heq =>
    rw [heq] at hgood
    apply Keeps.bind (keeps_setReader hgood.self); intro _
    split
    · exact Keeps.bind (keeps_ingest _ _ _) fun _ => Keeps.pure _
    · exact Keeps.pure _

/-! ## Writing -/

theorem keeps_written (t : Nat) (b : Index) (pt : Option Payload) : Keeps (Group.written t b pt) := by
  unfold Group.written; apply Keeps.frame; intro g; split <;> rfl

theorem keeps_write (o : Outgoing) : Keeps (Group.write o) := by
  unfold Group.write
  apply Keeps.get; intro g _
  split
  · exact Keeps.pure _
  · apply Keeps.bind; · frame
    intro _; exact Keeps.bind (keeps_written _ _ _) fun _ => Keeps.pure _

theorem keeps_stage (m : Message) (p : Pending) : Keeps (Group.stage m p) := by
  unfold Group.stage
  apply Keeps.bind; · frame
  intro _; apply Keeps.get; intro _ _; exact Keeps.pure _

theorem keeps_withAcks (m : Message) (p : Pending) : Keeps (Group.withAcks m p) := by
  unfold Group.withAcks
  apply Keeps.get; intro g hg
  exact Keeps.bind (Keeps.set hg) fun _ => Keeps.pure _

theorem keeps_control : Keeps Group.control := by
  unfold Group.control
  apply Keeps.get; intro g hg
  exact Keeps.bind (Keeps.set hg) fun _ => Keeps.pure _

theorem keeps_next : Keeps Group.next := by
  unfold Group.next
  apply Keeps.get; intro g hg
  split
  · exact keeps_control
  · exact Keeps.bind (Keeps.set hg) fun _ => Keeps.pure _

theorem keeps_release : Keeps Group.release := by unfold Group.release; frame

theorem keeps_hold : Keeps Group.hold := by unfold Group.hold; frame

theorem keeps_introduction (name : String) (rc : ByteArray) : Keeps (Group.introduction name rc) := by
  unfold Group.introduction
  apply Keeps.get; intro _ _
  exact Keeps.bind (keeps_followIfNew _) fun _ => Keeps.bind keeps_release fun _ => Keeps.pure _

theorem keeps_introduceNow (name : String) (rc : ByteArray) : Keeps (Group.introduceNow name rc) :=
  Keeps.bind (keeps_introduction _ _) fun _ => keeps_stage _ _

theorem keeps_flushSome : ∀ n, Keeps (Group.flushSome n)
  | 0 => by unfold Group.flushSome; exact Keeps.pure _
  | n + 1 => by
    unfold Group.flushSome
    apply Keeps.get; intro _ _
    split
    · exact Keeps.pure _
    · apply Keeps.bind keeps_next; intro ⟨m, p⟩
      apply Keeps.bind (keeps_withAcks _ _); intro ⟨m, p⟩
      exact Keeps.bind (keeps_stage _ _) fun o => Keeps.bind (keeps_write o) fun _ =>
        Keeps.bind (keeps_flushSome n) fun _ => Keeps.pure _

theorem keeps_flush : Keeps Group.flush := by
  unfold Group.flush
  apply Keeps.get; intro _ _
  apply Keeps.bind (keeps_flushSome _); intro _
  apply Keeps.get; intro g hg
  split
  · exact Keeps.bind (Keeps.set hg) fun _ => Keeps.pure _
  · exact Keeps.pure _

theorem keeps_commitInduction : Keeps Group.commitInduction := by
  unfold Group.commitInduction
  apply Keeps.get; intro _ _
  split
  · exact Keeps.pure _
  · exact Keeps.bind (keeps_introduceNow _ _) fun o => Keeps.bind (keeps_write o) fun _ =>
      Keeps.bind keeps_flush fun _ => Keeps.pure _

theorem keeps_progress : Keeps Group.progress := by
  unfold Group.progress
  apply Keeps.bind keeps_flush; intro _
  apply Keeps.bind
  · unfold Group.holdIfSettled; apply Keeps.get; intro _ _
    split
    · exact keeps_hold
    · exact Keeps.pure _
  intro _
  apply Keeps.bind
  · unfold Group.commitIfReady; apply Keeps.get; intro _ _
    split
    · exact keeps_commitInduction
    · exact Keeps.pure _
  intro _; exact Keeps.pure _

theorem keeps_derived (l : List Index) : Keeps (Group.derived l) := by
  unfold Group.derived
  exact Keeps.bind (by frame) fun _ => keeps_progress

theorem keeps_invite (name : String) (rc : ByteArray) (c : Bool) : Keeps (Group.invite name rc c) := by
  unfold Group.invite
  apply Keeps.bind; · frame
  intro _
  apply Keeps.get; intro g hg
  refine Keeps.bind (Keeps.set ?_) fun _ => ?_
  · exact hg.mapValues fun _ _ h => good_read h
  exact Keeps.bind keeps_progress fun _ => Keeps.pure _

/-! ## Membership and time -/

theorem keeps_remove (m : Key) : Keeps (Group.remove m) :=
  Keeps.modify fun _ h => h.erase m

theorem keeps_onEpoch (e : Nat) : Keeps (Group.onEpoch e) := by
  unfold Group.onEpoch
  apply Keeps.bind; · frame
  intro _; apply Keeps.bind; · frame
  intro _; apply Keeps.get; intro _ hg
  refine Keeps.bind (Keeps.set ?_) fun _ => ?_
  · exact hg
  apply Keeps.get; intro _ hg
  exact Keeps.bind (Keeps.set hg) fun _ => Keeps.pure _

/-! ## Every call on a member -/

/-- What a driver reports is possible: a walk kept no more boxes than it stepped past. -/
def Event.WF : Event → Prop
  | .walked _ _ skipped steps => WalkWF skipped steps
  | _ => True

theorem handle_keeps {e : Event} (hwf : e.WF) : Keeps (Group.handle e) := by
  unfold Group.handle
  apply Keeps.get; intro g hg
  cases e with
  | send c => exact Keeps.bind (Keeps.set hg) fun _ => keeps_progress
  | read s =>
    dsimp only
    split
    · next r hr =>
      exact Keeps.bind (keeps_setReader (good_read (good_get hg hr)).self) fun _ => Keeps.pure _
    · exact Keeps.pure _
  | scan s => exact keeps_scanStream s
  | boxRead s b res n =>
    exact Keeps.bind (keeps_boxRead _ _ _ _) fun _ => Keeps.bind keeps_progress fun _ => Keeps.pure _
  | indexesDerived _ l => exact keeps_derived l
  | walked s t sk st =>
    dsimp only
    split
    · next r hr =>
      exact Keeps.bind (keeps_setReader (good_walked (good_get hg hr) t sk st g.recheck hwf).self)
        fun _ => Keeps.pure _
    · exact Keeps.pure _
  | invite n rc => exact keeps_invite _ _ _
  | introduce n rc =>
    dsimp only
    split
    · exact keeps_invite _ _ _
    · exact Keeps.bind (Keeps.set hg) fun _ => keeps_progress
  | remove m => exact Keeps.bind (keeps_remove m) fun _ => Keeps.pure _
  | epochChanged e => exact keeps_onEpoch e

theorem observe_keeps (s : Key) (b : Index) (msg : Option Message) (n : Index) :
    Keeps (Group.observe s b msg n) := by
  unfold Group.observe
  apply Keeps.get; intro g hg
  split
  · exact Keeps.pure _
  · next r hr =>
    refine Keeps.bind (keeps_setReader ?_) fun _ => ?_
    · exact (good_get hg hr).congr rfl rfl rfl rfl rfl
    apply Keeps.bind (keeps_boxRead _ _ _ _); intro _
    refine Keeps.bind (Keeps.modify fun _ h => ?_) fun _ => Keeps.pure _
    apply ReadersOK.modify h
    intro _ _ h; exact h.congr rfl rfl rfl rfl rfl

theorem keeps_stageAll : ∀ l, Keeps (Group.stageAll l)
  | [] => by unfold Group.stageAll; exact Keeps.pure _
  | (m, p) :: l => by
    unfold Group.stageAll
    exact Keeps.bind (keeps_withAcks m p) fun _ => Keeps.bind (keeps_stage _ _) fun _ =>
      Keeps.bind (keeps_stageAll l) fun _ => Keeps.pure _

theorem compose_keeps (c : Option ByteArray) : Keeps (Group.compose c) := by
  unfold Group.compose
  apply Keeps.get; intro _ _
  dsimp only
  split
  · exact Keeps.bind (Keeps.map _ keeps_control) fun _ => keeps_stageAll _
  · exact Keeps.bind (Keeps.pure _) fun _ => keeps_stageAll _

theorem written_keeps (t : Nat) (b : Index) (pt : Option Payload) : Keeps (Group.written t b pt) :=
  keeps_written t b pt

theorem abandoned_keeps (t : Nat) : Keeps (Group.abandoned t) := by
  unfold Group.abandoned; apply Keeps.frame; intro g; split <;> rfl

theorem beginInduction_keeps : Keeps Group.beginInduction := by
  unfold Group.beginInduction
  exact Keeps.bind (compose_keeps _) fun _ => Keeps.bind keeps_hold fun _ => Keeps.pure _

theorem introduceNow_keeps (name : String) (rc : ByteArray) : Keeps (Group.introduceNow name rc) :=
  keeps_introduceNow name rc

theorem cancelInduction_keeps : Keeps Group.cancelInduction := keeps_release

theorem remove_keeps (m : Key) : Keeps (Group.remove m) := keeps_remove m

/-! ## Starting -/

theorem Keeps.foldlM {β : Type} {f : Unit → β → GM Unit} (hf : ∀ x, Keeps (f () x)) :
    ∀ (l : List β), Keeps (l.foldlM f ())
  | [] => Keeps.pure _
  | x :: xs => by
    rw [List.foldlM_cons]
    exact Keeps.bind (hf x) fun _ => Keeps.foldlM hf xs

theorem found_ok (rc : ByteArray) (fs : List ByteArray) (policy : Retention) (w : Nat) :
    ReadersOK (Group.found rc fs policy w).readers := by
  unfold Group.found
  apply Keeps.foldlM _ fs _ ReadersOK.empty
  intro cap
  split
  · exact keeps_follow _ _
  · exact Keeps.pure _

theorem joined_ok (rc : ByteArray) (reply : JoinReply) (policy : Retention) (w : Nat) :
    ReadersOK (Group.joined rc reply policy w).readers := by
  unfold Group.joined
  apply Keeps.foldlM _ reply.members _ ReadersOK.empty
  intro slot
  split
  · exact keeps_follow _ _
  · exact Keeps.pure _

/-! ## Acknowledgements sent -/

/-- A member as calls on it can leave it, from its start. -/
inductive Reachable : Group → Prop
  | found (rc : ByteArray) (fs : List ByteArray) (policy : Retention) (w : Nat) :
      Reachable (Group.found rc fs policy w)
  | joined (rc : ByteArray) (reply : JoinReply) (policy : Retention) (w : Nat) :
      Reachable (Group.joined rc reply policy w)
  | handle {g : Group} (e : Event) : e.WF → Reachable g → Reachable ((Group.handle e).run g).2
  | observe {g : Group} (s : Key) (b : Index) (msg : Option Message) (n : Index) :
      Reachable g → Reachable ((Group.observe s b msg n).run g).2
  | compose {g : Group} (c : Option ByteArray) : Reachable g → Reachable ((Group.compose c).run g).2
  | written {g : Group} (t : Nat) (b : Index) (pt : Option Payload) :
      Reachable g → Reachable ((Group.written t b pt).run g).2
  | abandoned {g : Group} (t : Nat) : Reachable g → Reachable ((Group.abandoned t).run g).2
  | beginInduction {g : Group} : Reachable g → Reachable (Group.beginInduction.run g).2
  | introduceNow {g : Group} (name : String) (rc : ByteArray) :
      Reachable g → Reachable ((Group.introduceNow name rc).run g).2
  | cancelInduction {g : Group} : Reachable g → Reachable (Group.cancelInduction.run g).2
  | remove {g : Group} (m : Key) : Reachable g → Reachable ((Group.remove m).run g).2
  /-- The client changes its retention policy, as a user's disappearing messages setting does. -/
  | policy {g : Group} (p : Retention) : Reachable g → Reachable { g with policy := p }

theorem Reachable.ok {g : Group} : Reachable g → ReadersOK g.readers
  | .found rc fs p w => found_ok rc fs p w
  | .joined rc reply p w => joined_ok rc reply p w
  | .handle _ hwf h => handle_keeps hwf _ h.ok
  | .observe s b msg n h => observe_keeps s b msg n _ h.ok
  | .compose _ h => compose_keeps _ _ h.ok
  | .written t b pt h => written_keeps t b pt _ h.ok
  | .abandoned _ h => abandoned_keeps _ _ h.ok
  | .beginInduction h => beginInduction_keeps _ h.ok
  | .introduceNow name rc h => introduceNow_keeps name rc _ h.ok
  | .cancelInduction h => cancelInduction_keeps _ h.ok
  | .remove _ h => remove_keeps _ _ h.ok
  | .policy _ h => h.ok

/-- **Every acknowledgement a reachable member sends names a box its reader of that stream read,
along with every box before it.** Every message takes its acknowledgements from `acksOf`. -/
theorem acks_sent_safe {g : Group} (hg : Reachable g) (p : Pending) :
    ∀ x ∈ (g.acksOf p).1, ∃ m r h b, (x.1, some m) ∈ g.rosters.known g.me ∧
      g.readers.get? m = some r ∧ r.stream = m ∧ Inv r h ∧ counter b = x.2 ∧ Safe h (some b) := by
  intro x hx
  obtain ⟨m, r, b, hk, hr, hrun, hb⟩ := acksOf_runs g p x hx
  obtain ⟨hs, h, inv⟩ := hg.ok m r hr
  exact ⟨m, r, h, b, hk, hr, hs, inv, hb, hrun ▸ run_safe inv⟩

end CryptWalker.GroupChat.Member

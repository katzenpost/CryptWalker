/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Tactic
import Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member.Reader

/-! # A reader acknowledges only what it has read

A `History` is a ghost record of every box a reader passed, read or not. `Inv` ties the reader's
state to it; every operation keeps `Inv`, and under it `run` names a box read along with every box
before it (`run_safe`). See "Opportunistic acknowledgements and backfill" in the group chat spec. -/

namespace Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member

/-- Every box a reader has passed, in order, and whether it has read it. -/
abbrev History := List (Index × Bool)

/-- Box `p` of the history is `b`. -/
def Names (h : History) (b : Index) (p : Nat) : Prop := ∃ x, h[p]? = some (b, x)

/-- Every box up to and including the one named has been read. -/
def Safe (h : History) : Option Index → Prop
  | none => True
  | some b => ∃ p, Names h b p ∧ ∀ q ≤ p, ∃ c, h[q]? = some (c, true)

/-- What the reader keeps is true of its history. -/
structure Inv (r : Reader) (h : History) : Prop where
  len : h.length = r.passed
  kept : ∀ e ∈ r.kept, h[e.2.1]? = some (e.1, false)
  nodup : (r.kept.map (·.2.1)).Nodup
  keptBefore : ∀ e ∈ r.kept, ∀ b, e.2.2 = some b → ∃ p < e.2.1, Names h b p
  lost : ∀ l b, r.lost = some (l, b) → l ≤ h.length ∧ ∀ c, b = some c → ∃ p < l, Names h c p
  /-- Every box passed unread is kept, or at or after the first one given up on. -/
  covered : ∀ p c, h[p]? = some (c, false) →
    (∃ e ∈ r.kept, e.2.1 = p) ∨ ∃ l b, r.lost = some (l, b) ∧ l ≤ p
  last : ∀ b, r.last = some b → ∃ p, Names h b p

theorem Inv.start (stream : Key) (readCap : ByteArray) (next : Index) :
    Inv ⟨stream, readCap, next, none, 0, [], none, .idle, []⟩ [] where
  len := rfl
  kept := by simp
  nodup := by simp
  keptBefore := by simp
  lost := by simp
  covered := by simp
  last := by simp

/-- `Inv` depends only on what the reader keeps. -/
theorem Inv.congr {r r' : Reader} {h : History} (inv : Inv r h) (hp : r'.passed = r.passed)
    (hk : r'.kept = r.kept) (hl : r'.lost = r.lost) (hla : r'.last = r.last) : Inv r' h := by
  obtain ⟨a, b, c, d, e, f, g⟩ := inv
  exact ⟨hp ▸ a, hk ▸ b, hk ▸ c, hk ▸ d, hl ▸ e, hk ▸ hl ▸ f, hla ▸ g⟩

/-! ## Histories only grow and only gain reads -/

/-- `h'` extends `h`, with boxes possibly turned from unread to read. -/
def Grows (h h' : History) : Prop :=
  h.length ≤ h'.length ∧
    ∀ (p : Nat) (c : Index) (x : Bool), h[p]? = some (c, x) → ∃ y, h'[p]? = some (c, y) ∧ (x → y)

theorem Names.grow {h h' : History} (g : Grows h h') {b : Index} {p : Nat} (n : Names h b p) :
    Names h' b p := by
  obtain ⟨x, hx⟩ := n
  obtain ⟨y, hy, -⟩ := g.2 p b x hx
  exact ⟨y, hy⟩

theorem Safe.mono {h h' : History} (g : Grows h h') : ∀ {b}, Safe h b → Safe h' b
  | none, _ => trivial
  | some _, ⟨p, n, hr⟩ => ⟨p, n.grow g, fun q hq => by
      obtain ⟨c, hc⟩ := hr q hq
      obtain ⟨y, hy, hxy⟩ := g.2 q c true hc
      exact ⟨c, by rw [hy, hxy rfl]⟩⟩

theorem Grows.refl (h : History) : Grows h h := ⟨le_rfl, fun _ _ x hp => ⟨x, hp, id⟩⟩

theorem Grows.append (h t : History) : Grows h (h ++ t) :=
  ⟨by simp, fun p c x hp => ⟨x, by rw [List.getElem?_append_left (List.getElem?_eq_some_iff.1 hp).1, hp], id⟩⟩

theorem Grows.set (h : History) (p : Nat) (c : Index) (hp : h[p]? = some (c, false)) :
    Grows h (h.set p (c, true)) := by
  refine ⟨by simp, fun q d x hq => ?_⟩
  by_cases hpq : p = q
  · subst hpq
    rw [hp] at hq
    cases hq
    exact ⟨true, by simp [List.getElem?_set_self (List.getElem?_eq_some_iff.1 hp).1], fun _ => rfl⟩
  · exact ⟨x, by rw [List.getElem?_set_ne hpq, hq], id⟩

/-! ## The acknowledgement is safe -/

/-- The gap with the earliest position, as `run` picks it. -/
theorem foldl_min (gs : List (Nat × Option Index)) :
    ∀ g, let m := gs.foldl (fun m x => if x.1 < m.1 then x else m) g
      (m = g ∨ m ∈ gs) ∧ m.1 ≤ g.1 ∧ ∀ x ∈ gs, m.1 ≤ x.1 := by
  induction gs with
  | nil => intro g; simp
  | cons y ys ih =>
    intro g
    simp only [List.foldl_cons]
    split_ifs with hy
    · obtain ⟨hm, hle, hall⟩ := ih y
      refine ⟨?_, by omega, ?_⟩
      · rcases hm with hm | hm
        · exact Or.inr (by simp [hm])
        · exact Or.inr (List.mem_cons_of_mem _ hm)
      · intro x hx
        rcases List.mem_cons.1 hx with rfl | hx
        · exact hle
        · exact hall x hx
    · obtain ⟨hm, hle, hall⟩ := ih g
      refine ⟨?_, hle, ?_⟩
      · rcases hm with hm | hm
        · exact Or.inl hm
        · exact Or.inr (List.mem_cons_of_mem _ hm)
      · intro x hx
        rcases List.mem_cons.1 hx with rfl | hx
        · omega
        · exact hall x hx

/-- Every box before the earliest gap has been read. -/
theorem read_before {r : Reader} {h : History} (inv : Inv r h) {m : Nat}
    (hk : ∀ e ∈ r.kept, m ≤ e.2.1) (hl : ∀ l b, r.lost = some (l, b) → m ≤ l) :
    ∀ q < m, ∀ c x, h[q]? = some (c, x) → x = true := by
  intro q hq c x hx
  cases x
  · rcases inv.covered q c hx with ⟨e, he, rfl⟩ | ⟨l, b, hlost, hlq⟩
    · exact absurd (hk e he) (by omega)
    · exact absurd (hl l b hlost) (by omega)
  · rfl

theorem safe_upto {h : History} {m : Nat} (hread : ∀ q < m, ∀ c x, h[q]? = some (c, x) → x = true)
    {b : Index} {p : Nat} (hp : p < m) (n : Names h b p) : Safe h (some b) := by
  refine ⟨p, n, fun q hq => ?_⟩
  obtain ⟨x, hx⟩ := n
  have hlen : q < h.length := by
    have := (List.getElem?_eq_some_iff.1 hx).1
    omega
  obtain ⟨⟨c, y⟩, hy⟩ := Option.isSome_iff_exists.1 (by simp [hlen] : h[q]?.isSome)
  exact ⟨c, by rw [hy, hread q (by omega) c y hy]⟩

/-- What a reader acknowledges it has read, with every box before it. -/
theorem run_safe {r : Reader} {h : History} (inv : Inv r h) : Safe h r.run := by
  unfold Reader.run
  split
  · next hgaps =>
    have hk : r.kept = [] := by
      have := congrArg List.length hgaps
      simp at this; exact this.1
    have hl : r.lost = none := by
      cases hlost : r.lost <;> simp_all
    cases hlast : r.last with
    | none => trivial
    | some b =>
      obtain ⟨p, n⟩ := inv.last b hlast
      obtain ⟨x, hx⟩ := n
      have hp : p < h.length := (List.getElem?_eq_some_iff.1 hx).1
      exact safe_upto (m := h.length) (fun q hq => read_before inv (m := h.length)
        (by simp [hk]) (by simp [hl]) q hq) hp ⟨x, hx⟩
  · next g gs hgaps =>
    obtain ⟨hm, hle, hall⟩ := foldl_min gs g
    set m := gs.foldl (fun m x => if x.1 < m.1 then x else m) g
    have hmin : ∀ x ∈ r.kept.map (·.2) ++ r.lost.toList, m.1 ≤ x.1 := by
      rw [hgaps]
      intro x hx
      rcases List.mem_cons.1 hx with rfl | hx
      · exact hle
      · exact hall x hx
    have hmem : m ∈ r.kept.map (·.2) ++ r.lost.toList := by
      rw [hgaps]
      rcases hm with hm | hm
      · simp [hm]
      · exact List.mem_cons_of_mem _ hm
    have hread := read_before inv (m := m.1)
      (fun e he => hmin e.2 (List.mem_append_left _ (List.mem_map_of_mem (f := (·.2)) he)))
      (fun l b hl => hmin (l, b) (by simp [hl]))
    cases hb : m.2 with
    | none => trivial
    | some b =>
      rcases List.mem_append.1 hmem with hk | hl
      · obtain ⟨e, he, hem⟩ := List.mem_map.1 hk
        obtain ⟨p, hp, n⟩ := inv.keptBefore e he b (by rw [hem, hb])
        exact safe_upto hread (by rw [← hem]; exact hp) n
      · obtain ⟨l, c⟩ := m
        simp only at hb
        subst hb
        have hlost : r.lost = some (l, some b) := by simpa using hl
        obtain ⟨p, hp, n⟩ := (inv.lost l (some b) hlost).2 b rfl
        exact safe_upto hread hp n

/-! ## Every operation keeps `Inv` -/

/-- A gap's `before` names an earlier box. -/
def BeforeOK (h : History) (at_ : Nat) (b : Option Index) : Prop := ∀ c, b = some c → ∃ p < at_, Names h c p

def LostOK (h : History) (lost : Option (Nat × Option Index)) : Prop :=
  ∀ l b, lost = some (l, b) → l ≤ h.length ∧ BeforeOK h l b

theorem BeforeOK.grow {h h' : History} (g : Grows h h') {a : Nat} {b : Option Index}
    (hb : BeforeOK h a b) : BeforeOK h' a b :=
  fun c hc => (hb c hc).imp fun _ ⟨hp, n⟩ => ⟨hp, n.grow g⟩

theorem lose_lost (r : Reader) (a : Nat) (b : Option Index) :
    ∃ l c, (r.lose a b).lost = some (l, c) ∧ l ≤ a ∧
      ((l, c) = (a, b) ∨ r.lost = some (l, c)) ∧ ∀ l0 c0, r.lost = some (l0, c0) → l ≤ l0 := by
  unfold Reader.lose
  split
  · next l0 c0 hlost =>
    split_ifs with hlt
    · exact ⟨a, b, rfl, le_rfl, Or.inl rfl, fun l1 c1 h1 => by rw [hlost] at h1; cases h1; omega⟩
    · exact ⟨l0, c0, hlost, by omega, Or.inr hlost, fun l1 c1 h1 => by rw [hlost] at h1; cases h1; rfl⟩
  · next hlost => exact ⟨a, b, rfl, le_rfl, Or.inl rfl, fun l1 c1 h1 => by rw [hlost] at h1; cases h1⟩

@[simp] theorem lose_kept (r : Reader) (a : Nat) (b : Option Index) : (r.lose a b).kept = r.kept := by
  unfold Reader.lose; split <;> (try split) <;> rfl
@[simp] theorem lose_last (r : Reader) (a : Nat) (b : Option Index) : (r.lose a b).last = r.last := by
  unfold Reader.lose; split <;> (try split) <;> rfl
@[simp] theorem lose_passed (r : Reader) (a : Nat) (b : Option Index) : (r.lose a b).passed = r.passed := by
  unfold Reader.lose; split <;> (try split) <;> rfl

theorem lose_ok {h : History} {r : Reader} (hr : LostOK h r.lost) {a : Nat} {b : Option Index}
    (ha : a ≤ h.length) (hb : BeforeOK h a b) : LostOK h (r.lose a b).lost := by
  intro l c hl
  obtain ⟨l', c', hlost, -, hfrom, -⟩ := lose_lost r a b
  rw [hlost] at hl
  cases hl
  rcases hfrom with hfrom | hfrom
  · cases hfrom; exact ⟨ha, hb⟩
  · exact hr _ _ hfrom

/-- Giving up on boxes `dropped`: each is then at or after the first one given up on. -/
theorem loseAll_spec (h : History) :
    ∀ (dropped : List (Index × Nat × Option Index)) (r : Reader), LostOK h r.lost →
      (∀ e ∈ dropped, e.2.1 ≤ h.length ∧ BeforeOK h e.2.1 e.2.2) →
      (r.loseAll dropped).kept = r.kept ∧ (r.loseAll dropped).last = r.last ∧
      (r.loseAll dropped).passed = r.passed ∧ LostOK h (r.loseAll dropped).lost ∧
      (∀ e ∈ dropped, ∃ l b, (r.loseAll dropped).lost = some (l, b) ∧ l ≤ e.2.1) ∧
      (∀ l0 b0, r.lost = some (l0, b0) → ∃ l b, (r.loseAll dropped).lost = some (l, b) ∧ l ≤ l0)
  | [], r, hr, _ => ⟨rfl, rfl, rfl, hr, by simp, fun l0 b0 h0 => ⟨l0, b0, h0, le_rfl⟩⟩
  | e :: es, r, hr, he => by
    obtain ⟨l, c, hlost, hla, -, hmono⟩ := lose_lost r e.2.1 e.2.2
    have he0 := he e List.mem_cons_self
    obtain ⟨hk, hlast, hpassed, hlost', hcover, hmono'⟩ :=
      loseAll_spec h es (r.lose e.2.1 e.2.2) (lose_ok hr he0.1 he0.2)
        fun x hx => he x (List.mem_cons_of_mem _ hx)
    have hcons : r.loseAll (e :: es) = (r.lose e.2.1 e.2.2).loseAll es := rfl
    rw [hcons]
    refine ⟨by simpa using hk, by simpa using hlast, by simpa using hpassed, hlost', ?_, ?_⟩
    · intro x hx
      rcases List.mem_cons.1 hx with rfl | hx
      · obtain ⟨l', b', h', hle⟩ := hmono' l c hlost
        exact ⟨l', b', h', by omega⟩
      · exact hcover x hx
    · intro l0 b0 h0
      obtain ⟨l', b', h', hle⟩ := hmono' l c hlost
      exact ⟨l', b', h', le_trans hle (hmono l0 b0 h0)⟩

theorem forget_inv {r : Reader} {h : History} (inv : Inv r h) (window : Nat) :
    Inv (r.forget window) h := by
  have hdropped : ∀ e ∈ r.kept.filter (fun e => e.2.1 + window < r.passed),
      e.2.1 ≤ h.length ∧ BeforeOK h e.2.1 e.2.2 := by
    intro e he
    have hek := (List.mem_filter.1 he).1
    exact ⟨((List.getElem?_eq_some_iff.1 (inv.kept e hek)).1).le, inv.keptBefore e hek⟩
  obtain ⟨-, hlast, hpassed, hlost, hcover, hmono⟩ :=
    loseAll_spec h (r.kept.filter fun e => e.2.1 + window < r.passed) r inv.lost hdropped
  have hkept : ∀ e, e ∈ (r.forget window).kept ↔ e ∈ r.kept ∧ r.passed ≤ e.2.1 + window := by
    intro e; simp [Reader.forget]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · show h.length = (r.loseAll _).passed
    rw [hpassed]; exact inv.len
  · intro e he; exact inv.kept e ((hkept e).1 he).1
  · exact inv.nodup.sublist (List.filter_sublist.map _)
  · intro e he; exact inv.keptBefore e ((hkept e).1 he).1
  · exact hlost
  · intro p c hp
    rcases inv.covered p c hp with ⟨e, he, hep⟩ | ⟨l, b, hl, hlp⟩
    · by_cases hkeep : r.passed ≤ e.2.1 + window
      · exact Or.inl ⟨e, (hkept e).2 ⟨he, hkeep⟩, hep⟩
      · obtain ⟨l', b', h', hle⟩ := hcover e (List.mem_filter.2 ⟨he, by simp; omega⟩)
        exact Or.inr ⟨l', b', h', by omega⟩
    · obtain ⟨l', b', h', hle⟩ := hmono l b hl
      exact Or.inr ⟨l', b', h', by omega⟩
  · show ∀ b, (r.loseAll _).last = some b → _
    rw [hlast]; exact inv.last

theorem read_inv {r : Reader} {h : History} (inv : Inv r h) : Inv r.read.1 h := by
  unfold Reader.read; split_ifs
  · exact inv
  · exact inv.congr rfl rfl rfl rfl

theorem scan_inv {r : Reader} {h : History} (inv : Inv r h) (heard : List Nat) (window : Nat) :
    Inv (r.scan heard window).1 h := by
  unfold Reader.scan; split_ifs <;> exact inv.congr rfl rfl rfl rfl

/-- What reading a box adds to the history. -/
def foundHistory (r : Reader) (h : History) (index : Index) (result : ReadResult) (next : Option Index) :
    History :=
  match r.kept.find? (·.1 = index) with
  | some e => if result = .missing .notFound then h else h.set e.2.1 (e.1, true)
  | none =>
    if index ≠ r.next || r.mode = .idle then h
    else match result, next with
      | .missing .notFound, _ => h
      | _, none => h
      | _, some _ => h ++ [(index, true)]

theorem found_grows {r : Reader} {h : History} (inv : Inv r h) (index : Index) (result : ReadResult)
    (next : Option Index) : Grows h (foundHistory r h index result next) := by
  unfold foundHistory
  cases hf : r.kept.find? (·.1 = index) with
  | some e =>
    simp only
    split_ifs
    · exact Grows.refl h
    · exact Grows.set h _ _ (inv.kept e (List.mem_of_find?_eq_some hf))
  | none =>
    simp only
    split_ifs
    · exact Grows.refl h
    · rcases result with m | (_ | _) <;> cases next <;> first | exact Grows.refl h | exact Grows.append _ _

/-- Reading a box in order keeps `Inv`, with the box read added. -/
theorem advance_inv {r : Reader} {h : History} (inv : Inv r h) (index next : Index) :
    Inv (r.advance index next) (h ++ [(index, true)]) := by
  have g := Grows.append h [(index, true)]
  refine ⟨by simp [Reader.advance, inv.len], ?_, inv.nodup, ?_, ?_, ?_, ?_⟩
  · intro x hx
    have := inv.kept x hx
    rw [List.getElem?_append_left (List.getElem?_eq_some_iff.1 this).1, this]
  · intro x hx b hb
    obtain ⟨p, hp, nm⟩ := inv.keptBefore x hx b hb
    exact ⟨p, hp, nm.grow g⟩
  · intro l b hl
    obtain ⟨hle, hb⟩ := inv.lost l b hl
    exact ⟨by simp; omega, BeforeOK.grow g hb⟩
  · intro p c hp
    by_cases hpl : p < h.length
    · rw [List.getElem?_append_left hpl] at hp
      exact inv.covered p c hp
    · have hlt := (List.getElem?_eq_some_iff.1 hp).1
      simp at hlt
      have : p = h.length := by omega
      subst this
      simp at hp
  · intro b hb
    simp only [Reader.advance, Option.some.injEq] at hb
    subst hb
    exact ⟨h.length, true, by simp⟩

theorem not_mem_eraseP_self {α : Type} [DecidableEq α] {e : α} :
    ∀ {l : List α}, l.Nodup → e ∉ l.eraseP (· = e)
  | [], _ => by simp
  | a :: as, h => by
    rw [List.eraseP_cons]
    by_cases ha : a = e
    · subst ha; simpa using (List.nodup_cons.1 h).1
    · simp only [ha, decide_false, cond_false, List.mem_cons, not_or]
      exact ⟨Ne.symm ha, not_mem_eraseP_self (List.nodup_cons.1 h).2⟩

/-- Reading a box keeps `Inv`. -/
theorem found_inv {r : Reader} {h : History} (inv : Inv r h) (index : Index) (result : ReadResult)
    (next : Option Index) (window : Nat) :
    Inv (r.found index result next window).2.1 (foundHistory r h index result next) := by
  unfold Reader.found foundHistory
  cases hf : r.kept.find? (·.1 = index) with
  | some e =>
    simp only
    have hek := List.mem_of_find?_eq_some hf
    split_ifs with hnf
    · exact inv
    · have hpos := inv.kept e hek
      have hlt : e.2.1 < h.length := (List.getElem?_eq_some_iff.1 hpos).1
      have g := Grows.set h _ _ hpos
      have hother : ∀ x ∈ r.kept.eraseP (· = e), x.2.1 ≠ e.2.1 := by
        intro x hx hxe
        have hxk := List.mem_of_mem_eraseP hx
        have : x = e := List.inj_on_of_nodup_map inv.nodup hxk hek hxe
        subst this
        exact not_mem_eraseP_self (List.Nodup.of_map _ inv.nodup) hx
      refine ⟨by simpa using inv.len, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · intro x hx
        rw [List.getElem?_set_ne (Ne.symm (hother x hx))]
        exact inv.kept x (List.mem_of_mem_eraseP hx)
      · exact inv.nodup.sublist (List.eraseP_sublist.map _)
      · intro x hx b hb
        obtain ⟨p, hp, n⟩ := inv.keptBefore x (List.mem_of_mem_eraseP hx) b hb
        exact ⟨p, hp, n.grow g⟩
      · intro l b hl
        obtain ⟨hle, hb⟩ := inv.lost l b hl
        exact ⟨by simpa using hle, BeforeOK.grow g hb⟩
      · intro p c hp
        by_cases hpe : e.2.1 = p
        · subst hpe; simp [List.getElem?_set_self hlt] at hp
        · rw [List.getElem?_set_ne hpe] at hp
          rcases inv.covered p c hp with ⟨x, hx, hxp⟩ | hl
          · refine Or.inl ⟨x, ?_, hxp⟩
            have : x ≠ e := fun hxe => hpe (by rw [← hxe, hxp])
            exact (List.mem_eraseP_of_neg (by simpa using this)).2 hx
          · exact Or.inr hl
      · intro b hb
        obtain ⟨p, n⟩ := inv.last b hb
        exact ⟨p, n.grow g⟩
  | none =>
    simp only
    split_ifs with hskip
    · exact inv
    · rcases result with m | (_ | _) <;> cases next <;>
        first
        | exact inv.congr rfl rfl rfl rfl
        | exact forget_inv (advance_inv inv index _) window

/-! ## A walk keeps `Inv` -/

@[simp] theorem jump_passed (r : Reader) (t : Index) (skipped : List Index) (steps : Nat) :
    (r.jump t skipped steps).passed = r.passed + steps := by
  simp only [Reader.jump]; split_ifs <;> simp
@[simp] theorem jump_kept (r : Reader) (t : Index) (skipped : List Index) (steps : Nat) :
    (r.jump t skipped steps).kept = r.kept ++ r.stepped skipped (r.passed + steps - skipped.length) := by
  simp only [Reader.jump]; split_ifs <;> simp
@[simp] theorem jump_last (r : Reader) (t : Index) (skipped : List Index) (steps : Nat) :
    (r.jump t skipped steps).last = r.last := by
  simp only [Reader.jump]; split_ifs <;> simp
theorem jump_lost (r : Reader) (t : Index) (skipped : List Index) (steps : Nat) :
    (r.jump t skipped steps).lost =
      if r.passed < r.passed + steps - skipped.length then (r.lose r.passed r.last).lost else r.lost := by
  simp only [Reader.jump]; split_ifs <;> simp_all

/-- Each box a walk kept: its index, position and the box before it. -/
theorem mem_stepped {r : Reader} {skipped : List Index} {start : Nat} {x : Index × Nat × Option Index}
    (hx : x ∈ r.stepped skipped start) : ∃ k, ∃ hk : k < skipped.length,
      x = (skipped[k], start + k, if k = 0 then r.last else skipped[k - 1]?) := by
  simp only [Reader.stepped, List.mem_map, List.mem_zipIdx_iff_getElem?] at hx
  obtain ⟨⟨⟨i, b⟩, n⟩, hmem, rfl⟩ := hx
  simp only [List.getElem?_zip_eq_some] at hmem
  obtain ⟨hi, hb⟩ := hmem
  have hn : n < skipped.length := (List.getElem?_eq_some_iff.1 hi).1
  refine ⟨n, hn, ?_⟩
  rw [List.getElem?_eq_getElem hn] at hi
  cases hi
  cases n with
  | zero => simp at hb; simp [hb]
  | succ n =>
    simp only [List.getElem?_cons_succ, List.getElem?_map, Option.map_eq_some_iff] at hb
    obtain ⟨c, hc, rfl⟩ := hb
    simp [hc]

theorem stepped_mem {r : Reader} {skipped : List Index} {start k : Nat} (hk : k < skipped.length) :
    (skipped[k], start + k, if k = 0 then r.last else skipped[k - 1]?) ∈ r.stepped skipped start := by
  simp only [Reader.stepped, List.mem_map, List.mem_zipIdx_iff_getElem?]
  refine ⟨((skipped[k], if k = 0 then r.last else skipped[k - 1]?), k), ?_, rfl⟩
  simp only [List.getElem?_zip_eq_some]
  refine ⟨List.getElem?_eq_getElem hk, ?_⟩
  cases k with
  | zero => simp
  | succ j =>
    have hj : j < skipped.length := by omega
    simp only [List.getElem?_cons_succ, List.getElem?_map, Nat.add_sub_cancel, Nat.add_one_ne_zero,
      if_false, List.getElem?_eq_getElem hj, Option.map_some]

theorem stepped_positions (r : Reader) (skipped : List Index) (start : Nat) :
    (r.stepped skipped start).map (·.2.1) = (List.range skipped.length).map (start + ·) := by
  apply List.ext_getElem
  · simp [Reader.stepped]
  · intro n h1 h2
    simp [Reader.stepped, List.getElem_zipIdx]

/-- What a walk adds to the history: every box it stepped past, unread. -/
def walkedHistory (h : History) (all : List Index) : History := h ++ all.map (·, false)

theorem walked_grows (h : History) (all : List Index) : Grows h (walkedHistory h all) :=
  Grows.append _ _

/-- A jump keeps `Inv`. `all` is every box the walk stepped past, of which the driver handed back
the last `skipped`. -/
theorem jump_inv {r : Reader} {h : History} (inv : Inv r h) (target : Index) (all skipped : List Index)
    (hall : skipped = all.drop (all.length - skipped.length)) :
    Inv (r.jump target skipped all.length) (walkedHistory h all) := by
  have hsl : skipped.length ≤ all.length := by
    have := congrArg List.length hall; simp at this; omega
  have g := walked_grows h all
  set start := r.passed + all.length - skipped.length with hstart_def
  have hstart : r.passed ≤ start := by omega
  have hlenh : h.length = r.passed := inv.len
  have hpos : ∀ k (hk : k < skipped.length),
      (walkedHistory h all)[start + k]? = some (skipped[k], false) := by
    intro k hk
    unfold walkedHistory
    rw [List.getElem?_append_right (by omega)]
    have : start + k - h.length = (all.length - skipped.length) + k := by omega
    rw [this, List.getElem?_map]
    have hk' : (all.length - skipped.length) + k < all.length := by omega
    rw [List.getElem?_eq_getElem hk']
    have hsk : skipped[k] = all[(all.length - skipped.length) + k] := by
      rw [List.getElem_of_eq hall hk, List.getElem_drop]
    simp only [Option.map_some, hsk]
  have lastOK : ∀ b, r.last = some b → ∃ p < r.passed, Names (walkedHistory h all) b p := by
    intro b hb
    obtain ⟨p, n⟩ := inv.last b hb
    obtain ⟨y, hy⟩ := n
    have : p < h.length := (List.getElem?_eq_some_iff.1 hy).1
    exact ⟨p, by omega, Names.grow g ⟨y, hy⟩⟩
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simp [walkedHistory, inv.len]
  · intro x hx
    rw [jump_kept] at hx
    rcases List.mem_append.1 hx with hx | hx
    · have := inv.kept x hx
      unfold walkedHistory
      rw [List.getElem?_append_left (List.getElem?_eq_some_iff.1 this).1, this]
    · obtain ⟨k, hk, rfl⟩ := mem_stepped hx
      exact hpos k hk
  · rw [jump_kept, List.map_append, stepped_positions]
    refine List.nodup_append.2 ⟨inv.nodup, (List.nodup_range).map (fun a b h => by omega), ?_⟩
    intro a ha b hb hab
    obtain ⟨e, he, rfl⟩ := List.mem_map.1 ha
    obtain ⟨k, -, rfl⟩ := List.mem_map.1 hb
    have := (List.getElem?_eq_some_iff.1 (inv.kept e he)).1
    omega
  · intro x hx b hb
    rw [jump_kept] at hx
    rcases List.mem_append.1 hx with hx | hx
    · obtain ⟨p, hp, n⟩ := inv.keptBefore x hx b hb
      exact ⟨p, hp, n.grow g⟩
    · obtain ⟨k, hk, rfl⟩ := mem_stepped hx
      simp only at hb
      split_ifs at hb with hk0
      · obtain ⟨p, hp, n⟩ := lastOK b hb
        exact ⟨p, by simp only; omega, n⟩
      · have hk1 : k - 1 < skipped.length := by omega
        rw [List.getElem?_eq_getElem hk1] at hb
        cases hb
        exact ⟨start + (k - 1), by simp only; omega, ⟨false, hpos (k - 1) hk1⟩⟩
  · intro l b hl
    rw [jump_lost] at hl
    split_ifs at hl with hgt
    · have hok : LostOK (walkedHistory h all) r.lost := fun l b hl =>
        let ⟨hle, hb⟩ := inv.lost l b hl
        ⟨le_trans hle g.1, BeforeOK.grow g hb⟩
      exact lose_ok hok (by simp [walkedHistory, inv.len])
        (fun c hc => (lastOK c hc).imp fun p ⟨hp, n⟩ => ⟨hp, n⟩) l b hl
    · obtain ⟨hle, hb⟩ := inv.lost l b hl
      exact ⟨le_trans hle g.1, BeforeOK.grow g hb⟩
  · intro p c hp
    rw [jump_lost, jump_kept]
    by_cases hph : p < h.length
    · unfold walkedHistory at hp
      rw [List.getElem?_append_left hph] at hp
      rcases inv.covered p c hp with ⟨e, he, hep⟩ | ⟨l, b, hl, hlp⟩
      · exact Or.inl ⟨e, List.mem_append_left _ he, hep⟩
      · right
        split_ifs with hgt
        · obtain ⟨l', c', hlost, -, -, hmono⟩ := lose_lost r r.passed r.last
          exact ⟨l', c', hlost, le_trans (hmono l b hl) hlp⟩
        · exact ⟨l, b, hl, hlp⟩
    · by_cases hps : p < start
      · right
        have hgt : r.passed < start := by omega
        rw [if_pos hgt]
        obtain ⟨l', c', hlost, hle, -, -⟩ := lose_lost r r.passed r.last
        exact ⟨l', c', hlost, by omega⟩
      · left
        have hp' : p < h.length + all.length := by
          have := (List.getElem?_eq_some_iff.1 hp).1
          simpa [walkedHistory] using this
        have hk : p - start < skipped.length := by omega
        refine ⟨_, List.mem_append_right _ (stepped_mem (r := r) (start := start) hk), ?_⟩
        simp only; omega
  · intro b hb
    rw [jump_last] at hb
    obtain ⟨p, -, n⟩ := lastOK b hb
    exact ⟨p, n⟩

/-- A walk keeps `Inv`. -/
theorem walked_inv {r : Reader} {h : History} (inv : Inv r h) (target : Index) (all skipped : List Index)
    (hall : skipped = all.drop (all.length - skipped.length)) (window : Nat) :
    Inv (r.walked (some target) skipped all.length window).1 (walkedHistory h all) :=
  forget_inv (jump_inv inv target all skipped hall) window

theorem walked_none_inv {r : Reader} {h : History} (inv : Inv r h) (skipped : List Index) (steps window : Nat) :
    Inv (r.walked none skipped steps window).1 h := inv

end Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Member

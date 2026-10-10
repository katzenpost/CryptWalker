/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Order.Basic

/-! # Rosters: following another member's numbering

See "Rosters" in the group chat spec, and katzenqt's `groupchat/numbering.py` (`resolve`) and
`groupchat/group.py` (`_ingest`, `_started`), which this follows. Every roster index is announced
in the Numbers of a message: as the member it names, or as the `Introduction` that introduced it,
named by its introducer and its box. A box `B` is opaque: only compared for equality. A member's
roster began as its introducer's, up to the index the introducer gave it, and a watcher learns
which introducer from the member's `IntroducedAt`.

A watcher holds, for each roster, the entries it has read, the Introductions it knows and where
the roster began. The world holds each roster as its owner keeps it, and whom each Introduction
introduced.

* `resolve_sound`: whoever a watcher names at an index of a roster is whoever its owner put
  there, however many messages it missed, for any group size.
* `ingest_sound`, `introduce_sound`, `begin_sound`: reading a truthful message, learning an
  Introduction, and following an `IntroducedAt` each keep a watcher sound. So a watcher that
  skips boxes leaves indexes unresolved, never misplaced.
* `first_introduction_misplaces`: a watcher that takes the first Introduction of a member it
  reads as where its roster began, without `IntroducedAt`, misplaces a member introduced twice.
  This is the counterexample TLC finds in `tla/protocol/MC_GroupChat_NoIntroducedAt.cfg`. -/

namespace CryptWalker.GroupChat.Roster

/-- A roster entry as a watcher holds it. -/
inductive Val (M B : Type)
  | key (m : M)
  | intro (introducer : M) (box : B)
  | unknown
  deriving DecidableEq

structure Watcher (M B : Type) where
  entries : M → ℕ → Option (Val M B)
  introductions : M → B → Option M
  started : M → Option (M × ℕ)

structure World (M B : Type) where
  roster : M → ℕ → Option M
  introduced : M → B → Option M

variable {M B : Type}

/-- Who `x` numbered `k`, if the watcher can tell: from its own entry, else from the roster it
began as, through the index its introducer gave it. `fuel` bounds the chain of introducers. -/
def resolve (w : Watcher M B) : ℕ → M → ℕ → Option M
  | fuel, x, k =>
    match w.entries x k with
    | some (.key m) => some m
    | some (.intro i b) => w.introductions i b
    | some .unknown => none
    | none =>
      match fuel with
      | 0 => none
      | f + 1 =>
        match w.started x with
        | some (i, top) => if k ≤ top then resolve w f i k else none
        | none => none

/-- Everything the watcher holds is true of the world. -/
structure Sound (w : Watcher M B) (W : World M B) : Prop where
  key : ∀ x k m, w.entries x k = some (.key m) → W.roster x k = some m
  intro : ∀ x k i b n, w.entries x k = some (.intro i b) → W.introduced i b = some n →
    W.roster x k = some n
  introductions : ∀ i b n, w.introductions i b = some n → W.introduced i b = some n
  started : ∀ x i top, w.started x = some (i, top) → ∀ j ≤ top, W.roster x j = W.roster i j

theorem resolve_sound {w : Watcher M B} {W : World M B} (h : Sound w W) :
    ∀ fuel x k n, resolve w fuel x k = some n → W.roster x k = some n := by
  intro fuel
  induction fuel with
  | zero =>
    intro x k n hr
    unfold resolve at hr
    split at hr
    · cases hr; exact h.key _ _ _ ‹_›
    · exact h.intro _ _ _ _ _ ‹_› (h.introductions _ _ _ hr)
    · cases hr
    · cases hr
  | succ f ih =>
    intro x k n hr
    unfold resolve at hr
    split at hr
    · cases hr; exact h.key _ _ _ ‹_›
    · exact h.intro _ _ _ _ _ ‹_› (h.introductions _ _ _ hr)
    · cases hr
    · cases hs : w.started x with
      | none => simp [hs] at hr
      | some p =>
        obtain ⟨i, top⟩ := p
        simp only [hs] at hr
        split_ifs at hr with hk
        rw [h.started x i top hs k hk]
        exact ih i k n hr

/-! ## Reading keeps a watcher sound -/

/-- A Numbers entry: the `Introduction` the message itself carries, or one named by its
introducer's index in the sender's roster and its box. -/
inductive Ref (B : Type)
  | own
  | via (introducer : ℕ) (box : B)

/-- A message of `x`'s stream, as far as rosters are concerned. -/
structure Msg (M B : Type) where
  box : B
  numbers : List (ℕ × Ref B)
  intro : Option M

/-- What `x` says is true: each number names whom its Introduction introduced, and the message
introduces whom it says. -/
structure Truthful (W : World M B) (x : M) (msg : Msg M B) : Prop where
  own : ∀ k n, (k, Ref.own) ∈ msg.numbers → msg.intro = some n → W.roster x k = some n
  via : ∀ k idx b i n, (k, Ref.via idx b) ∈ msg.numbers → W.roster x idx = some i →
    W.introduced i b = some n → W.roster x k = some n
  introduced : W.introduced x msg.box = msg.intro

/-- The entry a watcher keeps for one Numbers entry of `x`'s message: the Introduction it names,
with its introducer resolved now, or nothing it can use. -/
def value (fuel : ℕ) (x : M) (msg : Msg M B) (w : Watcher M B) : Ref B → Val M B
  | .own => match msg.intro with
    | some _ => .intro x msg.box
    | none => .unknown
  | .via idx b => match resolve w fuel x idx with
    | some i => .intro i b
    | none => .unknown

/-- Take one Numbers entry of `x`'s message, keeping any entry already held. -/
def ingestOne [DecidableEq M] (fuel : ℕ) (x : M) (msg : Msg M B) (w : Watcher M B) :
    ℕ × Ref B → Watcher M B
  | (k, r) =>
    if (w.entries x k).isSome then w
    else { w with entries := fun y j => if y = x ∧ j = k then some (value fuel x msg w r)
                                        else w.entries y j }

def ingest [DecidableEq M] (fuel : ℕ) (x : M) (msg : Msg M B) (w : Watcher M B) : Watcher M B :=
  msg.numbers.foldl (ingestOne fuel x msg) w

theorem value_ne_key {fuel : ℕ} {x : M} {msg : Msg M B} {w : Watcher M B} {r : Ref B} {m : M} :
    value fuel x msg w r ≠ .key m := by
  cases r with
  | own => cases hi : msg.intro <;> simp [value, hi]
  | via idx b => cases hi : resolve w fuel x idx <;> simp [value, hi]

theorem value_sound {w : Watcher M B} {W : World M B} {fuel : ℕ} {x : M} {msg : Msg M B}
    (h : Sound w W) (ht : Truthful W x msg) {k : ℕ} {r : Ref B} (he : (k, r) ∈ msg.numbers)
    {i : M} {b : B} {n : M} (hv : value fuel x msg w r = .intro i b)
    (hn : W.introduced i b = some n) : W.roster x k = some n := by
  cases r with
  | own =>
    cases hi : msg.intro with
    | none => simp [value, hi] at hv
    | some n' =>
      simp only [value, hi, Val.intro.injEq] at hv
      obtain ⟨rfl, rfl⟩ := hv
      rw [ht.introduced, hi] at hn
      cases hn
      exact ht.own _ _ he hi
  | via idx b' =>
    cases hi : resolve w fuel x idx with
    | none => simp [value, hi] at hv
    | some i' =>
      simp only [value, hi, Val.intro.injEq] at hv
      obtain ⟨rfl, rfl⟩ := hv
      exact ht.via _ _ _ _ _ he (resolve_sound h _ _ _ _ hi) hn

theorem ingestOne_sound [DecidableEq M] {w : Watcher M B} {W : World M B} {fuel : ℕ} {x : M}
    {msg : Msg M B} (h : Sound w W) (ht : Truthful W x msg) {e : ℕ × Ref B}
    (he : e ∈ msg.numbers) : Sound (ingestOne fuel x msg w e) W := by
  obtain ⟨k, r⟩ := e
  dsimp only [ingestOne]
  split_ifs with hs
  · exact h
  refine ⟨?_, ?_, h.introductions, h.started⟩
  · intro y j m hy
    dsimp only at hy
    split_ifs at hy with hyj
    · exact absurd (Option.some.inj hy) value_ne_key
    · exact h.key _ _ _ hy
  · intro y j i b n hy hn
    dsimp only at hy
    split_ifs at hy with hyj
    · obtain ⟨rfl, rfl⟩ := hyj
      exact value_sound h ht he (Option.some.inj hy) hn
    · exact h.intro _ _ _ _ _ hy hn

theorem ingest_sound [DecidableEq M] {w : Watcher M B} {W : World M B} {fuel : ℕ} {x : M}
    {msg : Msg M B} (h : Sound w W) (ht : Truthful W x msg) : Sound (ingest fuel x msg w) W := by
  unfold ingest
  suffices hl : ∀ l : List (ℕ × Ref B), (∀ e ∈ l, e ∈ msg.numbers) →
      ∀ w : Watcher M B, Sound w W → Sound (l.foldl (ingestOne fuel x msg) w) W from
    hl _ (fun _ he => he) w h
  intro l
  induction l with
  | nil => intro _ w h; exact h
  | cons e es ih =>
    intro hl w h
    exact ih (fun e' he' => hl e' (List.mem_cons_of_mem _ he')) _
      (ingestOne_sound h ht (hl e List.mem_cons_self))

/-- Learn that the Introduction in `x`'s box introduced `n`. -/
def introduce [DecidableEq M] [DecidableEq B] (x : M) (box : B) (n : M) (w : Watcher M B) :
    Watcher M B :=
  { w with introductions := fun i b => if i = x ∧ b = box then some n else w.introductions i b }

theorem introduce_sound [DecidableEq M] [DecidableEq B] {w : Watcher M B} {W : World M B}
    {x : M} {box : B} {n : M} (h : Sound w W) (hi : W.introduced x box = some n) :
    Sound (introduce x box n w) W := by
  refine ⟨h.key, ?_, ?_, h.started⟩
  · exact h.intro
  · intro i b m hm
    dsimp only [introduce] at hm
    split_ifs at hm with hib
    · obtain ⟨rfl, rfl⟩ := hib; cases hm; exact hi
    · exact h.introductions _ _ _ hm

/-! ## Following an `IntroducedAt` keeps a watcher sound -/

/-- `x`'s roster began as `i`'s, through the index `i` gave it. -/
def JoinedThrough (W : World M B) (x i : M) : Prop :=
  ∃ k₀, W.roster i k₀ = some x ∧ (∀ k, W.roster i k = some x → k = k₀) ∧
    ∀ j ≤ k₀, W.roster x j = W.roster i j

/-- `x` says it joined through the Introduction in box `b`: its roster began as that
introducer's, through the index the watcher finds `x` at in that introducer's roster. -/
def begin [DecidableEq M] (x i : M) (top : ℕ) (w : Watcher M B) : Watcher M B :=
  { w with started := fun y => if y = x then some (i, top) else w.started y }

theorem begin_sound [DecidableEq M] {w : Watcher M B} {W : World M B} {fuel : ℕ} {x i : M}
    {b : B} {top : ℕ} (h : Sound w W) (hb : w.introductions i b = some x)
    (hat : ∀ i', W.introduced i' b = some x → JoinedThrough W x i')
    (htop : resolve w fuel i top = some x) : Sound (begin x i top w) W := by
  refine ⟨h.key, h.intro, h.introductions, ?_⟩
  intro y i' t hy j hj
  dsimp only [begin] at hy
  split_ifs at hy with hyx
  · cases hy
    subst hyx
    obtain ⟨k₀, -, huniq, hpre⟩ := hat i (h.introductions _ _ _ hb)
    have := huniq _ (resolve_sound h _ _ _ _ htop)
    subst this
    exact hpre j hj
  · exact h.started _ _ _ hy j hj

/-! ## Without `IntroducedAt`, a member introduced twice is misplaced -/

/-- Founders `0` and `1`. `0` introduces `2`, and `1` introduces `3`, who joins through `1`. `0`
then introduces `3` again, in its box `1`, and numbers it `3`. -/
def exWorld : World (Fin 4) (Fin 2) where
  roster
    | 0, k => [some 0, some 1, some 2, some 3][k]?.join
    | 1, k => [some 0, some 1, some 3][k]?.join
    | 3, k => [some 0, some 1, some 3][k]?.join
    | _, _ => none
  introduced
    | 0, 0 => some 2
    | 0, 1 => some 3
    | 1, 0 => some 3
    | _, _ => none

/-- A watcher that read `0`'s roster and its second Introduction of `3` first, and took that as
where `3`'s roster began. -/
def exWatcher : Watcher (Fin 4) (Fin 2) where
  entries
    | 0, k => if h : k < 4 then some (.key ⟨k, h⟩) else none
    | _, _ => none
  introductions
    | 0, 1 => some 3
    | _, _ => none
  started
    | 3 => some (0, 3)
    | _ => none

theorem first_introduction_misplaces :
    resolve exWatcher 4 3 2 = some 2 ∧ exWorld.roster 3 2 = some 3 := by
  decide

end CryptWalker.GroupChat.Roster

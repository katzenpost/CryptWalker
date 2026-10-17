/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Order.Basic
import Mathlib.Logic.Function.Basic

/-! # Rosters: following another member's numbering

Every roster index is announced in a message's `Numbers`, by key prefix or as the member its own
`Introduction` introduces. A member's roster begins as its introducer's, which a watcher learns
from `IntroducedAt`. If no two members share a prefix, a watcher that misses messages leaves
indexes unresolved but never misplaced. See "Rosters" in the group chat spec. -/

namespace Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Roster

/-- A roster entry as a watcher holds it. -/
inductive Val (M P : Type)
  | key (m : M)
  | named (p : P)
  | unknown
  deriving DecidableEq

structure Watcher (M B P : Type) where
  entries : M → ℕ → Option (Val M P)
  introductions : M → B → Option M
  started : M → Option (M × ℕ)
  /-- The member known by a prefix. -/
  known : P → Option M

structure World (M B : Type) where
  roster : M → ℕ → Option M
  introduced : M → B → Option M

variable {M B P : Type}

/-- Who `x` numbered `k`, if the watcher can tell: from its own entry, else from the roster it
began as, through the index its introducer gave it. `fuel` bounds the chain of introducers. -/
def resolve (w : Watcher M B P) : ℕ → M → ℕ → Option M
  | fuel, x, k =>
    match w.entries x k with
    | some (.key m) => some m
    | some (.named p) => w.known p
    | some .unknown => none
    | none =>
      match fuel with
      | 0 => none
      | f + 1 =>
        match w.started x with
        | some (i, top) => if k ≤ top then resolve w f i k else none
        | none => none

/-- Everything the watcher holds is true of the world, where `pre` gives a member's prefix. -/
structure Sound (pre : M → P) (w : Watcher M B P) (W : World M B) : Prop where
  key : ∀ x k m, w.entries x k = some (.key m) → W.roster x k = some m
  named : ∀ x k p, w.entries x k = some (.named p) → ∃ n, W.roster x k = some n ∧ pre n = p
  known : ∀ p n, w.known p = some n → pre n = p
  introductions : ∀ i b n, w.introductions i b = some n → W.introduced i b = some n
  started : ∀ x i top, w.started x = some (i, top) → ∀ j ≤ top, W.roster x j = W.roster i j

theorem resolve_sound {pre : M → P} (hpre : Function.Injective pre) {w : Watcher M B P}
    {W : World M B} (h : Sound pre w W) :
    ∀ fuel x k n, resolve w fuel x k = some n → W.roster x k = some n := by
  have named : ∀ x k n p, w.entries x k = some (.named p) → w.known p = some n →
      W.roster x k = some n := by
    intro x k n p hv hr
    obtain ⟨n0, hn0, hp0⟩ := h.named _ _ _ hv
    rw [hpre ((h.known _ _ hr).trans hp0.symm)]
    exact hn0
  intro fuel
  induction fuel with
  | zero =>
    intro x k n hr
    unfold resolve at hr
    split at hr
    · next m hm => cases hr; exact h.key _ _ _ hm
    · next p hp => exact named x k n p hp hr
    · cases hr
    · cases hr
  | succ f ih =>
    intro x k n hr
    unfold resolve at hr
    split at hr
    · next m hm => cases hr; exact h.key _ _ _ hm
    · next p hp => exact named x k n p hp hr
    · cases hr
    · cases hs : w.started x with
      | none => simp [hs] at hr
      | some q =>
        obtain ⟨i, top⟩ := q
        simp only [hs] at hr
        split_ifs at hr with hk
        rw [h.started x i top hs k hk]
        exact ih i k n hr

/-! ## Reading keeps a watcher sound -/

/-- A message of `x`'s stream, as far as rosters are concerned: each number with the prefix of
the member assigned it, or `none` for the member the message's own Introduction introduces. -/
structure Msg (M B P : Type) where
  box : B
  numbers : List (ℕ × Option P)
  intro : Option M

/-- What `x` says is true: each number names a member `x` put there, and the message introduces
whom it says. -/
structure Truthful (pre : M → P) (W : World M B) (x : M) (msg : Msg M B P) : Prop where
  own : ∀ k n, (k, none) ∈ msg.numbers → msg.intro = some n → W.roster x k = some n
  named : ∀ k p, (k, some p) ∈ msg.numbers → ∃ n, W.roster x k = some n ∧ pre n = p
  introduced : W.introduced x msg.box = msg.intro

/-- The entry a watcher keeps for one Numbers entry of `x`'s message. -/
def value (msg : Msg M B P) : Option P → Val M P
  | some p => .named p
  | none => match msg.intro with
    | some n => .key n
    | none => .unknown

/-- Take one Numbers entry of `x`'s message, keeping any entry already held. -/
def ingestOne [DecidableEq M] (x : M) (msg : Msg M B P) (w : Watcher M B P) :
    ℕ × Option P → Watcher M B P
  | (k, r) =>
    if (w.entries x k).isSome then w
    else { w with entries := fun y j => if y = x ∧ j = k then some (value msg r) else w.entries y j }

def ingest [DecidableEq M] (x : M) (msg : Msg M B P) (w : Watcher M B P) : Watcher M B P :=
  msg.numbers.foldl (ingestOne x msg) w

theorem ingestOne_sound [DecidableEq M] {pre : M → P} {w : Watcher M B P} {W : World M B} {x : M}
    {msg : Msg M B P} (h : Sound pre w W) (ht : Truthful pre W x msg) {e : ℕ × Option P}
    (he : e ∈ msg.numbers) : Sound pre (ingestOne x msg w e) W := by
  obtain ⟨k, r⟩ := e
  dsimp only [ingestOne]
  split_ifs with hs
  · exact h
  refine ⟨?_, ?_, h.known, h.introductions, h.started⟩
  · intro y j m hy
    dsimp only at hy
    split_ifs at hy with hyj
    · obtain ⟨rfl, rfl⟩ := hyj
      cases r with
      | some p => simp [value] at hy
      | none =>
        cases hi : msg.intro with
        | none => simp [value, hi] at hy
        | some n =>
          simp only [value, hi, Option.some.injEq, Val.key.injEq] at hy
          subst hy
          exact ht.own _ _ he hi
    · exact h.key _ _ _ hy
  · intro y j p hy
    dsimp only at hy
    split_ifs at hy with hyj
    · obtain ⟨rfl, rfl⟩ := hyj
      cases r with
      | some q =>
        simp only [value, Option.some.injEq, Val.named.injEq] at hy
        subst hy
        exact ht.named _ _ he
      | none => cases hi : msg.intro <;> simp [value, hi] at hy
    · exact h.named _ _ _ hy

theorem ingest_sound [DecidableEq M] {pre : M → P} {w : Watcher M B P} {W : World M B} {x : M}
    {msg : Msg M B P} (h : Sound pre w W) (ht : Truthful pre W x msg) :
    Sound pre (ingest x msg w) W := by
  unfold ingest
  suffices hl : ∀ l : List (ℕ × Option P), (∀ e ∈ l, e ∈ msg.numbers) →
      ∀ w : Watcher M B P, Sound pre w W → Sound pre (l.foldl (ingestOne x msg) w) W from
    hl _ (fun _ he => he) w h
  intro l
  induction l with
  | nil => intro _ w h; exact h
  | cons e es ih =>
    intro hl w h
    exact ih (fun e' he' => hl e' (List.mem_cons_of_mem _ he')) _
      (ingestOne_sound h ht (hl e List.mem_cons_self))

/-- Learn that the Introduction in `x`'s box introduced `n`, and so learn `n`'s key. -/
def introduce [DecidableEq M] [DecidableEq B] [DecidableEq P] (pre : M → P) (x : M) (box : B)
    (n : M) (w : Watcher M B P) : Watcher M B P :=
  { w with introductions := fun i b => if i = x ∧ b = box then some n else w.introductions i b
           known := fun p => if p = pre n then some n else w.known p }

theorem introduce_sound [DecidableEq M] [DecidableEq B] [DecidableEq P] {pre : M → P}
    {w : Watcher M B P} {W : World M B} {x : M} {box : B} {n : M} (h : Sound pre w W)
    (hi : W.introduced x box = some n) : Sound pre (introduce pre x box n w) W := by
  refine ⟨h.key, h.named, ?_, ?_, h.started⟩
  · intro p m hm
    dsimp only [introduce] at hm
    split_ifs at hm with hp
    · cases hm; exact hp.symm
    · exact h.known _ _ hm
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
def begin [DecidableEq M] (x i : M) (top : ℕ) (w : Watcher M B P) : Watcher M B P :=
  { w with started := fun y => if y = x then some (i, top) else w.started y }

theorem begin_sound [DecidableEq M] {pre : M → P} (hpre : Function.Injective pre)
    {w : Watcher M B P} {W : World M B} {fuel : ℕ} {x i : M}
    {b : B} {top : ℕ} (h : Sound pre w W) (hb : w.introductions i b = some x)
    (hat : ∀ i', W.introduced i' b = some x → JoinedThrough W x i')
    (htop : resolve w fuel i top = some x) : Sound pre (begin x i top w) W := by
  refine ⟨h.key, h.named, h.known, h.introductions, ?_⟩
  intro y i' t hy j hj
  dsimp only [begin] at hy
  split_ifs at hy with hyx
  · cases hy
    subst hyx
    obtain ⟨k₀, -, huniq, hpre'⟩ := hat i (h.introductions _ _ _ hb)
    have := huniq _ (resolve_sound hpre h _ _ _ _ htop)
    subst this
    exact hpre' j hj
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
def exWatcher : Watcher (Fin 4) (Fin 2) (Fin 4) where
  entries
    | 0, k => if h : k < 4 then some (.key ⟨k, h⟩) else none
    | _, _ => none
  introductions
    | 0, 1 => some 3
    | _, _ => none
  started
    | 3 => some (0, 3)
    | _ => none
  known := some

theorem first_introduction_misplaces :
    resolve exWatcher 4 3 2 = some 2 ∧ exWorld.roster 3 2 = some 3 := by
  decide

end Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.Roster

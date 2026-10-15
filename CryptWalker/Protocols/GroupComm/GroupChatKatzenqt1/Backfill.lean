/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Tactic.Ring

/-! # Backfill against epoch-keyed replica storage

A stream owner rewrites every box once per replica epoch so every position stays populated. See
"Backfill" in the group chat spec. A replica keeps the current and previous epochs; a data write
matching what is stored stores nothing, so a rewrite does not move a box into the current epoch. -/

namespace CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Backfill

inductive Kind | data | tomb
  deriving DecidableEq

/-- One box at one replica: what is stored, by the epoch it was stored in. At most one entry per
epoch; storing again in the same epoch replaces it. -/
abbrev Box := List (ℕ × Kind)

/-- The epochs a replica keeps at epoch `now`: `now` and the one before. -/
def kept (now e : ℕ) : Bool := e = now || e + 1 = now

/-- What a read at epoch `now` returns: the newest kept entry, if any. -/
def look (now : ℕ) (b : Box) : Option Kind :=
  match b.find? (fun x => x.1 = now) with
  | some x => some x.2
  | none => (b.find? (fun x => x.1 + 1 = now)).map (·.2)

def put (now : ℕ) (k : Kind) (b : Box) : Box := (now, k) :: b.filter (fun x => x.1 ≠ now)

/-- A write of kind `k` at epoch `now`. With `refresh`, a matching data write is stored again. -/
def write (refresh : Bool) (now : ℕ) (k : Kind) (b : Box) : Box :=
  match k with
  | .tomb => put now .tomb b
  | .data =>
    match look now b with
    | none => put now .data b
    | some .data => if refresh then put now .data b else b
    | some .tomb => b

/-- Nothing stored in an epoch that has not begun. -/
def Settled (now : ℕ) (b : Box) : Prop := ∀ x ∈ b, x.1 ≤ now

theorem look_put_now (now : ℕ) (k : Kind) (b : Box) : look now (put now k b) = some k := by
  simp [look, put]

/-- An entry stored at `now` is what a read in the next epoch returns, if nothing is newer. -/
theorem look_put_next {now : ℕ} {k : Kind} {b : Box} (hb : Settled now b) :
    look (now + 1) (put now k b) = some k := by
  have hnone : (put now k b).find? (fun x => x.1 = now + 1) = none := by
    rw [List.find?_eq_none]
    intro x hx
    simp only [put, List.mem_cons, List.mem_filter] at hx
    rcases hx with rfl | ⟨hx, -⟩
    · simp
    · have := hb x hx; simp; omega
  simp only [look]; rw [hnone]; simp [put]

/-! ## As deployed, a rewrite does not keep a box -/

/-- Without refresh, a box written in epoch `e` and rewritten in `e + 1` is gone in `e + 2`. -/
theorem deployed_rewrite_lost (e : ℕ) :
    let first := write false e .data []
    let rewritten := write false (e + 1) .data first
    look (e + 1) first = some .data ∧ rewritten = first ∧ look (e + 2) rewritten = none := by
  simp [write, look, put]

/-! ## Storing a matching write again would keep it -/

/-- With refresh, a data rewrite in epoch `now` is readable through `now + 1`, from any settled
state not holding a tombstone. -/
theorem refresh_rewrite_kept {now : ℕ} {b : Box} (hb : Settled now b)
    (hnt : look now b ≠ some .tomb) :
    look now (write true now .data b) = some .data ∧
      look (now + 1) (write true now .data b) = some .data := by
  have hput : write true now .data b = put now .data b := by
    unfold write
    cases h : look now b with
    | none => rfl
    | some k => cases k with
      | data => rfl
      | tomb => exact absurd h hnt
  rw [hput]
  exact ⟨look_put_now _ _ _, look_put_next hb⟩

/-- Without refresh, rewriting a readable data box changes nothing. -/
theorem deployed_rewrite_noop {now : ℕ} {b : Box} (h : look now b = some .data) :
    write false now .data b = b := by
  simp [write, h]

/-! ## Tombstones -/

/-- A tombstone is stored at the current epoch and read through the next. -/
theorem tomb_kept (refresh : Bool) {now : ℕ} {b : Box} (hb : Settled now b) :
    look now (write refresh now .tomb b) = some .tomb ∧
      look (now + 1) (write refresh now .tomb b) = some .tomb :=
  ⟨look_put_now _ _ _, look_put_next hb⟩

end CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Backfill

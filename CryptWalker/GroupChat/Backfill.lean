/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Tactic.Ring

/-! # Backfill against the replica's epoch-keyed storage

See "Backfill" and "Rewrite and scan" in the group chat spec. A stream owner rewrites every box it
still holds once per replica epoch, "so every position stays populated, however long since a
reader last looked". This file models one box at one replica as `katzenpost/replica/state.go`
stores it, and asks whether that holds.

The replica keys a stored box by the replica epoch in which it was stored, keeps the current and
previous epochs, and reads and writes consult those newest first. A data write that matches what is
stored succeeds without storing anything (`handleReplicaWrite`); a tombstone is always stored at
the current epoch (`handleReplicaTombstone`). So a rewrite of a box that is still there does not
move it to the current epoch.

* `deployed_rewrite_lost`: a box written in epoch `e` and rewritten in `e + 1` cannot be read in
  `e + 2`, for every `e`.
* `refresh_rewrite_kept`: if a matching write were stored again at the current epoch, a box
  rewritten in epoch `e` could be read through `e + 1`, whatever it held before.
* `tomb_kept`: a tombstone is stored at the current epoch either way, and shadows older data.

The `Retention`, scan and acknowledgement questions are in `tla/Backfill.tla`. -/

namespace CryptWalker.GroupChat.Backfill

inductive Kind | data | tomb
  deriving DecidableEq

/-- One box at one replica: what is stored, by the epoch it was stored in. At most one entry per
epoch; storing again in the same epoch replaces it. -/
abbrev Box := List (ℕ × Kind)

/-- The epochs a replica keeps at epoch `now`: `now` and the one before. -/
def kept (now e : ℕ) : Bool := e = now || e + 1 = now

/-- What a read at epoch `now` returns: the newest kept entry, if any (`BoxIDNotFound` otherwise). -/
def look (now : ℕ) (b : Box) : Option Kind :=
  match b.find? (fun x => x.1 = now) with
  | some x => some x.2
  | none => (b.find? (fun x => x.1 + 1 = now)).map (·.2)

def put (now : ℕ) (k : Kind) (b : Box) : Box := (now, k) :: b.filter (fun x => x.1 ≠ now)

/-- The replica's handling of a write of kind `k` at epoch `now`. `refresh` stores a matching data
write again, which `state.go` does not. -/
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

/-- **A box written in epoch `e` and rewritten in `e + 1` is gone in `e + 2`.** The rewrite
matched what was stored, so nothing was stored at `e + 1`, and the entry from `e` is outside the
kept window. This is the counterexample TLC finds in `tla/MC_Backfill_Deployed.cfg`, for every
epoch rather than the first few. -/
theorem deployed_rewrite_lost (e : ℕ) :
    let first := write false e .data []
    let rewritten := write false (e + 1) .data first
    look (e + 1) first = some .data ∧ rewritten = first ∧ look (e + 2) rewritten = none := by
  simp [write, look, put]

/-! ## Storing a matching write again would keep it -/

/-- **With a refreshing replica, a data rewrite in epoch `e` can be read through `e + 1`**, from
any settled state not holding a tombstone. -/
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

/-- As deployed, the same rewrite of a box stored in the previous epoch leaves it where it was. -/
theorem deployed_rewrite_noop {now : ℕ} {b : Box} (h : look now b = some .data) :
    write false now .data b = b := by
  simp [write, h]

/-! ## Tombstones -/

/-- **A tombstone is stored at the current epoch** under either replica, so it is read through the
next epoch and shadows any older data. -/
theorem tomb_kept (refresh : Bool) {now : ℕ} {b : Box} (hb : Settled now b) :
    look now (write refresh now .tomb b) = some .tomb ∧
      look (now + 1) (write refresh now .tomb b) = some .tomb :=
  ⟨look_put_now _ _ _, look_put_next hb⟩

end CryptWalker.GroupChat.Backfill

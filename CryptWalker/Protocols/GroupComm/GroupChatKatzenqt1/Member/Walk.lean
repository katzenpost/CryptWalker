/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member.Wire

/-! # Walking a stream to an acknowledged box

What a client does for `Effect.walk` and `Effect.deriveIndexes`, given how to step from one box's
index to the next: by BACAP itself, or by asking the client daemon. -/

namespace CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member

/-- How far ahead a walk reaches. -/
def walkLimit : Nat := 256

/-- The box at the furthest of `targets` fewer than `walkLimit` boxes ahead of `start`, the last
`keep` indexes before it (all for `keep = 0`), and the step count: the answer to
`Effect.walk`. -/
def walkWith {m : Type → Type} [Monad m] (next : Index → m Index) (start : Index)
    (targets : List Nat) (keep : Nat) : m (Option Index × List Index × Nat) := do
  let here := counter start
  match (targets.filter fun t => here ≤ t && t < here + walkLimit).max? with
  | none => pure (none, [], 0)
  | some target =>
    let first := if keep = 0 then here else max here (target - keep)
    let mut index := start
    for _ in [here:first] do
      index ← next index
    let mut skipped : Array Index := #[]
    for _ in [first:target] do
      skipped := skipped.push index
      index ← next index
    pure (some index, skipped.toList, target - here)

/-- `count` indexes after `start`: the answer to `Effect.deriveIndexes`. -/
def deriveWith {m : Type → Type} [Monad m] (next : Index → m Index) (start : Index) :
    Nat → m (List Index)
  | 0 => pure []
  | n + 1 => do
    let i ← next start
    pure (i :: (← deriveWith next i n))

end CryptWalker.Protocols.GroupComm.GroupChatKatzenqt1.Member

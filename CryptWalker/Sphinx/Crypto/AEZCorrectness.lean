/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Crypto.AEZ
import Mathlib.Logic.Function.Iterate

namespace CryptWalker.Sphinx.Crypto.AEZ

/-! # Connecting `aezTinyLR`'s real loop to the abstract ladder

`AEZ.lean`'s `ladderFwdN`/`ladderBwdN`/`ladderBwdN_ladderFwdN_swap` model `aezTinyLR`'s
`for _ in [0:rounds/2] do ...` loop as a plain recursion on the iteration count, with the running
counter *derived* from that count (`2k`/`2k+1` ascending, or `2n-1-2k` descending). The real code
instead threads the counter as mutable `Int` state (`j`, advanced by `2*step` each iteration) — this
file is the (separate, purely bookkeeping — no new algebra) lemma connecting the two
representations, split into its own file per the project's usual practice of keeping generic
reusable lemmas apart from the code they'll eventually be applied to, and because `AEZ.lean` is
large enough already that every edit to it costs a full ~3-minute re-elaboration.

Not yet done: instantiating `G` to `aezTinyLR`'s actual `buf`-then-`aes4` computation (needs a
`mkBuf` matching buf1/buf2's `.set!` sequence, plus a small lemma that the real code's doubly
`%256`-normalized counter byte agrees with `G`'s), the pre-loop `d ≠ 0` tweak, the initial
`(L, R)` extraction from `inArr`, and `aezTiny`'s outer merge/demerge (with its odd-length
nibble-packing) — each of those is its own, separate remaining piece. -/

section
variable (G : Int → Block → Block)

/-- `aezTinyLR`'s `d = 0` loop body, abstracted over the round function: update `L` from `R`
under the running counter `j`, then `R` from the new `L` under `j + 1`, then advance `j` by `2`
(`step = 1`). -/
def realFwdStep (LR : Block × Block × Int) : Block × Block × Int :=
  let L := LR.1
  let R := LR.2.1
  let j := LR.2.2
  let L' := xor16 L (G j R)
  let R' := xor16 R (G (j + 1) L')
  (L', R', j + 2)

/-- The `d ≠ 0` loop body: same shape, but the second application uses `j - 1` and `j` advances
by `-2` (`step = -1`). -/
def realBwdStep (LR : Block × Block × Int) : Block × Block × Int :=
  let L := LR.1
  let R := LR.2.1
  let j := LR.2.2
  let L' := xor16 L (G j R)
  let R' := xor16 R (G (j - 1) L')
  (L', R', j - 2)

private def FofG (k : Nat) : Block → Block := G (k : Int)

/-- Running `aezTinyLR`'s `d = 0` loop body `n` times from counter `0` is exactly `n` iterations
of the abstract forward ladder (`ladderFwdN`), for the matching round function `G`. -/
theorem realFwdStep_iterate_eq (n : Nat) (L0 R0 : Block) :
    (realFwdStep G)^[n] (L0, R0, 0)
      = ((ladderFwdN (FofG G) n (L0, R0)).1, (ladderFwdN (FofG G) n (L0, R0)).2, (2 * n : Int)) := by
  induction n with
  | zero => rfl
  | succ n ih =>
    rw [Function.iterate_succ_apply', ih]
    show realFwdStep G ((ladderFwdN (FofG G) n (L0, R0)).1, (ladderFwdN (FofG G) n (L0, R0)).2,
        (2 * n : Int))
      = ((ladderFwdN (FofG G) (n + 1) (L0, R0)).1, (ladderFwdN (FofG G) (n + 1) (L0, R0)).2,
        (2 * (n + 1) : Int))
    have h1 : ((2 * n : Nat) : Int) = 2 * (n : Int) := by omega
    have h2 : ((2 * n + 1 : Nat) : Int) = 2 * (n : Int) + 1 := by omega
    have h3 : (2 * (n : Int)) + 2 = 2 * ((n : Int) + 1) := by omega
    simp only [realFwdStep, ladderFwdN, ladderFwdStep, FofG, h1, h2, h3]

/-- Running `aezTinyLR`'s `d ≠ 0` loop body `n` times from counter `2n - 1` is exactly `n`
iterations of the abstract backward ladder (`ladderBwdN`). -/
theorem realBwdStep_iterate_eq (n : Nat) (L0 R0 : Block) (s0 : Int) (hs0 : s0 = 2 * (n : Int) - 1) :
    (realBwdStep G)^[n] (L0, R0, s0)
      = ((ladderBwdN (FofG G) n (L0, R0)).1, (ladderBwdN (FofG G) n (L0, R0)).2, s0 - 2 * n) := by
  induction n generalizing L0 R0 s0 with
  | zero => simp [ladderBwdN]
  | succ n ih =>
    rw [Function.iterate_succ_apply]
    have e1 : ((2 * n + 1 : Nat) : Int) = s0 := by omega
    have ihn := ih (xor16 L0 (G s0 R0)) (xor16 R0 (G (s0 - 1) (xor16 L0 (G s0 R0)))) (s0 - 2)
      (by omega)
    show (realBwdStep G)^[n] (xor16 L0 (G s0 R0), xor16 R0 (G (s0 - 1) (xor16 L0 (G s0 R0))), s0 - 2)
      = ((ladderBwdN (FofG G) (n + 1) (L0, R0)).1, (ladderBwdN (FofG G) (n + 1) (L0, R0)).2,
        s0 - 2 * (n + 1))
    rw [ihn]
    have e2 : (2 * n + 1 - 1 : Nat) = 2 * n := by omega
    have e3 : s0 - 1 = ((2 * n : Nat) : Int) := by omega
    simp only [ladderBwdN, ladderBwdStep, FofG, e1, e2, e3, Prod.mk.injEq]
    exact ⟨trivial, trivial, by omega⟩

end

end CryptWalker.Sphinx.Crypto.AEZ

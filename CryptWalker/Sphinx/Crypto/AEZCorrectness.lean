/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Crypto.AEZ
import Mathlib.Logic.Function.Iterate
import Mathlib.Tactic.Set
import Std.Tactic.BVDecide

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

/-- Like `List.foldl_const`, but allowing the step function to actually use its second argument,
provided it always agrees with a fixed `g` on every element of `l` — this is what lets a later
proof match `f`/`g` pointwise (at a *generic*, freshly-introduced point) instead of needing to
prove `f = fun a _ => g a` as a whole-function fact, which for this file's `f` (`aezTinyLR`'s
already-unfolded loop body) is large enough that a direct `show`/defeq check of the whole iterated
expression times out — matching one *application* at a time avoids ever comparing more than one
copy of that body. -/
private theorem List.foldl_eq_iterate_of_forall {α β} (l : List β) (f : α → β → α) (g : α → α)
    (h : ∀ a b, b ∈ l → f a b = g a) (init : α) :
    l.foldl f init = g^[l.length] init := by
  induction l generalizing init with
  | nil => rfl
  | cons hd tl ih =>
    rw [List.foldl_cons, h init hd (List.mem_cons_self ..), List.length_cons,
      Function.iterate_succ_apply]
    exact ih (fun a b hb => h a b (List.mem_cons_of_mem hd hb)) (g init)

/-- `List.foldl_eq_iterate_of_forall`, specialized to produce the `(·.1, ·.2.1)`-projected pair
`aezTinyLR`'s own `Id.run do ... return (L, R)` actually needs — stated this way (rather than
projecting the plain version's conclusion afterward with `congrArg`/`Prod.ext`) so that using it
via `refine (... ?_ _).trans ?_` unifies directly against a goal already in this projected shape,
the same way the plain version does against an unprojected one: wrapping the *already proven*
fact in an extra projection here is instant, whereas asking the *elaborator* to bridge the two
shapes at the call site (via `congrArg`/`Prod.ext`) reliably timed out, confirmed for several
different phrasings of that bridge. -/
private theorem List.foldl_eq_iterate_of_forall_pair {β} (l : List β)
    (f : Block × Block × Int → β → Block × Block × Int) (g : Block × Block × Int → Block × Block × Int)
    (h : ∀ a b, b ∈ l → f a b = g a) (init : Block × Block × Int) :
    ((l.foldl f init).1, (l.foldl f init).2.1) = ((g^[l.length] init).1, (g^[l.length] init).2.1) := by
  rw [List.foldl_eq_iterate_of_forall l f g h init]

/-- Two functions that agree everywhere produce the same iterate. -/
private theorem Function.iterate_congr_of_forall {α} (f g : α → α) (h : ∀ a, f a = g a) :
    ∀ (n : Nat) (init : α), f^[n] init = g^[n] init
  | 0, _ => rfl
  | n + 1, init => by
      show f^[n] (f init) = g^[n] (g init)
      rw [h init]
      exact Function.iterate_congr_of_forall f g h n (g init)

/-! ## Instantiating the round function to `aezTinyLR`'s actual computation

`mkBuf` (`aezTinyLR`'s `buf1`/`buf2` construction, factored out under its own name) now lives in
`AEZ.lean` itself — `aezTinyLR`'s own source calls it directly, rather than inlining buf1/buf2's
construction twice, which is what made the whole-loop theorem below tractable at all. -/

/-- `aezTinyLR`'s `buf2` construction XORs in a doubly-`% 256`-renormalized counter byte
(matching the reference Go, whose `%` can return negative for a negative dividend); Lean's `Int`
`%` (`Int.emod`) already returns a value in `[0, 256)` for any dividend and a positive modulus, so
the renormalization is a no-op here. -/
theorem mod256_renorm (j : Int) : (j % 256 + 256) % 256 = j % 256 := by omega

/-- One call to the round function: whiten-then-`aes4`, for the counter byte derived from `j`
(`e`, `delta`, `half`, `ih2`, `i0`, `mask`, `pad` are all fixed for the whole `aezTinyLR` call). -/
def G_real (e : EState) (delta : Block) (half ih2 i0 : Nat) (mask pad : UInt8) (j : Int)
    (X : Block) : Block :=
  aes4 e zero16 e.I1 (e.L[i0]!) (mkBuf half ih2 mask pad delta X (UInt8.ofNat (j % 256).toNat))

/-- `aezTinyLR`'s prefix (everything before the main loop): extract `L`/`R` from `inArr`'s bytes,
and — for an odd-length input — nibble-shift `R` and switch `mask`/`pad` to the odd-length values.
Literally the same code as `aezTinyLR`'s own lines building `L`, `R`, `mask`, `pad`. -/
def initLR (inArr : ByteArray) : Block × Block × UInt8 × UInt8 := Id.run do
  let inBytes := inArr.size
  let half := (inBytes + 1) / 2
  let mut L : Block := zero16
  let mut R : Block := zero16
  for k in [0:half] do
    L := L.set! k (inArr.get! k)
  for k in [0:half] do
    R := R.set! k (inArr.get! (inBytes / 2 + k))
  let mut mask : UInt8 := 0x00
  let mut pad : UInt8 := 0x80
  if inBytes % 2 == 1 then
    let origR := R
    for k in [0:inBytes / 2] do
      R := R.set! k ((origR[k]! <<< 4) ||| (origR[k+1]! >>> 4))
    R := R.set! (inBytes / 2) (origR[inBytes / 2]! <<< 4)
    pad := 0x08
    mask := 0xf0
  return (L, R, mask, pad)

/-- One iteration of `aezTinyLR`'s main loop body, as a function of the threaded `(L, R, j)`
state — literally the same code as lines computing `buf1`/`tmp1`/`L := ...`/`buf2`/`tmp2`/
`R := ...`/`j := j + 2*step`, with `step` left as a parameter (the real code fixes it to `1` or
`-1` depending on `d`, but never uses any other value). -/
def loopBodyStep (e : EState) (delta : Block) (half ih2 i0 : Nat) (mask pad : UInt8) (step : Int)
    (LRj : Block × Block × Int) : Block × Block × Int :=
  let L := LRj.1
  let R := LRj.2.1
  let j := LRj.2.2
  Id.run do
    let mut buf1 : Block := zero16
    for k in [0:half] do buf1 := buf1.set! k (R[k]!)
    buf1 := buf1.set! ih2 ((buf1[ih2]! &&& mask) ||| pad)
    buf1 := xor16 buf1 delta
    buf1 := buf1.set! 15 (buf1[15]! ^^^ UInt8.ofNat (j % 256).toNat)
    let tmp1 := aes4 e zero16 e.I1 (e.L[i0]!) buf1
    let L' := xor16 L tmp1

    let mut buf2 : Block := zero16
    for k in [0:half] do buf2 := buf2.set! k (L'[k]!)
    buf2 := buf2.set! ih2 ((buf2[ih2]! &&& mask) ||| pad)
    buf2 := xor16 buf2 delta
    buf2 := buf2.set! 15 (buf2[15]! ^^^ UInt8.ofNat (((j + step) % 256 + 256) % 256).toNat)
    let tmp2 := aes4 e zero16 e.I1 (e.L[i0]!) buf2
    let R' := xor16 R tmp2

    return (L', R', j + 2 * step)

/-- `loopBodyStep` (`step = 1`, matching `d = 0`) is exactly one abstract forward-ladder step for
`G_real`. -/
theorem loopBodyStep_fwd_eq (e : EState) (delta : Block) (half ih2 i0 : Nat) (mask pad : UInt8)
    (L R : Block) (j : Int) :
    loopBodyStep e delta half ih2 i0 mask pad 1 (L, R, j)
      = realFwdStep (G_real e delta half ih2 i0 mask pad) (L, R, j) := by
  simp only [loopBodyStep, realFwdStep, G_real, mkBuf, mod256_renorm,
    Id.run, pure, bind, Prod.mk.injEq]
  refine ⟨trivial, trivial, by omega⟩

/-- `loopBodyStep` (`step = -1`, matching `d ≠ 0`) is exactly one abstract backward-ladder step
for `G_real`. -/
theorem loopBodyStep_bwd_eq (e : EState) (delta : Block) (half ih2 i0 : Nat) (mask pad : UInt8)
    (L R : Block) (j : Int) :
    loopBodyStep e delta half ih2 i0 mask pad (-1) (L, R, j)
      = realBwdStep (G_real e delta half ih2 i0 mask pad) (L, R, j) := by
  have hsub : j + (-1 : Int) = j - 1 := by omega
  simp only [loopBodyStep, realBwdStep, G_real, mkBuf, hsub, mod256_renorm,
    Id.run, pure, bind, Prod.mk.injEq]
  refine ⟨trivial, trivial, by omega⟩

/-- **`aezTinyLR`'s round-trip building block, forward direction**: a `d = 0` call is exactly
`rounds/2` abstract forward-ladder steps (`ladderFwdN`) for `G_real`, starting from the prefix
`initLR` extracts from `inArr`. Proved by converting the real `for` loop to a `List.foldl`
(the usual `Std.Legacy.Range.forIn_eq_forIn_range'`/`List.forIn_pure_yield_eq_foldl` conversion),
recognizing it as `List.foldl_const`-shaped (the loop ignores its own index, only threading state),
converting to `Function.iterate`, and matching that pointwise against `loopBodyStep`'s own iterate
via `Function.iterate_congr_of_forall` — then `loopBodyStep_fwd_eq` and `realFwdStep_iterate_eq`
finish it. This only became tractable once `aezTinyLR`'s own source called `mkBuf` (see `AEZ.lean`)
instead of inlining `buf1`/`buf2`'s construction twice: comparing the *inlined* form pointwise
still re-expands it on every `buf1[ih2]!`/`buf1[15]!` read-back, which times out even at 20x the
default heartbeat budget — the named call makes each comparison touch exactly one copy. -/
theorem aezTinyLR_fwd_eq (e : EState) (delta : Block) (inArr : ByteArray) (rounds i0 : Nat)
    (L0 R0 : Block) (mask pad : UInt8) (hinit : initLR inArr = (L0, R0, mask, pad)) :
    aezTinyLR e delta inArr 0 rounds i0
      = ladderFwdN (FofG (G_real e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 mask pad))
          (rounds / 2) (L0, R0) := by
  unfold initLR at hinit
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl, pure_bind] at hinit
  simp only [Id.run, pure] at hinit
  unfold aezTinyLR
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl, pure_bind]
  simp only [Id.run, pure]
  by_cases hodd : (inArr.size % 2 == 1) = true
  · simp only [hodd, if_true] at hinit ⊢
    simp only [Prod.mk.injEq] at hinit
    obtain ⟨hL0, hR0, hmask, hpad⟩ := hinit
    subst hL0; subst hR0; subst hmask; subst hpad
    split
    · omega
    · refine (List.foldl_eq_iterate_of_forall_pair _ _
          (loopBodyStep e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 240 8 1) ?_ _).trans ?_
      · intro a b _
        obtain ⟨L, R, J⟩ := a
        simp only [loopBodyStep, mkBuf, mod256_renorm, Std.Legacy.Range.forIn_eq_forIn_range',
          Id.run, pure, bind]
      · rw [List.length_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one,
          Function.iterate_congr_of_forall _
          (realFwdStep (G_real e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 240 8))
          (fun a => by obtain ⟨L, R, J⟩ := a; exact loopBodyStep_fwd_eq ..),
          realFwdStep_iterate_eq]
  · have hodd' : (inArr.size % 2 == 1) = false := by simpa using hodd
    simp only [hodd', Bool.false_eq_true, if_false] at hinit ⊢
    simp only [Prod.mk.injEq] at hinit
    obtain ⟨hL0, hR0, hmask, hpad⟩ := hinit
    subst hL0; subst hR0; subst hmask; subst hpad
    split
    · omega
    · refine (List.foldl_eq_iterate_of_forall_pair _ _
          (loopBodyStep e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 0 0x80 1) ?_ _).trans ?_
      · intro a b _
        obtain ⟨L, R, J⟩ := a
        simp only [loopBodyStep, mkBuf, mod256_renorm, Std.Legacy.Range.forIn_eq_forIn_range',
          Id.run, pure, bind]
      · rw [List.length_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one,
          Function.iterate_congr_of_forall _
          (realFwdStep (G_real e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 0 0x80))
          (fun a => by obtain ⟨L, R, J⟩ := a; exact loopBodyStep_fwd_eq ..),
          realFwdStep_iterate_eq]

/-- `aezTinyLR`'s `d ≠ 0` pre-loop tweak: for an input under 16 bytes, XOR a correction byte into
`L[0]`, computed from `inArr`'s raw bytes, before the main loop starts (with `j` at `rounds - 1`,
descending). Literally the same code as `aezTinyLR`'s own `if inBytes < 16 then ...` block inside
its `if d ≠ 0 then ...`. -/
def tinyTweakedL0 (e : EState) (delta : Block) (inArr : ByteArray) (L0 : Block) : Block := Id.run do
  let inBytes := inArr.size
  let mut L := L0
  if inBytes < 16 then
    let mut buf : Block := zero16
    for k in [0:inBytes] do buf := buf.set! k (inArr.get! k)
    buf := buf.set! 0 (buf[0]! ||| 0x80)
    buf := xor16 delta buf
    let tmp := aes4 e zero16 e.I1 (e.L[3]!) buf
    L := L.set! 0 (L[0]! ^^^ (tmp[0]! &&& 0x80))
  return L

/-- **`aezTinyLR`'s round-trip building block, backward direction**: a `d ≠ 0` call (specialized
to `d = 1`, `aezTiny`'s decrypt argument) is exactly `rounds/2` abstract backward-ladder steps
(`ladderBwdN`) for `G_real`, starting from `initLR`'s prefix with the pre-loop tweak applied to
`L`. Mirrors `aezTinyLR_fwd_eq` exactly, via `loopBodyStep_bwd_eq`/`realBwdStep_iterate_eq`
instead of the forward versions; needs `rounds` even (true of every `aezTinyParams` result) so
that the loop's starting counter `rounds - 1` lines up with `realBwdStep_iterate_eq`'s expected
`2 * (rounds / 2) - 1`. -/
theorem aezTinyLR_bwd_eq (e : EState) (delta : Block) (inArr : ByteArray) (rounds i0 : Nat)
    (heven : rounds % 2 = 0) (L0 R0 : Block) (mask pad : UInt8)
    (hinit : initLR inArr = (L0, R0, mask, pad)) :
    aezTinyLR e delta inArr 1 rounds i0
      = ladderBwdN (FofG (G_real e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 mask pad))
          (rounds / 2) (tinyTweakedL0 e delta inArr L0, R0) := by
  unfold initLR at hinit
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl, pure_bind] at hinit
  simp only [Id.run, pure] at hinit
  unfold aezTinyLR tinyTweakedL0
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl, pure_bind]
  simp only [Id.run, pure]
  have hs0 : ∀ mask pad : UInt8, ∀ L R : Block,
      ((loopBodyStep e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 mask pad (-1))^[rounds / 2]
          (L, R, (rounds : Int) - 1)).1
        = (ladderBwdN (FofG (G_real e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 mask pad))
            (rounds / 2) (L, R)).1
      ∧ ((loopBodyStep e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 mask pad (-1))^[rounds / 2]
          (L, R, (rounds : Int) - 1)).2.1
        = (ladderBwdN (FofG (G_real e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 mask pad))
            (rounds / 2) (L, R)).2 := by
    intro mask pad L R
    rw [Function.iterate_congr_of_forall _
        (realBwdStep (G_real e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 mask pad))
        (fun a => by obtain ⟨L, R, J⟩ := a; exact loopBodyStep_bwd_eq ..),
      realBwdStep_iterate_eq (hs0 := by omega)]
    exact ⟨rfl, rfl⟩
  by_cases hodd : (inArr.size % 2 == 1) = true
  · simp only [hodd, if_true] at hinit ⊢
    simp only [Prod.mk.injEq] at hinit
    obtain ⟨hL0, hR0, hmask, hpad⟩ := hinit
    subst hL0; subst hR0; subst hmask; subst hpad
    by_cases htiny : inArr.size < 16
    · simp only [htiny, if_true] at *
      refine (List.foldl_eq_iterate_of_forall_pair _ _
          (loopBodyStep e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 240 8 (-1)) ?_ _).trans ?_
      · intro a b _
        obtain ⟨L, R, J⟩ := a
        simp only [loopBodyStep, mkBuf, mod256_renorm, Std.Legacy.Range.forIn_eq_forIn_range',
          Id.run, pure, bind]
      · rw [List.length_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
        exact Prod.ext (hs0 240 8 _ _).1 (hs0 240 8 _ _).2
    · simp only [htiny, if_false] at *
      refine (List.foldl_eq_iterate_of_forall_pair _ _
          (loopBodyStep e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 240 8 (-1)) ?_ _).trans ?_
      · intro a b _
        obtain ⟨L, R, J⟩ := a
        simp only [loopBodyStep, mkBuf, mod256_renorm, Std.Legacy.Range.forIn_eq_forIn_range',
          Id.run, pure, bind]
      · rw [List.length_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
        exact Prod.ext (hs0 240 8 _ _).1 (hs0 240 8 _ _).2
  · have hodd' : (inArr.size % 2 == 1) = false := by simpa using hodd
    simp only [hodd', Bool.false_eq_true, if_false] at hinit ⊢
    simp only [Prod.mk.injEq] at hinit
    obtain ⟨hL0, hR0, hmask, hpad⟩ := hinit
    subst hL0; subst hR0; subst hmask; subst hpad
    by_cases htiny : inArr.size < 16
    · simp only [htiny, if_true] at *
      refine (List.foldl_eq_iterate_of_forall_pair _ _
          (loopBodyStep e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 0 0x80 (-1)) ?_ _).trans ?_
      · intro a b _
        obtain ⟨L, R, J⟩ := a
        simp only [loopBodyStep, mkBuf, mod256_renorm, Std.Legacy.Range.forIn_eq_forIn_range',
          Id.run, pure, bind]
      · rw [List.length_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
        exact Prod.ext (hs0 0 0x80 _ _).1 (hs0 0 0x80 _ _).2
    · simp only [htiny, if_false] at *
      refine (List.foldl_eq_iterate_of_forall_pair _ _
          (loopBodyStep e delta ((inArr.size + 1) / 2) (inArr.size / 2) i0 0 0x80 (-1)) ?_ _).trans ?_
      · intro a b _
        obtain ⟨L, R, J⟩ := a
        simp only [loopBodyStep, mkBuf, mod256_renorm, Std.Legacy.Range.forIn_eq_forIn_range',
          Id.run, pure, bind]
      · rw [List.length_range', Std.Legacy.Range.size, Nat.sub_zero, Nat.add_sub_cancel, Nat.div_one]
        exact Prod.ext (hs0 0 0x80 _ _).1 (hs0 0 0x80 _ _).2

/-! ## Locality: the ladder only needs to agree on a prefix

`aezTiny`'s merge step only ever reads the first `half` bytes of the ladder's final `(L, R)` —
everything from index `half` onward is discarded. So `aezTinyLR`'s decrypt call, fed the
*merged* ciphertext, doesn't receive a block that's *fully* equal to the swap of what encrypt
produced (only equal in the first `half` bytes — encrypt's own ladder rounds fill positions
`≥ half` with Feistel-round output that never gets read again, and merge throws it away). Reusing
`ladderBwdN_ladderFwdN_swap` as-is would need *full* equality; what actually holds, and is what
matters, is agreement up to `half` — proved here as a "congruence" version of the same round-trip,
generic over any round function that itself only depends on its input's first `half` bytes
(true of `G_real`, via `mkBuf`'s own `for k in [0:half] do ...` loop, proved separately below). -/

/-- Two blocks agree on their first `n` bytes. -/
def PrefixEq (n : Nat) (a b : Block) : Prop := ∀ k, k < n → a[k]! = b[k]!

theorem PrefixEq.xor16_congrLeft {n : Nat} (hn : n ≤ 16) {a a' : Block} (h : PrefixEq n a a')
    (b : Block) : PrefixEq n (xor16 a b) (xor16 a' b) := by
  intro k hk
  rw [xor16_get! (by omega), xor16_get! (by omega), h k hk]

/-- If `F` only depends on its input's first `half` bytes, so does `n` forward ladder steps: given
`half`-equal starting pairs, the outputs are `half`-equal too (not necessarily fully equal — the
tail can diverge, exactly as it does between `aezTinyLR`'s own run and a hypothetical run seeded
from a fully-agreeing block). -/
theorem ladderFwdN_congr (F : Nat → Block → Block) (half : Nat) (hhalf : half ≤ 16)
    (hF : ∀ j X X', PrefixEq half X X' → F j X = F j X') (n : Nat) :
    ∀ L R L' R' : Block, PrefixEq half L L' → PrefixEq half R R' →
      PrefixEq half (ladderFwdN F n (L, R)).1 (ladderFwdN F n (L', R')).1 ∧
      PrefixEq half (ladderFwdN F n (L, R)).2 (ladderFwdN F n (L', R')).2 := by
  induction n with
  | zero => intro L R L' R' hL hR; exact ⟨hL, hR⟩
  | succ n ih =>
    intro L R L' R' hL hR
    obtain ⟨ihL, ihR⟩ := ih L R L' R' hL hR
    show PrefixEq half (ladderFwdStep F n (ladderFwdN F n (L, R))).1
                        (ladderFwdStep F n (ladderFwdN F n (L', R'))).1 ∧
         PrefixEq half (ladderFwdStep F n (ladderFwdN F n (L, R))).2
                        (ladderFwdStep F n (ladderFwdN F n (L', R'))).2
    simp only [ladderFwdStep]
    have hR2k := hF (2 * n) _ _ ihR
    have hL' : PrefixEq half
        (xor16 (ladderFwdN F n (L, R)).1 (F (2 * n) (ladderFwdN F n (L, R)).2))
        (xor16 (ladderFwdN F n (L', R')).1 (F (2 * n) (ladderFwdN F n (L', R')).2)) := by
      rw [hR2k]; exact PrefixEq.xor16_congrLeft hhalf ihL _
    refine ⟨hL', ?_⟩
    rw [hF (2 * n + 1) _ _ hL']
    exact PrefixEq.xor16_congrLeft hhalf ihR _

/-- The backward analogue of `ladderFwdN_congr`. -/
theorem ladderBwdN_congr (F : Nat → Block → Block) (half : Nat) (hhalf : half ≤ 16)
    (hF : ∀ j X X', PrefixEq half X X' → F j X = F j X') (n : Nat) :
    ∀ L R L' R' : Block, PrefixEq half L L' → PrefixEq half R R' →
      PrefixEq half (ladderBwdN F n (L, R)).1 (ladderBwdN F n (L', R')).1 ∧
      PrefixEq half (ladderBwdN F n (L, R)).2 (ladderBwdN F n (L', R')).2 := by
  induction n with
  | zero => intro L R L' R' hL hR; exact ⟨hL, hR⟩
  | succ n ih =>
    intro L R L' R' hL hR
    show PrefixEq half (ladderBwdN F n (ladderBwdStep F (2 * n + 1) (L, R))).1
                        (ladderBwdN F n (ladderBwdStep F (2 * n + 1) (L', R'))).1 ∧
         PrefixEq half (ladderBwdN F n (ladderBwdStep F (2 * n + 1) (L, R))).2
                        (ladderBwdN F n (ladderBwdStep F (2 * n + 1) (L', R'))).2
    apply ih
    · rw [hF (2 * n + 1) _ _ hR]
      exact PrefixEq.xor16_congrLeft hhalf hL _
    · have hL' : PrefixEq half (xor16 L (F (2 * n + 1) R)) (xor16 L' (F (2 * n + 1) R')) := by
        rw [hF (2 * n + 1) _ _ hR]; exact PrefixEq.xor16_congrLeft hhalf hL _
      rw [hF (2 * n + 1 - 1) _ _ hL']
      exact PrefixEq.xor16_congrLeft hhalf hR _

/-- Combining `ladderBwdN_congr` with the exact (full-equality) round-trip
`ladderBwdN_ladderFwdN_swap`: running the backward ladder on anything that's merely `half`-equal
to the swap of a forward run's output still recovers the original pair, up to that same `half`
prefix — exactly the fact `aezTiny`'s round-trip needs, since decrypt's input only ever agrees
with encrypt's output that far. -/
theorem ladderBwdN_prefix_of_swap (F : Nat → Block → Block) (half : Nat) (hhalf : half ≤ 16)
    (hF : ∀ j X X', PrefixEq half X X' → F j X = F j X') (n : Nat) (L R L' R' : Block)
    (hL : L.size = 16) (hR : R.size = 16)
    (hL' : PrefixEq half L' (ladderFwdN F n (L, R)).2)
    (hR' : PrefixEq half R' (ladderFwdN F n (L, R)).1) :
    PrefixEq half (ladderBwdN F n (L', R')).1 R ∧ PrefixEq half (ladderBwdN F n (L', R')).2 L := by
  have hcongr := ladderBwdN_congr F half hhalf hF n L' R'
    (ladderFwdN F n (L, R)).2 (ladderFwdN F n (L, R)).1 hL' hR'
  rwa [show ((ladderFwdN F n (L, R)).2, (ladderFwdN F n (L, R)).1)
      = (ladderFwdN F n (L, R)).swap from rfl,
    ladderBwdN_ladderFwdN_swap F n L R hL hR] at hcongr

/-! ## Odd-length locality: agreement needs a boundary nibble too

For an odd-length input, `G_real`'s mask is `0xf0` (not `0`), so `mkBuf`'s output at the boundary
position `ih2 = inBytes / 2` depends on its input's *upper nibble* there, not just on the bytes
strictly below it. `PrefixEq` alone (agreement below `n`) is no longer enough to make `G_real`
congruent — the extra fact needed is that the two inputs' masked bytes agree exactly *at* `n` too.
`PrefixEqB` packages both; `ladderFwdN_congrB`/`ladderBwdN_congrB`/`ladderBwdN_prefix_of_swapB`
mirror the plain versions exactly, and reuse the same exact round-trip
(`ladderBwdN_ladderFwdN_swap`) underneath, since that fact never depended on locality at all. -/

/-- Two blocks agree on their first `n` bytes, and their `n`-th bytes agree after masking with
`mask`. -/
def PrefixEqB (n : Nat) (mask : UInt8) (a b : Block) : Prop :=
  PrefixEq n a b ∧ a[n]! &&& mask = b[n]! &&& mask

private theorem xor_and_distrib (a b m : UInt8) : (a ^^^ b) &&& m = (a &&& m) ^^^ (b &&& m) := by
  bv_decide

theorem PrefixEqB.xor16_congrLeft {n : Nat} (hn : n ≤ 15) {mask : UInt8} {a a' : Block}
    (h : PrefixEqB n mask a a') (b : Block) : PrefixEqB n mask (xor16 a b) (xor16 a' b) := by
  obtain ⟨hpre, hb⟩ := h
  refine ⟨PrefixEq.xor16_congrLeft (by omega) hpre b, ?_⟩
  rw [xor16_get! (by omega), xor16_get! (by omega), xor_and_distrib, xor_and_distrib, hb]

/-- The `PrefixEqB` analogue of `ladderFwdN_congr`. -/
theorem ladderFwdN_congrB (F : Nat → Block → Block) (n : Nat) (hn : n ≤ 15) (mask : UInt8)
    (hF : ∀ j X X', PrefixEqB n mask X X' → F j X = F j X') (rounds : Nat) :
    ∀ L R L' R' : Block, PrefixEqB n mask L L' → PrefixEqB n mask R R' →
      PrefixEqB n mask (ladderFwdN F rounds (L, R)).1 (ladderFwdN F rounds (L', R')).1 ∧
      PrefixEqB n mask (ladderFwdN F rounds (L, R)).2 (ladderFwdN F rounds (L', R')).2 := by
  induction rounds with
  | zero => intro L R L' R' hL hR; exact ⟨hL, hR⟩
  | succ rounds ih =>
    intro L R L' R' hL hR
    obtain ⟨ihL, ihR⟩ := ih L R L' R' hL hR
    show PrefixEqB n mask (ladderFwdStep F rounds (ladderFwdN F rounds (L, R))).1
                        (ladderFwdStep F rounds (ladderFwdN F rounds (L', R'))).1 ∧
         PrefixEqB n mask (ladderFwdStep F rounds (ladderFwdN F rounds (L, R))).2
                        (ladderFwdStep F rounds (ladderFwdN F rounds (L', R'))).2
    simp only [ladderFwdStep]
    have hR2k := hF (2 * rounds) _ _ ihR
    have hL' : PrefixEqB n mask
        (xor16 (ladderFwdN F rounds (L, R)).1 (F (2 * rounds) (ladderFwdN F rounds (L, R)).2))
        (xor16 (ladderFwdN F rounds (L', R')).1 (F (2 * rounds) (ladderFwdN F rounds (L', R')).2)) := by
      rw [hR2k]; exact PrefixEqB.xor16_congrLeft hn ihL _
    refine ⟨hL', ?_⟩
    rw [hF (2 * rounds + 1) _ _ hL']
    exact PrefixEqB.xor16_congrLeft hn ihR _

/-- The `PrefixEqB` analogue of `ladderBwdN_congr`. -/
theorem ladderBwdN_congrB (F : Nat → Block → Block) (n : Nat) (hn : n ≤ 15) (mask : UInt8)
    (hF : ∀ j X X', PrefixEqB n mask X X' → F j X = F j X') (rounds : Nat) :
    ∀ L R L' R' : Block, PrefixEqB n mask L L' → PrefixEqB n mask R R' →
      PrefixEqB n mask (ladderBwdN F rounds (L, R)).1 (ladderBwdN F rounds (L', R')).1 ∧
      PrefixEqB n mask (ladderBwdN F rounds (L, R)).2 (ladderBwdN F rounds (L', R')).2 := by
  induction rounds with
  | zero => intro L R L' R' hL hR; exact ⟨hL, hR⟩
  | succ rounds ih =>
    intro L R L' R' hL hR
    show PrefixEqB n mask (ladderBwdN F rounds (ladderBwdStep F (2 * rounds + 1) (L, R))).1
                        (ladderBwdN F rounds (ladderBwdStep F (2 * rounds + 1) (L', R'))).1 ∧
         PrefixEqB n mask (ladderBwdN F rounds (ladderBwdStep F (2 * rounds + 1) (L, R))).2
                        (ladderBwdN F rounds (ladderBwdStep F (2 * rounds + 1) (L', R'))).2
    apply ih
    · rw [hF (2 * rounds + 1) _ _ hR]
      exact PrefixEqB.xor16_congrLeft hn hL _
    · have hL' : PrefixEqB n mask (xor16 L (F (2 * rounds + 1) R)) (xor16 L' (F (2 * rounds + 1) R')) := by
        rw [hF (2 * rounds + 1) _ _ hR]; exact PrefixEqB.xor16_congrLeft hn hL _
      rw [hF (2 * rounds + 1 - 1) _ _ hL']
      exact PrefixEqB.xor16_congrLeft hn hR _

/-- The `PrefixEqB` analogue of `ladderBwdN_prefix_of_swap`. -/
theorem ladderBwdN_prefix_of_swapB (F : Nat → Block → Block) (n : Nat) (hn : n ≤ 15) (mask : UInt8)
    (hF : ∀ j X X', PrefixEqB n mask X X' → F j X = F j X') (rounds : Nat) (L R L' R' : Block)
    (hL : L.size = 16) (hR : R.size = 16)
    (hL' : PrefixEqB n mask L' (ladderFwdN F rounds (L, R)).2)
    (hR' : PrefixEqB n mask R' (ladderFwdN F rounds (L, R)).1) :
    PrefixEqB n mask (ladderBwdN F rounds (L', R')).1 R ∧
    PrefixEqB n mask (ladderBwdN F rounds (L', R')).2 L := by
  have hcongr := ladderBwdN_congrB F n hn mask hF rounds L' R'
    (ladderFwdN F rounds (L, R)).2 (ladderFwdN F rounds (L, R)).1 hL' hR'
  rwa [show ((ladderFwdN F rounds (L, R)).2, (ladderFwdN F rounds (L, R)).1)
      = (ladderFwdN F rounds (L, R)).swap from rfl,
    ladderBwdN_ladderFwdN_swap F rounds L R hL hR] at hcongr

private theorem List.foldl_congr {α β} (l : List β) (f g : α → β → α)
    (h : ∀ a k, k ∈ l → f a k = g a k) (init : α) : l.foldl f init = l.foldl g init := by
  induction l generalizing init with
  | nil => rfl
  | cons hd tl ih =>
    rw [List.foldl_cons, List.foldl_cons, h init hd (List.mem_cons_self ..)]
    exact ih (fun a k hk => h a k (List.mem_cons_of_mem hd hk)) (g init hd)

/-- Congruence for `forIn` over a `List`, `Id`-valued, with a step that only ever `.yield`s: two
step functions that agree pointwise on every list element give the same result. Needed because
`Id`-monad `for`-loops surface as bare `forIn ... (fun a b => ForInStep.yield ...)` terms (no
`pure` wrapper for `simp` to key `List.forIn_pure_yield_eq_foldl` off), unlike the `Except`-monad
loops elsewhere in this project. -/
private theorem forIn_yield_congr {α β} (l : List α) (f g : α → β → β)
    (h : ∀ a ∈ l, ∀ b, f a b = g a b) (init : β) :
    (forIn l init (fun a b => ForInStep.yield (f a b)) : Id β) =
    (forIn l init (fun a b => ForInStep.yield (g a b)) : Id β) := by
  induction l generalizing init with
  | nil => simp
  | cons hd tl ih =>
    simp only [List.forIn_cons, h hd (List.mem_cons_self ..) init, bind]
    exact ih (fun a ha b => h a (List.mem_cons_of_mem hd ha) b) (g hd init)

/-- `mkBuf`'s output only depends on its input's first `half` bytes — its own `for k in [0:half]
do ...` loop is the only place it ever reads `X`. This is the fact that makes `aezTiny`'s
round-trip only need `PrefixEq`, not full block equality, between what encrypt produces and what
decrypt receives. -/
theorem mkBuf_congr (half ih2 : Nat) (mask pad : UInt8) (delta : Block) (X X' : Block)
    (h : PrefixEq half X X') (ctr : UInt8) :
    mkBuf half ih2 mask pad delta X ctr = mkBuf half ih2 mask pad delta X' ctr := by
  unfold mkBuf
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Id.run, pure, bind]
  have hfold : (forIn (List.range' 0 [:half].size) zero16
        (fun k acc => ForInStep.yield (acc.set! k X[k]!)) : Id Block)
      = (forIn (List.range' 0 [:half].size) zero16
        (fun k acc => ForInStep.yield (acc.set! k X'[k]!)) : Id Block) := by
    refine forIn_yield_congr _ _ _ (fun k hk acc => ?_) _
    have hk' : k < half := by simpa using hk
    rw [h k hk']
  rw [hfold]

/-- `G_real`'s congruence, as a direct corollary of `mkBuf_congr`: `aes4` applied to equal `mkBuf`
outputs gives equal results, and `mkBuf`'s inputs need only agree on the first `half` bytes. This
is exactly the `hF` hypothesis `ladderFwdN_congr`/`ladderBwdN_congr`/`ladderBwdN_prefix_of_swap`
need, instantiated to the real round function. -/
theorem G_real_congr (e : EState) (delta : Block) (half ih2 i0 : Nat) (mask pad : UInt8)
    (j : Int) (X X' : Block) (h : PrefixEq half X X') :
    G_real e delta half ih2 i0 mask pad j X = G_real e delta half ih2 i0 mask pad j X' := by
  unfold G_real
  rw [mkBuf_congr half ih2 mask pad delta X X' h]

/-! ## `aezTiny`'s merge/demerge: the even-length case -/

/-- `aezTiny`'s merge step for even-length input, with no final tweak: `buf[k] = R[k]` for
`k < inBytes / 2`, `buf[inBytes / 2 + k] = L[k]` for `k < half` — literally `aezTiny`'s own
construction, skipping the odd-length nibble-packing (`half = inBytes / 2` when even, so that
branch is dead) and the `d = 0 ∧ inBytes < 16` output tweak. -/
def mergeEven (inBytes : Nat) (L R : Block) : ByteArray := Id.run do
  let half := (inBytes + 1) / 2
  let mut buf : Array UInt8 := Array.replicate inBytes 0
  for k in [0:inBytes / 2] do buf := buf.set! k (R[k]!)
  for k in [0:half] do buf := buf.set! (inBytes / 2 + k) (L[k]!)
  return ⟨buf⟩

theorem aezTiny_eq_mergeEven (e : EState) (delta : Block) (inArr : ByteArray) (d : Nat)
    (heven : inArr.size % 2 = 0) (hnotweak : ¬(inArr.size < 16 ∧ d == 0)) :
    aezTiny e delta inArr d
      = mergeEven inArr.size
          (aezTinyLR e delta inArr d (aezTinyParams inArr.size).2 (aezTinyParams inArr.size).1).1
          (aezTinyLR e delta inArr d (aezTinyParams inArr.size).2 (aezTinyParams inArr.size).1).2 := by
  unfold aezTiny mergeEven
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Id.run, pure, bind]
  have heven' : (inArr.size % 2 == 1) = false := by simp [heven]
  simp only [heven', Bool.false_eq_true, if_false]
  have hnotweak2 : inArr.size ≥ 16 ∨ d ≠ 0 := by
    rcases Nat.lt_or_ge inArr.size 16 with h | h
    · right; intro hd; exact hnotweak ⟨h, by simp [hd]⟩
    · left; exact h
  have hnotweak' : (decide (inArr.size < 16) && d == 0) = false := by
    rcases hnotweak2 with h | h
    · simp [Nat.not_lt.mpr h]
    · simp [h]
  simp only [hnotweak', Bool.false_eq_true, if_false]

/-- A `forIn` loop that only ever `.set!`s (never changes the array's size) preserves the starting
size, regardless of how many times it runs. -/
private theorem forIn_set!_size {α} (l : List Nat) (idx : Nat → Nat) (f : Nat → α)
    (init : Array α) :
    (forIn l init (fun k acc => ForInStep.yield (acc.set! (idx k) (f k))) : Id (Array α)).size
      = init.size := by
  induction l generalizing init with
  | nil => simp [pure]
  | cons hd tl ih => simp only [List.forIn_cons, bind, ih, Array.size_set!]

@[simp] private theorem byteArray_mk_size (a : Array UInt8) : (⟨a⟩ : ByteArray).size = a.size := rfl

theorem mergeEven_size (inBytes : Nat) (L R : Block) : (mergeEven inBytes L R).size = inBytes := by
  unfold mergeEven
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Id.run, pure, bind, forIn_set!_size,
    Array.size_replicate, byteArray_mk_size]

/-- Decrypt's `initLR`, fed the ciphertext `mergeEven inBytes L R`, recovers `(R, L)` in the first
`inBytes / 2` bytes (all that `mergeEven`'s own construction ever reads) — the concrete instance
of the "half-agrees-with-swap" fact `ladderBwdN_prefix_of_swap` needs, matching the `L0`/`R0`
built from `mergeEven`'s own construction: `initLR`'s `L`-extraction only ever reads `mergeEven`'s
first `inBytes / 2` bytes (`R`'s own contribution), and its `R`-extraction only ever reads the
next `inBytes / 2` (`L`'s own contribution). -/
private theorem forIn_append {α β} (l1 l2 : List α) (init : β) (f : α → β → β) :
    (forIn (l1 ++ l2) init (fun a b => ForInStep.yield (f a b)) : Id β)
      = (forIn l2 (forIn l1 init (fun a b => ForInStep.yield (f a b)) : Id β)
          (fun a b => ForInStep.yield (f a b)) : Id β) := by
  induction l1 generalizing init with
  | nil => simp [pure, Id.run]
  | cons hd tl ih => simp only [List.cons_append, List.forIn_cons, bind, ih]

/-- A `forIn` loop `.set!`ting `idxOffset + i` (for `i` ranging over `[0, n)`) writes exactly `f k`
at position `idxOffset + k`, for every `k < n` in range — provided the array is big enough that
`Array.set!` never falls back to a no-op. Generic over the array's own size `sz` (not fixed to a
16-byte `Block`): `mergeEven`'s buffer is `inBytes`-sized instead. -/
private theorem forIn_range_set!_get_lt (n idxOffset sz : Nat) (f : Nat → UInt8)
    (init : Array UInt8) (hsize : init.size = sz) (hbound : idxOffset + n ≤ sz) :
    ∀ k, k < n →
      (forIn (List.range' 0 n) init
          (fun i acc => ForInStep.yield (acc.set! (idxOffset + i) (f i))) :
            Id (Array UInt8)).run[idxOffset + k]! = f k := by
  induction n generalizing init with
  | zero => intro k hk; omega
  | succ n ih =>
    intro k hk
    rw [List.range'_1_concat, forIn_append]
    simp only [List.forIn_cons, List.forIn_nil, bind, pure, Id.run, Nat.zero_add]
    rcases Nat.lt_succ_iff_lt_or_eq.mp hk with hk' | hk'
    · rw [Array.getElem!_set!_ne _ _ _ _ (by omega)]
      exact ih init hsize (by omega) k hk'
    · subst hk'
      rw [Array.getElem!_set!_self]
      rw [forIn_set!_size]
      omega

/-- The complement of `forIn_range_set!_get_lt`: such a loop leaves every index below `idxOffset`
untouched. -/
private theorem forIn_range_set!_get_unaffected (n idxOffset : Nat) (f : Nat → UInt8)
    (init : Array UInt8) (k0 : Nat) (hk0 : k0 < idxOffset) :
    (forIn (List.range' 0 n) init
        (fun i acc => ForInStep.yield (acc.set! (idxOffset + i) (f i))) :
          Id (Array UInt8)).run[k0]! = init[k0]! := by
  induction n generalizing init with
  | zero => simp
  | succ n ih =>
    rw [List.range'_1_concat, forIn_append]
    simp only [List.forIn_cons, List.forIn_nil, bind, pure, Id.run, Nat.zero_add]
    rw [Array.getElem!_set!_ne _ _ _ _ (by omega)]
    exact ih init

/-- `forIn_range_set!_get_lt`, specialized to `idxOffset = 0` (so the conclusion reads `f k`
directly at position `k`, not `0 + k`). -/
private theorem forIn_range_set!_get_lt0 (n sz : Nat) (f : Nat → UInt8) (init : Array UInt8)
    (hsize : init.size = sz) (hbound : n ≤ sz) :
    ∀ k, k < n →
      (forIn (List.range' 0 n) init (fun i acc => ForInStep.yield (acc.set! i (f i))) :
        Id (Array UInt8)).run[k]! = f k := by
  intro k hk
  simpa using forIn_range_set!_get_lt n 0 sz f init hsize (by omega) k hk

theorem mergeEven_get_left (inBytes : Nat) (heven : inBytes % 2 = 0) (L R : Block) (k : Nat)
    (hk : k < inBytes / 2) : (mergeEven inBytes L R).get! k = R[k]! := by
  show (mergeEven inBytes L R).data[k]! = R[k]!
  unfold mergeEven
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, Id.run, pure, bind]
  have hhalf : (inBytes + 1) / 2 = inBytes / 2 := by omega
  rw [hhalf]
  have h1 := forIn_range_set!_get_unaffected (inBytes / 2) (inBytes / 2) (fun i => L[i]!)
    (forIn (List.range' 0 (inBytes / 2)) (Array.replicate inBytes 0)
      (fun i acc => ForInStep.yield (acc.set! i R[i]!)) : Id (Array UInt8)) k hk
  exact h1.trans (forIn_range_set!_get_lt0 (inBytes / 2) inBytes (fun i => R[i]!)
    (Array.replicate inBytes 0) (by simp) (by omega) k hk)

theorem mergeEven_get_right (inBytes : Nat) (heven : inBytes % 2 = 0) (L R : Block) (k : Nat)
    (hk : k < inBytes / 2) : (mergeEven inBytes L R).get! (inBytes / 2 + k) = L[k]! := by
  show (mergeEven inBytes L R).data[inBytes / 2 + k]! = L[k]!
  unfold mergeEven
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, Id.run, pure, bind]
  have hhalf : (inBytes + 1) / 2 = inBytes / 2 := by omega
  rw [hhalf]
  exact forIn_range_set!_get_lt (inBytes / 2) (inBytes / 2) inBytes (fun i => L[i]!)
    (forIn (List.range' 0 (inBytes / 2)) (Array.replicate inBytes 0)
      (fun i acc => ForInStep.yield (acc.set! i R[i]!)) : Id (Array UInt8))
    (by rw [forIn_set!_size]; simp) (by omega) k hk

/-- Decrypt's `initLR`, fed the ciphertext `mergeEven inBytes L R`, recovers `(R, L)` in the first
`inBytes / 2` bytes (all that `mergeEven`'s own construction ever reads) — the concrete instance
of the "half-agrees-with-swap" fact `ladderBwdN_prefix_of_swap` needs. -/
theorem initLR_mergeEven (inBytes : Nat) (heven : inBytes % 2 = 0) (hlt : inBytes < 32)
    (L R : Block) :
    PrefixEq (inBytes / 2) (initLR (mergeEven inBytes L R)).1 R ∧
    PrefixEq (inBytes / 2) (initLR (mergeEven inBytes L R)).2.1 L ∧
    (initLR (mergeEven inBytes L R)).2.2 = (0, 0x80) := by
  have hsize : (mergeEven inBytes L R).size = inBytes := mergeEven_size inBytes L R
  unfold initLR
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, Id.run, pure, bind]
  rw [hsize]
  have heven' : (inBytes % 2 == 1) = false := by simp [heven]
  have hhalf : (inBytes + 1) / 2 = inBytes / 2 := by omega
  rw [heven', hhalf]
  simp only [Bool.false_eq_true, if_false]
  refine ⟨?_, ?_, trivial⟩
  · intro k hk
    exact (forIn_range_set!_get_lt0 (inBytes / 2) 16 (fun i => (mergeEven inBytes L R).get! i)
        zero16 (by simp [zero16]) (by omega) k hk).trans
      (mergeEven_get_left inBytes heven L R k hk)
  · intro k hk
    exact (forIn_range_set!_get_lt0 (inBytes / 2) 16
        (fun i => (mergeEven inBytes L R).get! (inBytes / 2 + i)) zero16
        (by simp [zero16]) (by omega) k hk).trans
      (mergeEven_get_right inBytes heven L R k hk)

/-- The same extraction facts as `initLR_mergeEven`, but for `initLR` applied directly to a raw
even-length input `inArr` rather than to `mergeEven`'s reconstruction: `initLR`'s own `L`/`R`
loops read `inArr.get!` directly, with no intervening `mergeEven`/`get!`-bridging needed. This is
what recovers the *original* `inArr` from the round-trip's final `(L, R)`. -/
theorem initLR_even_eq (inArr : ByteArray) (heven : inArr.size % 2 = 0) (hlt : inArr.size < 32) :
    (∀ k, k < inArr.size / 2 → (initLR inArr).1[k]! = inArr.get! k) ∧
    (∀ k, k < inArr.size / 2 → (initLR inArr).2.1[k]! = inArr.get! (inArr.size / 2 + k)) ∧
    (initLR inArr).2.2 = (0, 0x80) := by
  unfold initLR
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, Id.run, pure, bind]
  have heven' : (inArr.size % 2 == 1) = false := by simp [heven]
  have hhalf : (inArr.size + 1) / 2 = inArr.size / 2 := by omega
  rw [heven', hhalf]
  simp only [Bool.false_eq_true, if_false]
  refine ⟨?_, ?_, trivial⟩
  · intro k hk
    exact forIn_range_set!_get_lt0 (inArr.size / 2) 16 (fun i => inArr.get! i) zero16
      (by simp [zero16]) (by omega) k hk
  · intro k hk
    exact forIn_range_set!_get_lt0 (inArr.size / 2) 16
      (fun i => inArr.get! (inArr.size / 2 + i)) zero16 (by simp [zero16]) (by omega) k hk

/-- `aezTinyParams`'s only branch reachable for inputs of at least 16 bytes. -/
theorem aezTinyParams_ge16 (n : Nat) (h : 16 ≤ n) : aezTinyParams n = (6, 8) := by
  unfold aezTinyParams
  have h1 : (n == 1) = false := by simp only [beq_eq_false_iff_ne]; omega
  have h2 : (n == 2) = false := by simp only [beq_eq_false_iff_ne]; omega
  rw [if_neg (by simpa using h1), if_neg (by simpa using h2), if_neg (by omega)]

/-- `initLR`'s `L`/`R` components always come out as 16-byte blocks, for an even-length input:
both start from `zero16` and are only ever `.set!`-updated (no odd-length nibble-packing branch
taken), and `.set!` never changes an array's size. -/
theorem initLR_size (inArr : ByteArray) (heven : inArr.size % 2 = 0) :
    (initLR inArr).1.size = 16 ∧ (initLR inArr).2.1.size = 16 := by
  unfold initLR
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Id.run, pure, bind]
  have heven' : (inArr.size % 2 == 1) = false := by simp [heven]
  simp only [heven', Bool.false_eq_true, if_false, forIn_set!_size, Array.size_replicate, zero16]
  exact ⟨trivial, trivial⟩

private theorem byteArray_get!_eq (b : ByteArray) (i : Nat) : b.get! i = b[i]! := by
  show b.data[i]! = b[i]!
  by_cases h : i < b.size
  · rw [getElem!_pos b i h]
    show b.data[i]! = b.get i h
    rw [getElem!_pos b.data i h]
    rfl
  · rw [getElem!_neg b i h]
    show b.data[i]! = (default : UInt8)
    exact getElem!_neg b.data i (by simpa using h)

/-- Byte-level extensionality for `ByteArray`, stated via `.get!` (the form every lemma in this
file, e.g. `mergeEven_get_left`/`mergeEven_get_right`, works with) rather than `getElem`-with-proof
(`ByteArray.ext_getElem`'s own form). -/
private theorem byteArray_ext_get! {a b : ByteArray} (hsize : a.size = b.size)
    (h : ∀ i, i < a.size → a.get! i = b.get! i) : a = b := by
  apply ByteArray.ext_getElem hsize
  intro i hi hi'
  have := h i hi
  rwa [byteArray_get!_eq, byteArray_get!_eq, getElem!_pos a i hi, getElem!_pos b i hi'] at this

/-- **The full `aezTiny` round-trip, for even-length inputs of at least 16 bytes**: encrypting
(`d = 0`) then decrypting (`d = 1`) recovers the original input exactly. Composes the whole chain
built above: `aezTiny_eq_mergeEven` (both directions) reduces both calls to their `aezTinyLR`
cores; `aezTinyLR_fwd_eq`/`aezTinyLR_bwd_eq` identify those cores with the abstract ladder;
`initLR_mergeEven` supplies the prefix-agreement the decrypt ladder actually receives (not full
agreement — see the "Locality" section); `ladderBwdN_prefix_of_swap` (built from the exact
`ladderBwdN_ladderFwdN_swap` round-trip together with `G_real_congr`'s locality) then recovers the
original `(L, R)` up to that same prefix; and `initLR_even_eq` plus `mergeEven_get_left`/
`mergeEven_get_right` translate that prefix-equality on `(L, R)` back into byte-equality with
`inArr` itself, closed via `byteArray_ext_get!`. -/
theorem aezTiny_roundtrip_even (e : EState) (delta : Block) (inArr : ByteArray)
    (heven : inArr.size % 2 = 0) (h16 : 16 ≤ inArr.size) (hlt : inArr.size < 32) :
    aezTiny e delta (aezTiny e delta inArr 0) 1 = inArr := by
  have hparams : aezTinyParams inArr.size = (6, 8) := aezTinyParams_ge16 inArr.size h16
  have half_eq : (inArr.size + 1) / 2 = inArr.size / 2 := by omega
  -- Encrypt: `aezTiny ... 0 = mergeEven ... (aezTinyLR ... 0 ...)`.
  have hnotweak0 : ¬(inArr.size < 16 ∧ (0 : Nat) == 0) := by rintro ⟨h1, -⟩; omega
  have henc := aezTiny_eq_mergeEven e delta inArr 0 heven hnotweak0
  simp only [hparams] at henc
  set L0 := (initLR inArr).1 with hL0def
  set R0 := (initLR inArr).2.1 with hR0def
  obtain ⟨hL0, hR0, hmp0⟩ := initLR_even_eq inArr heven hlt
  have hinit0 : initLR inArr = (L0, R0, 0, 0x80) := by rw [← hmp0]
  have hfwd := aezTinyLR_fwd_eq e delta inArr 8 6 L0 R0 0 0x80 hinit0
  rw [half_eq] at hfwd
  set L1 := (ladderFwdN (FofG (G_real e delta (inArr.size / 2) (inArr.size / 2) 6 0 0x80))
      (8 / 2) (L0, R0)).1 with hL1def
  set R1 := (ladderFwdN (FofG (G_real e delta (inArr.size / 2) (inArr.size / 2) 6 0 0x80))
      (8 / 2) (L0, R0)).2 with hR1def
  rw [show (aezTinyLR e delta inArr 0 8 6).1 = L1 from by rw [hfwd],
    show (aezTinyLR e delta inArr 0 8 6).2 = R1 from by rw [hfwd]] at henc
  -- Decrypt: `aezTiny ... 1 = mergeEven ... (aezTinyLR ... 1 ...)`, on the ciphertext.
  set C := mergeEven inArr.size L1 R1 with hCdef
  have hCsize : C.size = inArr.size := mergeEven_size inArr.size L1 R1
  have hnotweak1 : ¬(C.size < 16 ∧ (1 : Nat) == 0) := by simp
  have hdec := aezTiny_eq_mergeEven e delta C 1 (by rw [hCsize]; exact heven) hnotweak1
  simp only [hCsize, hparams] at hdec
  -- Identify decrypt's `initLR C` extraction and feed it to `aezTinyLR_bwd_eq`.
  obtain ⟨hCswap1, hCswap2, hCmp⟩ := initLR_mergeEven inArr.size heven hlt L1 R1
  rw [← hCdef] at hCswap1 hCswap2 hCmp
  set L0' := (initLR C).1 with hL0'def
  set R0' := (initLR C).2.1 with hR0'def
  have hinit1 : initLR C = (L0', R0', 0, 0x80) := by rw [← hCmp]
  have hbwd := aezTinyLR_bwd_eq e delta C 8 6 (by decide) L0' R0' 0 0x80 hinit1
  rw [hCsize, half_eq] at hbwd
  have htweaknoop : tinyTweakedL0 e delta C L0' = L0' := by
    unfold tinyTweakedL0
    rw [hCsize, if_neg (show ¬ inArr.size < 16 from by omega)]
    simp [Id.run, pure]
  rw [htweaknoop] at hbwd
  -- The swap-prefix fact: decrypt's ladder, seeded from something only `half`-agreeing with the
  -- swap of encrypt's output, still recovers `(R0, L0)` up to that same prefix.
  obtain ⟨hL0size, hR0size⟩ := initLR_size inArr heven
  rw [← hL0def] at hL0size
  rw [← hR0def] at hR0size
  have hswap := ladderBwdN_prefix_of_swap
    (FofG (G_real e delta (inArr.size / 2) (inArr.size / 2) 6 0 0x80)) (inArr.size / 2)
    (by omega)
    (fun j X X' h => by
      simp only [FofG]
      exact G_real_congr e delta (inArr.size / 2) (inArr.size / 2) 6 0 0x80 (j : Int) X X' h)
    (8 / 2) L0 R0 L0' R0' hL0size hR0size hCswap1 hCswap2
  set L2 := (aezTinyLR e delta C 1 8 6).1 with hL2def
  set R2 := (aezTinyLR e delta C 1 8 6).2 with hR2def
  have hL2eq : L2 = (ladderBwdN (FofG (G_real e delta (inArr.size / 2) (inArr.size / 2) 6 0 0x80))
      (8 / 2) (L0', R0')).1 := by rw [hL2def, hbwd]
  have hR2eq : R2 = (ladderBwdN (FofG (G_real e delta (inArr.size / 2) (inArr.size / 2) 6 0 0x80))
      (8 / 2) (L0', R0')).2 := by rw [hR2def, hbwd]
  have hL2R0 : PrefixEq (inArr.size / 2) L2 R0 := hL2eq ▸ hswap.1
  have hR2L0 : PrefixEq (inArr.size / 2) R2 L0 := hR2eq ▸ hswap.2
  rw [henc, hdec]
  apply byteArray_ext_get!
  · rw [mergeEven_size]
  · intro i hi
    rw [mergeEven_size] at hi
    rcases Nat.lt_or_ge i (inArr.size / 2) with hlt' | hge
    · exact (mergeEven_get_left inArr.size heven L2 R2 i hlt').trans
        ((hR2L0 i hlt').trans (hL0 i hlt'))
    · have hk : i - inArr.size / 2 < inArr.size / 2 := by omega
      have hrw : i = inArr.size / 2 + (i - inArr.size / 2) := by omega
      rw [hrw]
      exact (mergeEven_get_right inArr.size heven L2 R2 _ hk).trans
        ((hL2R0 _ hk).trans (hR0 _ hk))

/-! ## Odd-length merge/demerge: bit-level groundwork

For odd-length input, `G_real`'s mask is `0xf0`: `mkBuf`'s output at the boundary position `ih2`
depends on that byte's *upper nibble*, and `aezTiny`'s odd-length merge/demerge packs adjacent
bytes' nibbles together. All of it reduces to a handful of general, free-variable `UInt8` bit
identities, discharged by `bv_decide` (an off-the-shelf bitvector decision procedure — these are
not properties special to this codebase, just facts about 8-bit shifts/masks). -/

private theorem shl4_shr4 (x : UInt8) : (x <<< 4) >>> 4 = x &&& 0x0f := by bv_decide
private theorem shr4_shl4 (x : UInt8) : (x >>> 4) <<< 4 = x &&& 0xf0 := by bv_decide
private theorem shr4_shr4 (x : UInt8) : (x >>> 4) >>> 4 = 0 := by bv_decide
private theorem shl4_shl4 (x : UInt8) : (x <<< 4) <<< 4 = 0 := by bv_decide
private theorem nibble_recombine (x : UInt8) : (x &&& 0x0f) ||| (x &&& 0xf0) = x := by bv_decide
private theorem or_and_distrib (a b m : UInt8) : (a ||| b) &&& m = (a &&& m) ||| (b &&& m) := by
  bv_decide
private theorem shr4_and_f0 (x : UInt8) : x >>> 4 = (x &&& 0xf0) >>> 4 := by bv_decide

/-- Two `Block`s that agree at every index `< 16` are equal. The `Array UInt8` analogue of
`byteArray_ext_get!`, needed once `mkBuf`'s congruence proofs must bridge from "agrees pointwise"
back to "is the same `Block`" before handing the result to the opaque `aes4` call. -/
private theorem block_ext_get! {a b : Block} (hsa : a.size = 16) (hsb : b.size = 16)
    (h : ∀ k, k < 16 → a[k]! = b[k]!) : a = b := by
  apply Array.ext_getElem?
  intro i
  by_cases hi : i < 16
  · rw [getElem?_pos a i (by omega), getElem?_pos b i (by omega)]
    congr 1
    rw [← getElem!_pos a i (by omega), ← getElem!_pos b i (by omega)]
    exact h i hi
  · rw [getElem?_neg a i (by omega), getElem?_neg b i (by omega)]

/-- The complement of `forIn_range_set!_get_lt0`: a `forIn` loop over `[0, n)` leaves every index
`≥ n` untouched. -/
private theorem forIn_range_set!_get_ge (n : Nat) (f : Nat → UInt8) (init : Array UInt8)
    (k0 : Nat) (hk0 : n ≤ k0) :
    (forIn (List.range' 0 n) init (fun i acc => ForInStep.yield (acc.set! i (f i))) :
      Id (Array UInt8)).run[k0]! = init[k0]! := by
  induction n generalizing init with
  | zero => simp
  | succ n ih =>
    rw [List.range'_1_concat, forIn_append]
    simp only [List.forIn_cons, List.forIn_nil, bind, pure, Id.run, Nat.zero_add]
    rw [Array.getElem!_set!_ne _ _ _ _ (by omega)]
    exact ih init (by omega)

/-- If two blocks agree below `ih2`, and agree at `ih2` itself once masked, `mkBuf` (with
`half := ih2 + 1`, matching the odd-length case's own `half`/`ih2` relationship) gives the same
output for both: the copy loop's only read of position `ih2` is immediately overwritten by
`(·[ih2]! &&& mask) ||| pad`, erasing everything about the read-back value except its image under
`&&& mask`; positions `< ih2` survive untouched into the final output, and positions `> ih2`
(within the 16-byte block) are never touched by the copy loop at all (since `half = ih2 + 1`). -/
theorem mkBuf_congr_boundary (ih2 : Nat) (hih2 : ih2 < 16) (mask pad : UInt8) (delta X X' : Block)
    (hpre : PrefixEq ih2 X X') (hmask : X[ih2]! &&& mask = X'[ih2]! &&& mask) (ctr : UInt8) :
    mkBuf (ih2 + 1) ih2 mask pad delta X ctr = mkBuf (ih2 + 1) ih2 mask pad delta X' ctr := by
  have hcopy : ∀ (Y : Block) (k : Nat), k < 16 →
      (forIn (List.range' 0 (ih2 + 1)) zero16
        (fun i acc => ForInStep.yield (acc.set! i Y[i]!)) : Id Block).run[k]!
        = if k < ih2 + 1 then Y[k]! else (0 : UInt8) := by
    intro Y k hk
    split
    · next h =>
        exact forIn_range_set!_get_lt0 (ih2 + 1) 16 (fun i => Y[i]!) zero16
          (by simp [zero16]) (by omega) k h
    · next h =>
        rw [forIn_range_set!_get_ge (ih2 + 1) (fun i => Y[i]!) zero16 k (by omega),
          getElem!_pos (zero16 : Block) k (by simp [zero16]; omega)]
        simp [zero16]
  have hcopysize : ∀ Y : Block, (forIn (List.range' 0 (ih2 + 1)) zero16
      (fun i acc => ForInStep.yield (acc.set! i Y[i]!)) : Id Block).run.size = 16 :=
    fun Y => (forIn_set!_size (List.range' 0 (ih2 + 1)) id (fun i => Y[i]!) zero16).trans
      (by simp [zero16])
  have hbuf1 : ∀ k, k < 16 →
      (((forIn (List.range' 0 (ih2 + 1)) zero16
          (fun i acc => ForInStep.yield (acc.set! i X[i]!)) : Id Block).run).set! ih2
          ((((forIn (List.range' 0 (ih2 + 1)) zero16
            (fun i acc => ForInStep.yield (acc.set! i X[i]!)) : Id Block).run)[ih2]! &&&
            mask) ||| pad))[k]!
        = (((forIn (List.range' 0 (ih2 + 1)) zero16
          (fun i acc => ForInStep.yield (acc.set! i X'[i]!)) : Id Block).run).set! ih2
          ((((forIn (List.range' 0 (ih2 + 1)) zero16
            (fun i acc => ForInStep.yield (acc.set! i X'[i]!)) : Id Block).run)[ih2]! &&&
            mask) ||| pad))[k]! := by
    intro k hk
    by_cases hkeq : k = ih2
    · rw [hkeq,
        Array.getElem!_set!_self _ _ _ (by rw [hcopysize]; omega),
        Array.getElem!_set!_self _ _ _ (by rw [hcopysize]; omega),
        hcopy X ih2 (by omega), hcopy X' ih2 (by omega), if_pos (by omega), if_pos (by omega),
        hmask]
    · rw [Array.getElem!_set!_ne _ _ _ _ (Ne.symm hkeq), Array.getElem!_set!_ne _ _ _ _ (Ne.symm hkeq),
        hcopy X k hk, hcopy X' k hk]
      split
      · next h => exact hpre k (by omega)
      · rfl
  have hbuf1eq : (((forIn (List.range' 0 (ih2 + 1)) zero16
        (fun i acc => ForInStep.yield (acc.set! i X[i]!)) : Id Block).run).set! ih2
        ((((forIn (List.range' 0 (ih2 + 1)) zero16
          (fun i acc => ForInStep.yield (acc.set! i X[i]!)) : Id Block).run)[ih2]! &&&
          mask) ||| pad))
      = (((forIn (List.range' 0 (ih2 + 1)) zero16
        (fun i acc => ForInStep.yield (acc.set! i X'[i]!)) : Id Block).run).set! ih2
        ((((forIn (List.range' 0 (ih2 + 1)) zero16
          (fun i acc => ForInStep.yield (acc.set! i X'[i]!)) : Id Block).run)[ih2]! &&&
          mask) ||| pad)) :=
    block_ext_get! (by rw [Array.size_set!]; exact hcopysize X)
      (by rw [Array.size_set!]; exact hcopysize X') hbuf1
  unfold mkBuf
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, Id.run, pure, bind]
  exact congrArg (fun b : Block => (xor16 b delta).set! 15 ((xor16 b delta)[15]! ^^^ ctr)) hbuf1eq

/-- `G_real`'s congruence under `PrefixEqB`, the fact `mkBuf`'s `0xf0`-masked boundary needs: a
plain `PrefixEq` on `X`/`X'` below `half`, as `G_real_congr` uses, is too strong to hold for the
odd-length ciphertext/plaintext byte relationships this file establishes (only agreement up to
`mask`, at the boundary, ever holds there) — but it's also more than `mkBuf` actually needs, since
position `ih2` is immediately overwritten by the mask/pad step regardless of what was read back. -/
theorem G_real_congrB (e : EState) (delta : Block) (ih2 i0 : Nat) (hih2 : ih2 < 16) (mask pad : UInt8)
    (j : Int) (X X' : Block) (h : PrefixEqB ih2 mask X X') :
    G_real e delta (ih2 + 1) ih2 i0 mask pad j X = G_real e delta (ih2 + 1) ih2 i0 mask pad j X' := by
  unfold G_real
  obtain ⟨hpre, hb⟩ := h
  rw [mkBuf_congr_boundary ih2 hih2 mask pad delta X X' hpre hb]

/-! ## `aezTiny`'s merge/demerge: the odd-length case -/

/-- `aezTiny`'s merge step for odd-length input, with no final tweak: bytes `< inBytes / 2` are a
plain copy of `R`; byte `inBytes / 2` and bytes `> inBytes / 2` are built by shifting adjacent
bytes' nibbles together, packing `half = inBytes / 2 + 1` bytes of `L` (plus a borrowed upper
nibble from `R`) into `half` output bytes. Literally `aezTiny`'s own construction, skipping the
`d = 0 ∧ inBytes < 16` output tweak. -/
def mergeOdd (inBytes : Nat) (L R : Block) : ByteArray := Id.run do
  let mut buf : Array UInt8 := Array.replicate inBytes 0
  for k in [0:inBytes / 2] do buf := buf.set! k (R[k]!)
  for k in [0:(inBytes + 1) / 2] do buf := buf.set! (inBytes / 2 + k) (L[k]!)
  let orig := buf
  for k in [inBytes / 2 + 1 : inBytes] do
    buf := buf.set! k ((orig[k]! >>> 4) ||| (orig[k - 1]! <<< 4))
  buf := buf.set! (inBytes / 2) ((L[0]! >>> 4) ||| (R[inBytes / 2]! &&& 0xf0))
  return ⟨buf⟩

theorem aezTiny_eq_mergeOdd (e : EState) (delta : Block) (inArr : ByteArray) (d : Nat)
    (hodd : inArr.size % 2 = 1) (hnotweak : ¬(inArr.size < 16 ∧ d == 0)) :
    aezTiny e delta inArr d
      = mergeOdd inArr.size
          (aezTinyLR e delta inArr d (aezTinyParams inArr.size).2 (aezTinyParams inArr.size).1).1
          (aezTinyLR e delta inArr d (aezTinyParams inArr.size).2 (aezTinyParams inArr.size).1).2 := by
  unfold aezTiny mergeOdd
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Id.run, pure, bind]
  have hodd' : (inArr.size % 2 == 1) = true := by simp [hodd]
  simp only [hodd', if_true]
  have hnotweak2 : inArr.size ≥ 16 ∨ d ≠ 0 := by
    rcases Nat.lt_or_ge inArr.size 16 with h | h
    · right; intro hd; exact hnotweak ⟨h, by simp [hd]⟩
    · left; exact h
  have hnotweak' : (decide (inArr.size < 16) && d == 0) = false := by
    rcases hnotweak2 with h | h
    · simp [Nat.not_lt.mpr h]
    · simp [h]
  simp only [hnotweak', Bool.false_eq_true, if_false]

theorem mergeOdd_size (inBytes : Nat) (L R : Block) : (mergeOdd inBytes L R).size = inBytes := by
  unfold mergeOdd
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Id.run, pure, bind, forIn_set!_size,
    Array.size_replicate, byteArray_mk_size, Array.size_set!]

/-- Like `forIn_range_set!_get_lt0`, but for a `List.range'` starting anywhere (`s`, not just `0`)
and with the loop body indexing directly by the range value (no separate offset addition) —
matches `aezTiny`'s `for k in [inBytes/2+1 : inBytes] do ...` shape directly. -/
private theorem forIn_range'_set!_get_in (s n sz : Nat) (g : Nat → UInt8) (init : Array UInt8)
    (hsize : init.size = sz) (hbound : s + n ≤ sz) :
    ∀ k, s ≤ k → k < s + n →
      (forIn (List.range' s n) init (fun i acc => ForInStep.yield (acc.set! i (g i))) :
        Id (Array UInt8)).run[k]! = g k := by
  induction n generalizing init with
  | zero => intro k hk1 hk2; omega
  | succ n ih =>
    intro k hk1 hk2
    rw [List.range'_1_concat, forIn_append]
    simp only [List.forIn_cons, List.forIn_nil, bind, pure, Id.run, Nat.zero_add]
    by_cases hk3 : k = s + n
    · subst hk3
      rw [Array.getElem!_set!_self _ _ _ (by rw [forIn_set!_size]; omega)]
    · rw [Array.getElem!_set!_ne _ _ _ _ (Ne.symm hk3)]
      exact ih init hsize (by omega) k hk1 (by omega)

/-- The complement of `forIn_range'_set!_get_in`: positions outside `[s, s + n)` are untouched. -/
private theorem forIn_range'_set!_get_out (s n : Nat) (g : Nat → UInt8) (init : Array UInt8)
    (k : Nat) (hk : k < s ∨ s + n ≤ k) :
    (forIn (List.range' s n) init (fun i acc => ForInStep.yield (acc.set! i (g i))) :
      Id (Array UInt8)).run[k]! = init[k]! := by
  induction n generalizing init with
  | zero => simp
  | succ n ih =>
    rw [List.range'_1_concat, forIn_append]
    simp only [List.forIn_cons, List.forIn_nil, bind, pure, Id.run, Nat.zero_add]
    rw [Array.getElem!_set!_ne _ _ _ _ (by omega)]
    exact ih init (by omega)

theorem mergeOdd_get_left (inBytes : Nat) (hodd : inBytes % 2 = 1) (L R : Block) (k : Nat)
    (hk : k < inBytes / 2) : (mergeOdd inBytes L R).get! k = R[k]! := by
  show (mergeOdd inBytes L R).data[k]! = R[k]!
  unfold mergeOdd
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, Id.run, pure, bind]
  rw [Array.getElem!_set!_ne _ _ _ _ (by omega)]
  refine Eq.trans ?_ (forIn_range_set!_get_lt0 (inBytes / 2) inBytes (fun i => R[i]!)
    (Array.replicate inBytes 0) (by simp) (by omega) k hk)
  refine (forIn_range'_set!_get_out (inBytes / 2 + 1) (inBytes - (inBytes / 2 + 1)) _ _ k
    (Or.inl (by omega))).trans ?_
  exact forIn_range_set!_get_unaffected ((inBytes + 1) / 2) (inBytes / 2) (fun i => L[i]!)
    (forIn (List.range' 0 (inBytes / 2)) (Array.replicate inBytes 0)
      (fun i acc => ForInStep.yield (acc.set! i R[i]!)) : Id (Array UInt8)) k hk

/-- The boundary byte: combines `L`'s first byte's upper nibble with `R`'s own boundary byte's
upper nibble (already masked to `0xf0` by the round function, but re-masked here regardless). -/
theorem mergeOdd_get_mid (inBytes : Nat) (hodd : inBytes % 2 = 1) (L R : Block) :
    (mergeOdd inBytes L R).get! (inBytes / 2) = (L[0]! >>> 4) ||| (R[inBytes / 2]! &&& 0xf0) := by
  show (mergeOdd inBytes L R).data[inBytes / 2]! = (L[0]! >>> 4) ||| (R[inBytes / 2]! &&& 0xf0)
  unfold mergeOdd
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, Id.run, pure, bind]
  exact Array.getElem!_set!_self _ _ _
    (by simp only [forIn_set!_size, Array.size_replicate]; omega)

/-- Bytes above the boundary: adjacent bytes of `L`, nibble-shifted together. Phrased with the
position as `inBytes / 2 + k` directly (matching `forIn_range_set!_get_lt`'s own `idxOffset + k`
shape), rather than requiring the caller to reconstruct `k` from a general position: this is the
same trick `mergeEven_get_right` already uses, and it's what lets the proof avoid ever needing an
`omega`-driven re-indexing bridge under a `GetElem`/`Id.run` mismatch. -/
theorem mergeOdd_get_upper (inBytes : Nat) (hodd : inBytes % 2 = 1) (L R : Block) (k : Nat)
    (hk1 : 1 ≤ k) (hk2 : k ≤ inBytes / 2) :
    (mergeOdd inBytes L R).get! (inBytes / 2 + k) = (L[k]! >>> 4) ||| (L[k - 1]! <<< 4) := by
  show (mergeOdd inBytes L R).data[inBytes / 2 + k]! = (L[k]! >>> 4) ||| (L[k - 1]! <<< 4)
  unfold mergeOdd
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, Id.run, pure, bind]
  rw [Array.getElem!_set!_ne _ _ _ _ (by omega)]
  refine (forIn_range'_set!_get_in (inBytes / 2 + 1) (inBytes - (inBytes / 2 + 1)) inBytes _ _
      (by simp only [forIn_set!_size, Array.size_replicate]) (by omega) (inBytes / 2 + k)
      (by omega) (by omega)).trans ?_
  rw [show inBytes / 2 + k - 1 = inBytes / 2 + (k - 1) from by omega]
  exact (congrArg (· >>> (4 : UInt8))
      (forIn_range_set!_get_lt ((inBytes + 1) / 2) (inBytes / 2) inBytes (fun i => L[i]!)
        (forIn (List.range' 0 (inBytes / 2)) (Array.replicate inBytes 0)
          (fun i acc => ForInStep.yield (acc.set! i R[i]!)) : Id (Array UInt8))
        (by simp only [forIn_set!_size, Array.size_replicate]) (by omega) k (by omega))) ▸
    (congrArg (· <<< (4 : UInt8))
      (forIn_range_set!_get_lt ((inBytes + 1) / 2) (inBytes / 2) inBytes (fun i => L[i]!)
        (forIn (List.range' 0 (inBytes / 2)) (Array.replicate inBytes 0)
          (fun i acc => ForInStep.yield (acc.set! i R[i]!)) : Id (Array UInt8))
        (by simp only [forIn_set!_size, Array.size_replicate]) (by omega) (k - 1) (by omega))) ▸
    rfl

end CryptWalker.Sphinx.Crypto.AEZ

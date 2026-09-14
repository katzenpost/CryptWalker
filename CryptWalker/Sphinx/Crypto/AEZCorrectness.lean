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

end CryptWalker.Sphinx.Crypto.AEZ
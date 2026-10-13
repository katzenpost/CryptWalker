/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Cipher.AES
import CryptWalker.WideBlockCipher.WideBlockCipher

namespace CryptWalker.WideBlockCipher.AEZ

open CryptWalker.Cipher.AES (subBytes shiftRows mixColumns)
open CryptWalker.WideBlockCipher (WideBlockCipher)

/-! # AEZ v5 as a strong pseudorandom permutation

AEZ with `tau = 0`, no associated data, a 48-byte extracted key and a 16-byte nonce: a
length-preserving SPRP with no authentication tag. Key extraction, associated-data hashing and
`aezPRF` are omitted. -/

abbrev Block := Array UInt8 -- 16 bytes; not tracked in the type

def zero16 : Block := Array.replicate 16 0

def xor16 (a b : Block) : Block := Array.ofFn fun i : Fin 16 => a[i.val]! ^^^ b[i.val]!

private def xor4 (a b c d : Block) : Block :=
  Array.ofFn fun i : Fin 16 => a[i.val]! ^^^ b[i.val]! ^^^ c[i.val]! ^^^ d[i.val]!

@[simp] private theorem xor16_size (a b : Block) : (xor16 a b).size = 16 := by simp [xor16]

@[simp] private theorem xor4_size (a b c d : Block) : (xor4 a b c d).size = 16 := by simp [xor4]

@[simp] private theorem shiftRows_size (s : Array UInt8) : (shiftRows s).size = 16 := by
  simp [shiftRows]

@[simp] private theorem mixColumns_size (s : Array UInt8) : (mixColumns s).size = 16 := by
  simp [mixColumns]

/-- Doubling in GF(2¹²⁸) modulo `x¹²⁸+x⁷+x²+x+1`, big-endian. -/
def doubleBlock (p : Block) : Block := Id.run do
  let mut out : Block := zero16
  for i in [0:15] do
    out := out.set! i ((p[i]! <<< 1) ||| (p[i+1]! >>> 7))
  let top := p[0]! >>> 7
  out := out.set! 15 ((p[15]! <<< 1) ^^^ (if top == 1 then (135 : UInt8) else 0))
  return out

/-! ## The round function

AES4/AES10 whiten the input with the call-site `j`,`i`,`l` blocks, then apply 4 or 10 full AES
rounds under a fixed schedule derived from the key. -/

private def aesRound (s rk : Block) : Block := xor16 (mixColumns (shiftRows (subBytes s))) rk

private def roundsApply (s : Block) (schedule : List Block) : Block := schedule.foldl aesRound s

@[simp] private theorem aesRound_size (s rk : Block) : (aesRound s rk).size = 16 := by
  simp [aesRound]

/-- A nonempty schedule always produces a 16-byte block. -/
private theorem foldl_aesRound_size_or_eq (l : List Block) (s : Block) :
    (l.foldl aesRound s).size = 16 ∨ (l = [] ∧ (l.foldl aesRound s).size = s.size) := by
  induction l generalizing s with
  | nil => right; exact ⟨rfl, rfl⟩
  | cons hd tl ih =>
    left
    rw [List.foldl_cons]
    rcases ih (aesRound s hd) with h | ⟨-, h⟩
    · exact h
    · rw [h]; simp

private theorem foldl_aesRound_size {l : List Block} (s : Block) (h : l ≠ []) :
    (l.foldl aesRound s).size = 16 := by
  rcases foldl_aesRound_size_or_eq l s with h' | ⟨hl, -⟩
  · exact h'
  · exact absurd hl h

private theorem roundsApply_size {s : Block} {l : List Block} (h : l ≠ []) :
    (roundsApply s l).size = 16 :=
  foldl_aesRound_size s h

structure EState where
  I0 : Block
  I1 : Block
  J0 : Block
  J1 : Block
  J2 : Block
  L : Array Block -- L[0..7], L[0] = zero
  aes4Sched  : List Block -- [J0, I0, L1, zero], 4 entries
  aes10Sched : List Block -- [I0,J0,L1] repeated 3 times, then [I0], 10 entries

/-- `AES4(j, i, l; src)`: whiten with the call-site `j,i,l`, then 4 fixed-schedule rounds. -/
def aes4 (e : EState) (j i l src : Block) : Block := roundsApply (xor4 j i l src) e.aes4Sched

/-- `AES10(l; src)`: whiten with the call-site `l` alone, then 10 fixed-schedule rounds. -/
def aes10 (e : EState) (l src : Block) : Block := roundsApply (xor16 src l) e.aes10Sched

private theorem aes4_size {e : EState} (h : e.aes4Sched ≠ []) (j i l src : Block) :
    (aes4 e j i l src).size = 16 :=
  roundsApply_size h

private theorem aes10_size {e : EState} (h : e.aes10Sched ≠ []) (l src : Block) :
    (aes10 e l src).size = 16 :=
  roundsApply_size h

/-- `aes4` always produces a 16-byte block. -/
@[simp] theorem aes4_size' (e : EState) (j i l src : Block) : (aes4 e j i l src).size = 16 := by
  unfold aes4 roundsApply
  rcases foldl_aesRound_size_or_eq e.aes4Sched (xor4 j i l src) with h | ⟨-, h⟩
  · exact h
  · rw [h]; exact xor4_size j i l src

/-- `aes10` always produces a 16-byte block. -/
@[simp] private theorem aes10_size' (e : EState) (l src : Block) : (aes10 e l src).size = 16 := by
  unfold aes10 roundsApply
  rcases foldl_aesRound_size_or_eq e.aes10Sched (xor16 src l) with h | ⟨-, h⟩
  · exact h
  · rw [h]; exact xor16_size src l

/-- The key schedule, from a 48-byte extracted key. -/
def initState (key48 : Block) : EState :=
  let i0 := key48.extract 0 16
  let j0 := key48.extract 16 32
  let l1 := key48.extract 32 48
  let i1 := doubleBlock i0
  let j1 := doubleBlock j0
  let j2 := doubleBlock j1
  let l0 := zero16
  let l2 := doubleBlock l1
  let l3 := xor16 l2 l1
  let l4 := doubleBlock l2
  let l5 := xor16 l4 l1
  let l6 := doubleBlock l3
  let l7 := xor16 l6 l1
  { I0 := i0, I1 := i1, J0 := j0, J1 := j1, J2 := j2
    L := #[l0, l1, l2, l3, l4, l5, l6, l7]
    aes4Sched := [j0, i0, l1, l0]
    aes10Sched := [i0, j0, l1, i0, j0, l1, i0, j0, l1, i0] }

@[simp] private theorem initState_aes4Sched_ne_nil (key48 : Block) :
    (initState key48).aes4Sched ≠ [] := by simp [initState]

@[simp] private theorem initState_aes10Sched_ne_nil (key48 : Block) :
    (initState key48).aes10Sched ≠ [] := by simp [initState]

/-! ## `aezHash` with `tau = 0` and no associated data -/

private def oneZeroPad (src : Block) (sz : Nat) : Block :=
  Array.ofFn fun i : Fin 16 => if i.val < sz then src[i.val]! else if i.val == sz then 0x80 else 0

@[simp] private theorem oneZeroPad_size (src : Block) (sz : Nat) : (oneZeroPad src sz).size = 16 := by
  simp [oneZeroPad]

def aezHashNoAD (e : EState) (nonce : ByteArray) : Block := Id.run do
  -- Hash of tau = 0: sixteen zero bytes; E(3,1).
  let j01 := xor16 e.J0 e.J1
  let mut sum := aes4 e j01 e.I1 (e.L[1]!) zero16
  -- Hash the nonce, one block at a time.
  let mut i : Nat := 1
  let mut ii := e.I1
  let mut off : Nat := 0
  let nLen := nonce.size
  while off + 16 ≤ nLen do
    let blk : Block := (nonce.extract off (off + 16)).data
    sum := xor16 sum (aes4 e e.J2 ii (e.L[i % 8]!) blk)
    off := off + 16
    if i % 8 == 0 then ii := doubleBlock ii
    i := i + 1
  -- Final fragment, or the empty nonce.
  if off < nLen || nLen == 0 then
    let frag : Block := oneZeroPad (nonce.extract off nLen).data (nLen - off)
    sum := xor16 sum (aes4 e e.J2 e.I0 (e.L[0]!) frag)
  return sum

/-- Folding `.set!` calls never changes an array's size. -/
private theorem foldl_set!_size {α} (idx : Nat → Nat) (f : Nat → α) (l : List Nat) (a : Array α) :
    (l.foldl (fun acc i => acc.set! (idx i) (f i)) a).size = a.size := by
  induction l generalizing a with
  | nil => rfl
  | cons hd tl ih => rw [List.foldl_cons, ih, Array.size_set!]

/-- A fold that replaces both blocks of a pair with 16-byte values keeps both at 16 bytes, given
16-byte starting blocks. -/
private theorem foldl_pair16_size {α β} (l : List β) (step : Block × Block × α → β → Block × Block × α)
    (hstep1 : ∀ acc x, (step acc x).1.size = 16) (hstep2 : ∀ acc x, (step acc x).2.1.size = 16)
    (a : Block × Block × α) (ha1 : a.1.size = 16) (ha2 : a.2.1.size = 16) :
    (l.foldl step a).1.size = 16 ∧ (l.foldl step a).2.1.size = 16 := by
  induction l generalizing a with
  | nil => exact ⟨ha1, ha2⟩
  | cons hd tl ih => rw [List.foldl_cons]; exact ih (step a hd) (hstep1 a hd) (hstep2 a hd)

/-- A fold whose output buffer grows by 32 bytes per step grows by `32 * l.length` in total. -/
private theorem foldl_append32_size {α γ} (l : List γ) (step : α → γ → α) (out : α → ByteArray)
    (hstep : ∀ acc x, (out (step acc x)).size = (out acc).size + 32) (a : α) :
    (out (l.foldl step a)).size = (out a).size + 32 * l.length := by
  induction l generalizing a with
  | nil => simp
  | cons hd tl ih =>
    rw [List.foldl_cons, ih (step a hd), hstep, List.length_cons]
    omega

/-- Pushes `pure` out of an `if` so `List.forIn_pure_yield_eq_foldl` applies. -/
private theorem ite_pure_yield {α} (c : Prop) [Decidable c] (a b : α) :
    (if c then (pure (ForInStep.yield a) : Id (ForInStep α)) else pure (ForInStep.yield b)) =
      pure (ForInStep.yield (if c then a else b)) := by
  split <;> rfl

/-! ## `aezTiny`: inputs shorter than 32 bytes -/

/-- `aezTiny`'s `(i0, rounds)` parameters. Separate so size proofs need not case-split on them. -/
def aezTinyParams (inBytes : Nat) : Nat × Nat :=
  if inBytes == 1 then (7, 24)
  else if inBytes == 2 then (7, 16)
  else if inBytes < 16 then (7, 10)
  else (6, 8)

/-- The round buffer of `aezTinyLR`: `X`'s first `half` bytes, `mask`/`pad` at `ih2`, XOR
`delta`, then the counter byte XORed into the last position. -/
def mkBuf (half ih2 : Nat) (mask pad : UInt8) (delta : Block) (X : Block) (ctr : UInt8) : Block :=
  Id.run do
    let mut buf : Block := zero16
    for k in [0:half] do buf := buf.set! k (X[k]!)
    buf := buf.set! ih2 ((buf[ih2]! &&& mask) ||| pad)
    buf := xor16 buf delta
    buf := buf.set! 15 (buf[15]! ^^^ ctr)
    return buf

/-- `aezTiny`'s Feistel rounds, producing `(L, R)`. Kept separate to keep proof terms small. -/
def aezTinyLR (e : EState) (delta : Block) (inArr : ByteArray) (d rounds i0 : Nat) :
    Block × Block := Id.run do
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
  let mut j : Int := 0
  let mut step : Int := 1
  if d ≠ 0 then
    if inBytes < 16 then
      let mut buf : Block := zero16
      for k in [0:inBytes] do buf := buf.set! k (inArr.get! k)
      buf := buf.set! 0 (buf[0]! ||| 0x80)
      buf := xor16 delta buf
      let tmp := aes4 e zero16 e.I1 (e.L[3]!) buf
      L := L.set! 0 (L[0]! ^^^ (tmp[0]! &&& 0x80))
    j := (rounds : Int) - 1
    step := -1
  for _ in [0:rounds / 2] do
    let buf1 := mkBuf half (inBytes / 2) mask pad delta R (UInt8.ofNat (j % 256).toNat)
    let tmp1 := aes4 e zero16 e.I1 (e.L[i0]!) buf1
    L := xor16 L tmp1

    let buf2 := mkBuf half (inBytes / 2) mask pad delta L
      (UInt8.ofNat (((j + step) % 256 + 256) % 256).toNat)
    let tmp2 := aes4 e zero16 e.I1 (e.L[i0]!) buf2
    R := xor16 R tmp2

    j := j + 2 * step
  return (L, R)

/-- `d = 0`: encipher; `d = 1`: decipher. -/
def aezTiny (e : EState) (delta : Block) (inArr : ByteArray) (d : Nat) : ByteArray := Id.run do
  let inBytes := inArr.size
  let (i0, rounds) := aezTinyParams inBytes
  let half := (inBytes + 1) / 2
  let (L, R) := aezTinyLR e delta inArr d rounds i0

  -- 32 bytes, since `inBytes` can be up to 31.
  let mut buf : Array UInt8 := Array.replicate inBytes 0
  for k in [0:inBytes / 2] do buf := buf.set! k (R[k]!)
  for k in [0:half] do buf := buf.set! (inBytes / 2 + k) (L[k]!)
  if inBytes % 2 == 1 then
    let orig := buf
    for k in [inBytes / 2 + 1 : inBytes] do
      -- Each `k` reads only from `orig`, so iteration order does not matter.
      buf := buf.set! k ((orig[k]! >>> 4) ||| (orig[k-1]! <<< 4))
    buf := buf.set! (inBytes / 2) ((L[0]! >>> 4) ||| (R[inBytes / 2]! &&& 0xf0))
  let mut out : ByteArray := ⟨buf⟩
  if inBytes < 16 && d == 0 then
    let mut buf2 : Block := zero16
    for k in [0:inBytes] do buf2 := buf2.set! k (out.get! k)
    buf2 := buf2.set! 0 (buf2[0]! ||| 0x80)
    buf2 := xor16 delta buf2
    let tmp := aes4 e zero16 e.I1 (e.L[3]!) buf2
    out := out.set! 0 (out.get! 0 ^^^ (tmp[0]! &&& 0x80))
  return out

set_option maxHeartbeats 8000000 in
private theorem aezTinyLR_size (e : EState) (delta : Block) (inArr : ByteArray) (d rounds i0 : Nat) :
    (aezTinyLR e delta inArr d rounds i0).1.size = 16 ∧
      (aezTinyLR e delta inArr d rounds i0).2.size = 16 := by
  unfold aezTinyLR
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl, pure_bind]
  repeat' split
  all_goals
    simp only [Id.run, pure, zero16]
  all_goals
    exact foldl_pair16_size _ _ (fun _ _ => xor16_size ..) (fun _ _ => xor16_size ..) _
      (by simp only [Array.size_replicate, foldl_set!_size, Array.size_set!])
      (by simp only [Array.size_replicate, foldl_set!_size, Array.size_set!])

set_option maxHeartbeats 8000000 in
theorem aezTiny_size (e : EState) (delta : Block) (inArr : ByteArray) (d : Nat) :
    (aezTiny e delta inArr d).size = inArr.size := by
  unfold aezTiny
  obtain ⟨hL, hR⟩ := aezTinyLR_size e delta inArr d (aezTinyParams inArr.size).2
    (aezTinyParams inArr.size).1
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl, pure_bind]
  repeat' split
  all_goals
    simp only [Id.run, pure, ByteArray.size, ByteArray.set!, ByteArray.get!, zero16,
      foldl_set!_size, Array.size_replicate, Array.size_set!]

/-! ## The `aezTiny` Feistel ladder inverts

`n` forward double-rounds followed by `n` backward double-rounds on the swapped pair is the
identity, for any round function. -/

theorem xor16_get! {i : Nat} (hi : i < 16) (a b : Block) :
    (xor16 a b)[i]! = a[i]! ^^^ b[i]! := by
  simp only [xor16, getElem!_pos, Array.getElem_ofFn, Array.size_ofFn, hi]

/-- XORing the same block twice is the identity. -/
theorem xor16_cancel {a : Block} (b : Block) (ha : a.size = 16) :
    xor16 (xor16 a b) b = a := by
  apply Array.ext (by rw [xor16_size, ha])
  intro i hi1 hi2
  have hi16 : i < 16 := by rw [xor16_size] at hi1; exact hi1
  rw [← getElem!_pos (xor16 (xor16 a b) b) i hi1, ← getElem!_pos a i hi2,
    xor16_get! hi16, xor16_get! hi16, UInt8.xor_assoc, UInt8.xor_self, UInt8.xor_zero]

/-- One forward double-round at iteration `k`, under counters `2k` and `2k+1`. -/
def ladderFwdStep (F : Nat → Block → Block) (k : Nat) (LR : Block × Block) : Block × Block :=
  let L' := xor16 LR.1 (F (2*k) LR.2)
  let R' := xor16 LR.2 (F (2*k+1) L')
  (L', R')

/-- One backward double-round under counters `s` and `s-1`. -/
def ladderBwdStep (F : Nat → Block → Block) (s : Nat) (LR : Block × Block) : Block × Block :=
  let L' := xor16 LR.1 (F s LR.2)
  let R' := xor16 LR.2 (F (s-1) L')
  (L', R')

/-- `n` forward double-rounds, counters ascending from `0`. -/
def ladderFwdN (F : Nat → Block → Block) : Nat → Block × Block → Block × Block
  | 0, LR => LR
  | n+1, LR => ladderFwdStep F n (ladderFwdN F n LR)

/-- `n` backward double-rounds, counters descending from `2n-1`. -/
def ladderBwdN (F : Nat → Block → Block) : Nat → Block × Block → Block × Block
  | 0, LR => LR
  | n+1, LR => ladderBwdN F n (ladderBwdStep F (2*n+1) LR)

theorem ladderFwdN_size1 (F : Nat → Block → Block) (n : Nat) (L R : Block)
    (hL : L.size = 16) : (ladderFwdN F n (L, R)).1.size = 16 := by
  cases n with
  | zero => exact hL
  | succ n => simp [ladderFwdN, ladderFwdStep]

theorem ladderFwdN_size2 (F : Nat → Block → Block) (n : Nat) (L R : Block)
    (hR : R.size = 16) : (ladderFwdN F n (L, R)).2.size = 16 := by
  cases n with
  | zero => exact hR
  | succ n => simp [ladderFwdN, ladderFwdStep]

/-- `n` forward double-rounds, a swap, then `n` backward double-rounds return the swapped input,
for any `F`. -/
theorem ladderBwdN_ladderFwdN_swap (F : Nat → Block → Block) (n : Nat) (L R : Block)
    (hL : L.size = 16) (hR : R.size = 16) :
    ladderBwdN F n (ladderFwdN F n (L, R)).swap = (R, L) := by
  induction n generalizing L R with
  | zero => rfl
  | succ n ih =>
    obtain ⟨Ln, Rn, hLR⟩ : ∃ Ln Rn, ladderFwdN F n (L, R) = (Ln, Rn) := ⟨_, _, rfl⟩
    have hLn : Ln.size = 16 := by
      have h := ladderFwdN_size1 F n L R hL; rw [hLR] at h; exact h
    have hRn : Rn.size = 16 := by
      have h := ladderFwdN_size2 F n L R hR; rw [hLR] at h; exact h
    show ladderBwdN F n (ladderBwdStep F (2*n+1)
        (ladderFwdStep F n (ladderFwdN F n (L, R))).swap) = (R, L)
    rw [hLR]
    show ladderBwdN F n (ladderBwdStep F (2*n+1) (ladderFwdStep F n (Ln, Rn)).swap) = (R, L)
    have key : ladderBwdStep F (2*n+1) (ladderFwdStep F n (Ln, Rn)).swap = (Rn, Ln) := by
      have e : 2*n+1-1 = 2*n := by omega
      simp only [ladderFwdStep, ladderBwdStep, Prod.swap, e]
      rw [xor16_cancel _ hRn, xor16_cancel _ hLn]
    rw [key]
    have hih := ih L R hL hR
    rw [hLR] at hih
    exact hih

/-! ## `aezCore`: inputs of 32 bytes or more

The two passes process all 32-byte chunks except the final chunk and any shorter fragment, which
are finished separately. -/

private def chunk32 (b : ByteArray) (k : Nat) : Block := (b.extract (32*k) (32*k+16)).data
private def chunk32' (b : ByteArray) (k : Nat) : Block := (b.extract (32*k+16) (32*k+32)).data

/-- Pass 1: returns `(outPrefix, X)`. `nChunks = initialBytes / 32`. -/
private def pass1 (e : EState) (inArr : ByteArray) (nChunks : Nat) : ByteArray × Block := Id.run do
  let mut out : ByteArray := ByteArray.empty
  let mut x : Block := zero16
  let mut ii := e.I1
  for k in [0:nChunks] do
    let i := k + 1
    let inA := chunk32 inArr k
    let inB := chunk32' inArr k
    let tmp1 := aes4 e e.J0 ii (e.L[i % 8]!) inB
    let outA := xor16 inA tmp1
    let tmp2 := aes4 e zero16 e.I0 (e.L[0]!) outA
    let outB := xor16 inB tmp2
    x := xor16 x outB
    out := out ++ (⟨outA⟩ : ByteArray) ++ (⟨outB⟩ : ByteArray)
    if i % 8 == 0 then ii := doubleBlock ii
  return (out, x)

set_option maxHeartbeats 800000 in
private theorem pass1_size (e : EState) (inArr : ByteArray) (nChunks : Nat) :
    (pass1 e inArr nChunks).1.size = 32 * nChunks := by
  unfold pass1
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, List.forIn_pure_yield_eq_foldl, pure_bind, ite_pure_yield]
  simp only [Id.run, pure]
  rw [show (32 * nChunks : Nat)
      = (ByteArray.empty : ByteArray).size + 32 * (List.range' 0 nChunks).length by
    simp [List.length_range']]
  exact foldl_append32_size _ _ Prod.fst
    (fun acc x => by
      split <;> simp only [ByteArray.size_append] <;> simp only [ByteArray.size, xor16_size] <;>
        omega) _

/-- Pass 2: returns `(outPrefix, Y)`, given `S` (fixed across all chunks) and pass 1's output
prefix to read `P1a`/`P1b` from. -/
private def pass2 (e : EState) (pass1Out : ByteArray) (s : Block) (nChunks : Nat) :
    ByteArray × Block := Id.run do
  let mut out : ByteArray := ByteArray.empty
  let mut y : Block := zero16
  let mut ii := e.I1
  for k in [0:nChunks] do
    let i := k + 1
    let p1a := chunk32 pass1Out k
    let p1b := chunk32' pass1Out k
    let tmp1 := aes4 e e.J1 ii (e.L[i % 8]!) s
    let a1 := xor16 p1a tmp1
    let b1 := xor16 p1b tmp1
    y := xor16 y a1
    let tmp2 := aes4 e zero16 e.I0 (e.L[0]!) b1
    let a2 := xor16 a1 tmp2
    let tmp3 := aes4 e e.J0 ii (e.L[i % 8]!) a2
    let b2 := xor16 b1 tmp3
    -- swap: final chunk is (b2, a2)
    out := out ++ (⟨b2⟩ : ByteArray) ++ (⟨a2⟩ : ByteArray)
    if i % 8 == 0 then ii := doubleBlock ii
  return (out, y)

set_option maxHeartbeats 800000 in
private theorem pass2_size (e : EState) (pass1Out : ByteArray) (s : Block) (nChunks : Nat) :
    (pass2 e pass1Out s nChunks).1.size = 32 * nChunks := by
  unfold pass2
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', Std.Legacy.Range.size, Nat.sub_zero,
    Nat.add_sub_cancel, Nat.div_one, List.forIn_pure_yield_eq_foldl, pure_bind, ite_pure_yield]
  simp only [Id.run, pure]
  rw [show (32 * nChunks : Nat)
      = (ByteArray.empty : ByteArray).size + 32 * (List.range' 0 nChunks).length by
    simp [List.length_range']]
  exact foldl_append32_size _ _ Prod.fst
    (fun acc x => by
      split <;> simp only [ByteArray.size_append] <;> simp only [ByteArray.size, xor16_size] <;>
        omega) _

def aezCore (e : EState) (delta : Block) (inArr : ByteArray) (d : Nat) : ByteArray := Id.run do
  let len := inArr.size
  let fragBytes := len % 32
  let initialBytes := len - fragBytes - 32
  let nChunks := initialBytes / 32

  -- Pass 1 (only when there is a >=64-byte prefix to process).
  let (pass1Out, x0) := if len ≥ 64 then pass1 e inArr nChunks else (ByteArray.empty, zero16)

  -- Finish X with the fragment.
  let frag := inArr.extract initialBytes (initialBytes + fragBytes)
  let mut x := x0
  if fragBytes ≥ 16 then
    let tmp1 := aes4 e zero16 e.I1 (e.L[4]!) (frag.extract 0 16).data
    x := xor16 x tmp1
    let tmp2 := aes4 e zero16 e.I1 (e.L[5]!) (oneZeroPad (frag.extract 16 fragBytes).data (fragBytes - 16))
    x := xor16 x tmp2
  else if fragBytes > 0 then
    let tmp := aes4 e zero16 e.I1 (e.L[4]!) (oneZeroPad frag.data fragBytes)
    x := xor16 x tmp

  -- Calculate S from the last 32 bytes.
  let lastA : Block := (inArr.extract (len - 32) (len - 16)).data
  let lastB : Block := (inArr.extract (len - 16) len).data
  let l1d := e.L[(1 + d) % 8]!
  let tmpS1 := aes4 e zero16 e.I1 l1d lastB
  let a : Block := xor4 x lastA delta tmpS1
  let tmpS2 := aes10 e l1d a
  let b : Block := xor16 lastB tmpS2
  let s : Block := xor16 a b

  -- Pass 2.
  let (pass2Out, y0) := if len ≥ 64 then pass2 e pass1Out s nChunks else (ByteArray.empty, zero16)

  -- Finish Y and finish encrypting the fragment.
  let mut y := y0
  let mut fragOut : ByteArray := ByteArray.empty
  if fragBytes ≥ 16 then
    let tmpA := aes10 e (e.L[4]!) s
    let outA : Block := xor16 (frag.extract 0 16).data tmpA
    let tmpYa := aes4 e zero16 e.I1 (e.L[4]!) outA
    y := xor16 y tmpYa
    let restLen := fragBytes - 16
    let tmpB := aes10 e (e.L[5]!) s
    let restOut : Array UInt8 :=
      Array.ofFn fun k : Fin restLen => (frag.extract 16 fragBytes).data[k.val]! ^^^ tmpB[k.val]!
    let tmpYb := aes4 e zero16 e.I1 (e.L[5]!) (oneZeroPad restOut restLen)
    y := xor16 y tmpYb
    fragOut := (⟨outA⟩ : ByteArray) ++ (⟨restOut⟩ : ByteArray)
  else if fragBytes > 0 then
    let tmpA := aes10 e (e.L[4]!) s
    let restOut : Array UInt8 :=
      Array.ofFn fun k : Fin fragBytes => frag.data[k.val]! ^^^ tmpA[k.val]!
    let tmpYa := aes4 e zero16 e.I1 (e.L[4]!) (oneZeroPad restOut fragBytes)
    y := xor16 y tmpYa
    fragOut := ⟨restOut⟩

  -- Finish the last two blocks.
  let l2d := e.L[(2 - d) % 8]!
  let tmpF1 := aes10 e l2d b
  let block0 : Block := xor16 a tmpF1
  let tmpF2 := aes4 e zero16 e.I1 l2d block0
  let block1 : Block := xor4 tmpF2 b delta y
  let lastTwo : ByteArray := (⟨block1⟩ : ByteArray) ++ (⟨block0⟩ : ByteArray)

  return pass2Out ++ fragOut ++ lastTwo

@[simp] private theorem ofFn_size {n} (f : Fin n → UInt8) : (Array.ofFn f).size = n := by simp

/-- `ByteArray.size` unfolding restricted to literal constructors, leaving variables' `.size`
alone. -/
@[simp] private theorem byteArray_mk_size (a : Array UInt8) : (⟨a⟩ : ByteArray).size = a.size := rfl

@[simp] private theorem byteArray_empty_size : (ByteArray.empty : ByteArray).size = 0 := rfl

set_option maxHeartbeats 1000000 in
theorem aezCore_size (e : EState) (delta : Block) (inArr : ByteArray) (d : Nat)
    (h : 32 ≤ inArr.size) : (aezCore e delta inArr d).size = inArr.size := by
  unfold aezCore
  simp only [Id.run, pure]
  by_cases h64 : inArr.size ≥ 64 <;>
    by_cases h16 : inArr.size % 32 ≥ 16 <;>
      by_cases hgt : inArr.size % 32 > 0 <;>
        simp only [h64, h16, hgt, if_true, if_false] <;>
        simp only [ByteArray.size_append] <;>
        (try simp only [pass2_size]) <;>
        simp only [byteArray_mk_size, byteArray_empty_size, xor16_size, xor4_size, ofFn_size] <;>
        omega

/-! ## Top-level dispatch -/

def encipher (e : EState) (delta : Block) (inArr : ByteArray) : ByteArray :=
  if inArr.size == 0 then ByteArray.empty
  else if inArr.size < 32 then aezTiny e delta inArr 0
  else aezCore e delta inArr 0

def decipher (e : EState) (delta : Block) (inArr : ByteArray) : ByteArray :=
  if inArr.size == 0 then ByteArray.empty
  else if inArr.size < 32 then aezTiny e delta inArr 1
  else aezCore e delta inArr 1

/-- SPRP encryption: 48-byte key, 16-byte IV. -/
def sprpEncrypt (key : Array UInt8) (iv : ByteArray) (msg : ByteArray) : ByteArray :=
  let e := initState key
  let delta := aezHashNoAD e iv
  encipher e delta msg

/-- SPRP decryption. With `tau = 0` there is no tag to check. -/
def sprpDecrypt (key : Array UInt8) (iv : ByteArray) (msg : ByteArray) : ByteArray :=
  let e := initState key
  let delta := aezHashNoAD e iv
  decipher e delta msg

/-! ## Length preservation -/

theorem encipher_size (e : EState) (delta : Block) (inArr : ByteArray) :
    (encipher e delta inArr).size = inArr.size := by
  unfold encipher
  split
  · next h =>
      have h0 : inArr.size = 0 := by simpa using h
      rw [h0]; rfl
  · split
    · next h1 h2 => exact aezTiny_size e delta inArr 0
    · next h1 h2 => exact aezCore_size e delta inArr 0 (by omega)

theorem decipher_size (e : EState) (delta : Block) (inArr : ByteArray) :
    (decipher e delta inArr).size = inArr.size := by
  unfold decipher
  split
  · next h =>
      have h0 : inArr.size = 0 := by simpa using h
      rw [h0]; rfl
  · split
    · next h1 h2 => exact aezTiny_size e delta inArr 1
    · next h1 h2 => exact aezCore_size e delta inArr 1 (by omega)

theorem sprpEncrypt_size (key : Array UInt8) (iv msg : ByteArray) :
    (sprpEncrypt key iv msg).size = msg.size := by
  unfold sprpEncrypt
  exact encipher_size _ _ _

theorem sprpDecrypt_size (key : Array UInt8) (iv msg : ByteArray) :
    (sprpDecrypt key iv msg).size = msg.size := by
  unfold sprpDecrypt
  exact decipher_size _ _ _

/-! ## AEZ, as a `WideBlockCipher` -/

/-- AEZ round trip. An unproven axiom: only the `aezTiny` ladder is proved above; checked
against `sprp_aez.json`. -/
axiom aez_roundTrip (key : Array UInt8) (iv msg : ByteArray) (h16 : 16 ≤ msg.size) :
    sprpDecrypt key iv (sprpEncrypt key iv msg) = msg

/-- AEZ as a `WideBlockCipher`. -/
def aez : WideBlockCipher where
  keySize := 48
  ivSize  := 16
  encrypt := sprpEncrypt
  decrypt := sprpDecrypt
  encrypt_size := sprpEncrypt_size
  decrypt_size := sprpDecrypt_size
  roundTrip := aez_roundTrip

end CryptWalker.WideBlockCipher.AEZ

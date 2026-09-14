/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Cipher.AES

namespace CryptWalker.Sphinx.Crypto.AEZ

open CryptWalker.Cipher.AES (subBytes shiftRows mixColumns)

/-! # AEZ v5, restricted to Sphinx's exact usage

`crypto.SPRPEncrypt`/`crypto.SPRPDecrypt` (`katzenpost/core/sphinx/internal/crypto/crypto.go`)
call `gitlab.com/yawning/aez.git`'s `Encrypt`/`Decrypt` with `additionalData = nil`, `tau = 0`,
a 48-byte key (`SPRPKeyLength`), and a 16-byte nonce (`SPRPIVLength`) — i.e. AEZ used in pure
SPRP mode: a length-preserving strong pseudorandom permutation, no AEZ-native authentication
tag, no associated data. This file ports exactly that usage, not general AEZ-AEAD:

* **No key extraction.** `aez.go`'s `extract` only hashes the key with BLAKE2b when it isn't
  already exactly the 48-byte "extracted key" size; Sphinx's `SPRPKeyLength` is 48, so that
  branch never fires here, and this file simply requires a 48-byte key.
* **No associated data.** The AD-hashing loop in `aezHash` (`for k, p := range ad`) is absent;
  Sphinx never passes AD.
* **No `aezPRF`.** It is only reachable when the plaintext is empty *and* `tau > 0`; with
  `tau = 0` the empty-plaintext case is simply an empty ciphertext, so `aezPRF` is unneeded.

Everything else — `doubleBlock`'s GF(2¹²⁸) doubling, the `eState` key schedule, `AES4`/`AES10`,
`aezHash`'s nonce-hashing loop, `aezTiny` and `aezCore` — is a direct, line-by-line port of the
upstream reference (`aez_ref.go`/`round_vartime.go`'s literal T-table-free round function, i.e.
plain SubBytes/ShiftRows/MixColumns/AddRoundKey composed `rounds` times with **no** initial
whitening beyond what `AES4`/`AES10`'s caller-supplied `j`,`i`,`l` XOR already provides, and
**no** skipped-MixColumns final round the way AES-256 proper has) — reusing `Cipher.AES`'s
`subBytes`/`shiftRows`/`mixColumns` round primitives, since AEZ's round function is built from
the same three steps, just under a different, fixed-length key schedule.

Deferred per the project's vectors-first pass: no laws are stated about this module. Checked
against `sprp_aez.json`, covering both the `aezTiny` (<32B) and `aezCore` (≥32B) code paths. -/

abbrev Block := Array UInt8 -- always length 16 here; not tracked in the type, matching this
                             -- module's Go original, which is not proof-carrying either.

-- Not `private`: `zero16`/`xor16` (plus `aezTinyParams`/`aezTinyLR` and the ladder section below)
-- are also needed from `AEZCorrectness.lean`, which reasons about `aezTinyLR`'s round-trip
-- correctness against this file's own definitions rather than restating them.
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

/-- GF(2¹²⁸) doubling: shift the 16-byte big-endian value left by one bit, reducing by the
primitive polynomial `x¹²⁸+x⁷+x²+x+1` (conditionally XOR `0x87` into the low byte) when the top
bit overflows. -/
def doubleBlock (p : Block) : Block := Id.run do
  let mut out : Block := zero16
  for i in [0:15] do
    out := out.set! i ((p[i]! <<< 1) ||| (p[i+1]! >>> 7))
  let top := p[0]! >>> 7
  out := out.set! 15 ((p[15]! <<< 1) ^^^ (if top == 1 then (135 : UInt8) else 0))
  return out

/-! ## The round function

Each AES4/AES10 call first whitens the input with the caller-supplied `j`,`i`,`l` blocks (which
vary by call site), then applies a *fixed* schedule of 4 or 10 rounds of
SubBytes→ShiftRows→MixColumns→AddRoundKey, keyed from the master extracted key's `1I`,`1J`,`1L`
(fixed for the whole `EState`, independent of the call site's `j`,`i`,`l`) — see
`round_vartime.go`'s `roundVartime.{AES4,AES10}`/`rounds`. -/

private def aesRound (s rk : Block) : Block := xor16 (mixColumns (shiftRows (subBytes s))) rk

private def roundsApply (s : Block) (schedule : List Block) : Block := schedule.foldl aesRound s

@[simp] private theorem aesRound_size (s rk : Block) : (aesRound s rk).size = 16 := by
  simp [aesRound]

/-- `roundsApply` "forgets" whatever size its starting block had after the first round, since
`aesRound`'s output is always 16 bytes regardless of its input — so as long as the schedule is
nonempty, the final size is 16 no matter what. Every schedule this file ever builds (`initState`'s
`aes4Sched`/`aes10Sched`) is a literal 4- or 10-element list, so the hypothesis is always
dischargeable by `simp`/`decide` at the call site. -/
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

/-- Unconditional version: `aes4`'s whitened input is already size 16 (via `xor4_size`), so the
result is size 16 whether or not `e.aes4Sched` is empty (an empty schedule just returns it as-is). -/
@[simp] theorem aes4_size' (e : EState) (j i l src : Block) : (aes4 e j i l src).size = 16 := by
  unfold aes4 roundsApply
  rcases foldl_aesRound_size_or_eq e.aes4Sched (xor4 j i l src) with h | ⟨-, h⟩
  · exact h
  · rw [h]; exact xor4_size j i l src

/-- Unconditional version: `aes10`'s whitened input is already size 16 (via `xor16_size`). -/
@[simp] private theorem aes10_size' (e : EState) (l src : Block) : (aes10 e l src).size = 16 := by
  unfold aes10 roundsApply
  rcases foldl_aesRound_size_or_eq e.aes10Sched (xor16 src l) with h | ⟨-, h⟩
  · exact h
  · rw [h]; exact xor16_size src l

/-- `eState.init`, restricted to an already-48-byte extracted key (see module doc). -/
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

/-! ## `aezHash`, restricted to no additional data

Still general over nonce length (the AD-hashing loop is what's dropped, not the nonce loop),
following `aez.go`'s `aezHash` with `ad = nil`, `tau = 0` (so the `tau`-derived leading block is
a hash of sixteen zero bytes). -/

private def oneZeroPad (src : Block) (sz : Nat) : Block :=
  Array.ofFn fun i : Fin 16 => if i.val < sz then src[i.val]! else if i.val == sz then 0x80 else 0

@[simp] private theorem oneZeroPad_size (src : Block) (sz : Nat) : (oneZeroPad src sz).size = 16 := by
  simp [oneZeroPad]

def aezHashNoAD (e : EState) (nonce : ByteArray) : Block := Id.run do
  -- Hash of tau (= 0 for Sphinx): buf is sixteen zero bytes; E(3,1).
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
  -- Final fragment (or, per aez.go, the empty-nonce case too).
  if off < nLen || nLen == 0 then
    let frag : Block := oneZeroPad (nonce.extract off nLen).data (nLen - off)
    sum := xor16 sum (aes4 e e.J2 e.I0 (e.L[0]!) frag)
  return sum

/-- Folding any number of `.set!` calls — whatever indices or values, however many, in whatever
order — never changes an array's size. This is the one fact behind every size-preservation proof
below: every `for`-loop in `aezTiny`/`pass1`/`pass2`/`aezCore` that mutates an `Array UInt8`
accumulator does so only via `.set!` at some index and value that are each pure functions of the
loop variable (never of the accumulator itself). -/
private theorem foldl_set!_size {α} (idx : Nat → Nat) (f : Nat → α) (l : List Nat) (a : Array α) :
    (l.foldl (fun acc i => acc.set! (idx i) (f i)) a).size = a.size := by
  induction l generalizing a with
  | nil => rfl
  | cons hd tl ih => rw [List.foldl_cons, ih, Array.size_set!]

/-- The `rounds/2`-style loop in `aezTinyLR`/`aezCore`'s passes threads a pair of blocks (here,
`Block × Block`, ignoring whatever else — `Int` counters and the like — rides along in further
components) where each step unconditionally replaces both with a fresh, always-16-byte value
(`xor16`'s output). So regardless of how many times it runs, and regardless of the *starting*
sizes, both components come out exactly 16 bytes — *provided* the starting sizes already are, to
cover the zero-iteration case where the fold returns its input unchanged. -/
private theorem foldl_pair16_size {α β} (l : List β) (step : Block × Block × α → β → Block × Block × α)
    (hstep1 : ∀ acc x, (step acc x).1.size = 16) (hstep2 : ∀ acc x, (step acc x).2.1.size = 16)
    (a : Block × Block × α) (ha1 : a.1.size = 16) (ha2 : a.2.1.size = 16) :
    (l.foldl step a).1.size = 16 ∧ (l.foldl step a).2.1.size = 16 := by
  induction l generalizing a with
  | nil => exact ⟨ha1, ha2⟩
  | cons hd tl ih => rw [List.foldl_cons]; exact ih (step a hd) (hstep1 a hd) (hstep2 a hd)

/-- `pass1`/`pass2`'s loop: whatever else its accumulator carries (`x`/`y`, the `ii` counter
block), the `ByteArray` component (read off by `out`) grows by exactly 32 bytes every iteration —
so after `l.length` iterations, it's grown by `32 * l.length`, regardless of what the accumulator
actually is or how the other components evolve. -/
private theorem foldl_append32_size {α γ} (l : List γ) (step : α → γ → α) (out : α → ByteArray)
    (hstep : ∀ acc x, (out (step acc x)).size = (out acc).size + 32) (a : α) :
    (out (l.foldl step a)).size = (out a).size + 32 * l.length := by
  induction l generalizing a with
  | nil => simp
  | cons hd tl ih =>
    rw [List.foldl_cons, ih (step a hd), hstep, List.length_cons]
    omega

/-- `pass1`/`pass2`'s loop body ends with `if i % 8 == 0 then ii := doubleBlock ii`, which
elaborates to `if c then pure (.yield a) else pure (.yield b)` — not the flat
`pure (.yield (f a b))` shape `List.forIn_pure_yield_eq_foldl` needs. This pushes the `pure`
outward first (matching `NIKESphinx.lean`'s identically-named, identically-shaped fact for the
`Except`-monad case), so that conversion can still fire. -/
private theorem ite_pure_yield {α} (c : Prop) [Decidable c] (a b : α) :
    (if c then (pure (ForInStep.yield a) : Id (ForInStep α)) else pure (ForInStep.yield b)) =
      pure (ForInStep.yield (if c then a else b)) := by
  split <;> rfl

/-! ## `aezTiny`: inputs shorter than 32 bytes -/

/-- `aezTiny`'s `(i0, rounds)` pair, pulled out under its own name so the size-preservation proof
below can treat it as an opaque `Nat × Nat` — it only ever feeds an `L[i0]!` index and a loop
trip count, neither of which affects `aezTiny`'s output *size* (every branch of every loop below
is a `.set!`, unconditionally preserving size regardless of how many times it runs or which
index it touches), so there is nothing to gain from a size proof case-splitting on it — and
plenty to lose, since it would multiply every other case split by its own four branches. -/
def aezTinyParams (inBytes : Nat) : Nat × Nat :=
  if inBytes == 1 then (7, 24)
  else if inBytes == 2 then (7, 16)
  else if inBytes < 16 then (7, 10)
  else (6, 8)

/-- The buffer construction shared by `aezTinyLR`'s `buf1` and `buf2`: copy `X`'s first `half`
bytes in, fold `mask`/`pad` into position `ih2` (`inBytes / 2`), XOR in `delta`, then XOR the
counter byte into the last position. `buf1` is `mkBuf ... R ctr1`; `buf2` is `mkBuf ... L' ctr2`
for the freshly-updated `L'` — literally the same code, differing only in which block and which
counter they're given. Factored out under its own name (not just inlined twice) so that
`buf1[ih2]!`/`buf1[15]!` reading back into `buf1`'s own construction doesn't re-expand the whole
thing at every read site — the same "term-duplication blowup" fix already used for `aezTinyLR`
itself and for `KEMSphinx.lean`'s `kemRiFragment`. -/
def mkBuf (half ih2 : Nat) (mask pad : UInt8) (delta : Block) (X : Block) (ctr : UInt8) : Block :=
  Id.run do
    let mut buf : Block := zero16
    for k in [0:half] do buf := buf.set! k (X[k]!)
    buf := buf.set! ih2 ((buf[ih2]! &&& mask) ||| pad)
    buf := xor16 buf delta
    buf := buf.set! 15 (buf[15]! ^^^ ctr)
    return buf

/-- `aezTiny`'s Feistel-round computation, producing the pair `(L, R)` the merge step below
consumes. Pulled out under its own name for exactly one reason: `aezTiny`'s size-preservation
proof only needs to know `(aezTinyLR ..).1.size = 16 ∧ (aezTinyLR ..).2.size = 16` (proved once,
in isolation, the same way `roundsApply_size` is), and can otherwise treat this whole computation
as opaque — without this split, every occurrence of `L`/`R` inside the merge step's own
`for`-loops gets inlined into a separate copy of this entire computation, and the resulting term
is too large for `simp`/`split` to process. -/
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

  -- Go's merge buffer is `[2*blockSize]byte` (32 bytes) here, not one block: `inBytes` can be
  -- up to 31, which overruns a 16-byte `Block`.
  let mut buf : Array UInt8 := Array.replicate inBytes 0
  for k in [0:inBytes / 2] do buf := buf.set! k (R[k]!)
  for k in [0:half] do buf := buf.set! (inBytes / 2 + k) (L[k]!)
  if inBytes % 2 == 1 then
    let orig := buf
    for k in [inBytes / 2 + 1 : inBytes] do
      -- Go: for k := inBytes-1; k > inBytes/2; k--  (descending; reads are independent per k
      -- from `orig` here, so direction does not matter for correctness).
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
    simp only [Id.run, pure, bind, zero16, Array.size_replicate, foldl_set!_size,
      Array.size_set!]
  all_goals
    exact foldl_pair16_size _ _ (fun _ _ => xor16_size ..) (fun _ _ => xor16_size ..) _
      (by simp only [zero16, Array.size_replicate, foldl_set!_size, Array.size_set!])
      (by simp only [zero16, Array.size_replicate, foldl_set!_size, Array.size_set!])

set_option maxHeartbeats 8000000 in
theorem aezTiny_size (e : EState) (delta : Block) (inArr : ByteArray) (d : Nat) :
    (aezTiny e delta inArr d).size = inArr.size := by
  unfold aezTiny
  obtain ⟨hL, hR⟩ := aezTinyLR_size e delta inArr d (aezTinyParams inArr.size).2
    (aezTinyParams inArr.size).1
  simp only [Std.Legacy.Range.forIn_eq_forIn_range', List.forIn_pure_yield_eq_foldl, pure_bind]
  repeat' split
  all_goals
    simp only [Id.run, pure, bind, ByteArray.size, ByteArray.set!, ByteArray.get!, zero16,
      foldl_set!_size, Array.size_replicate, Array.size_set!, ByteArray.size_set!, hL, hR]

/-! ## Toward round-trip correctness: `aezTinyLR`'s abstract Feistel-style ladder

`decipher (encipher m) = m` (the fact `wrapNIKE_unwrapNIKE_complete`/`wrapKEM_unwrapKEM_complete`
ultimately need) is real cryptographic-construction correctness, not the loop-invariant/size
bookkeeping the rest of this file's proofs are — a categorically different, larger undertaking.
This section proves the algebraic crux of the `aezTiny` half of it (the `< 32`-byte path):
`aezTinyLR`'s `for _ in [0:rounds/2] do ...` loop, run forward (`d = 0`, ascending counters
`j = 0,2,4,...`) or backward (`d ≠ 0`, descending counters `j = rounds-1,rounds-3,...`), each
double-round updating a pair `(L,R)` via a round function `F` keyed by the running counter.
Numerically checking this first (a Python simulation with a deliberately non-injective,
non-cryptographic stand-in `F`) confirmed the round-trip holds by pure XOR algebra alone — no
property of AES4 is needed, and no property of the counter arithmetic beyond what's proved here.

The catch: running the loop backward over descending counters does **not**, by itself, invert
running it forward — `aezTiny`'s surrounding merge/demerge step also swaps `L`/`R` between an
encrypt call and the following decrypt call (ciphertext bytes are laid out `R ‖ L`, not `L ‖ R`),
and it's *that* swap, composed with the reversed counters, that makes each double-round exactly
undo the matching forward one via `xor16`'s self-cancellation (`a ^^^ b ^^^ b = a`).

`ladderFwdN`/`ladderBwdN` below model the loop with the counter folded into a plain recursion on
the iteration count (rather than `aezTinyLR`'s actual mutable `Int` `j`/`step` state) — connecting
this to the real loop, then to `aezTiny`'s merge/demerge and its small-input/odd-length special
cases, then doing the analogous (structurally different — a two-pass X/S/Y construction, not a
Feistel ladder) derivation for `aezCore`, and finally composing through `unwrapNIKE`/`unwrapKEM`'s
whole multi-hop chain, is substantial further work not attempted here. This lemma is the one piece
of that chain proved so far, kept as a real, checked, standalone fact. -/

theorem xor16_get! {i : Nat} (hi : i < 16) (a b : Block) :
    (xor16 a b)[i]! = a[i]! ^^^ b[i]! := by
  simp only [xor16, getElem!_pos, Array.getElem_ofFn, Array.size_ofFn, hi]

/-- The one fact behind the whole ladder round-trip: XOR is its own inverse, per byte. Needs only
`a.size = 16` (not `b`'s) — `b` is read at the same index on both sides, whatever it is. -/
theorem xor16_cancel {a : Block} (b : Block) (ha : a.size = 16) :
    xor16 (xor16 a b) b = a := by
  apply Array.ext (by rw [xor16_size, ha])
  intro i hi1 hi2
  have hi16 : i < 16 := by rw [xor16_size] at hi1; exact hi1
  rw [← getElem!_pos (xor16 (xor16 a b) b) i hi1, ← getElem!_pos a i hi2,
    xor16_get! hi16, xor16_get! hi16, UInt8.xor_assoc, UInt8.xor_self, UInt8.xor_zero]

/-- One forward double-round at iteration `k`: update `L` from `R` under counter `2k`, then `R`
from the new `L` under counter `2k+1`. Matches `aezTinyLR`'s loop body when `d = 0` (`j` starts at
`0`, `step = 1`). -/
def ladderFwdStep (F : Nat → Block → Block) (k : Nat) (LR : Block × Block) : Block × Block :=
  let L' := xor16 LR.1 (F (2*k) LR.2)
  let R' := xor16 LR.2 (F (2*k+1) L')
  (L', R')

/-- One backward double-round starting from counter `s` (the *higher* of the pair): update `L`
from `R` under counter `s`, then `R` from the new `L` under counter `s-1`. Matches `aezTinyLR`'s
loop body when `d ≠ 0` (`j` starts at `rounds-1`, `step = -1`), with `s` the current `j`. -/
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

/-- **The ladder round-trip.** `n` forward double-rounds, then (after swapping `L`/`R` — exactly
what `aezTinyLR`'s caller does between an encrypt call and the matching decrypt call) `n` backward
double-rounds, recover the original pair, swapped back. True for *any* `F` — nothing here uses
anything about the round function beyond its type, matching the numerical check this was verified
against first. Proved by induction on `n`, peeling the *last* forward double-round (counters
`2n,2n+1`) and showing it's exactly undone by the *first* backward double-round (counter `2n+1`),
via `xor16_cancel` applied twice. -/
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

`aezCorePass1`/`aezCorePass2` process the input in 32-byte chunks, all but the final chunk and
any `< 32`-byte fragment (`aezCorePass1Ref`/`aezCorePass2Ref`); the final chunk and fragment are
finished separately, matching `aezCore`. -/

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
  simp only [Id.run, pure, bind]
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
  simp only [Id.run, pure, bind]
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

/-- Targeted versions of `ByteArray.size`'s unfolding, applying only to a literal `⟨_⟩`/`.empty`
constructor rather than an arbitrary `ByteArray`-valued term — unlike bare `ByteArray.size`, these
don't touch a plain variable's `.size` (e.g. `inArr.size`), which would otherwise desync it from
hypotheses/`by_cases` names stated in terms of `inArr.size`. -/
@[simp] private theorem byteArray_mk_size (a : Array UInt8) : (⟨a⟩ : ByteArray).size = a.size := rfl

@[simp] private theorem byteArray_empty_size : (ByteArray.empty : ByteArray).size = 0 := rfl

set_option maxHeartbeats 1000000 in
theorem aezCore_size (e : EState) (delta : Block) (inArr : ByteArray) (d : Nat)
    (h : 32 ≤ inArr.size) : (aezCore e delta inArr d).size = inArr.size := by
  unfold aezCore
  simp only [Id.run, pure, bind]
  by_cases h64 : inArr.size ≥ 64 <;>
    by_cases h16 : inArr.size % 32 ≥ 16 <;>
      by_cases hgt : inArr.size % 32 > 0 <;>
        simp only [h64, h16, hgt, if_true, if_false, ite_true, ite_false] <;>
        simp only [ByteArray.size_append] <;>
        (try simp only [pass1_size, pass2_size]) <;>
        simp only [byteArray_mk_size, byteArray_empty_size, xor16_size, xor4_size, aes4_size',
          aes10_size', ofFn_size] <;>
        omega

/-! ## Top-level dispatch, matching `encipher`/`decipher`/`SPRPEncrypt`/`SPRPDecrypt` -/

def encipher (e : EState) (delta : Block) (inArr : ByteArray) : ByteArray :=
  if inArr.size == 0 then ByteArray.empty
  else if inArr.size < 32 then aezTiny e delta inArr 0
  else aezCore e delta inArr 0

def decipher (e : EState) (delta : Block) (inArr : ByteArray) : ByteArray :=
  if inArr.size == 0 then ByteArray.empty
  else if inArr.size < 32 then aezTiny e delta inArr 1
  else aezCore e delta inArr 1

/-- **`crypto.SPRPEncrypt`**: `key` 48 bytes, `iv` 16 bytes, `tau = 0`, no additional data. -/
def sprpEncrypt (key : Array UInt8) (iv : ByteArray) (msg : ByteArray) : ByteArray :=
  let e := initState key
  let delta := aezHashNoAD e iv
  encipher e delta msg

/-- **`crypto.SPRPDecrypt`**. With `tau = 0` the AEZ-native tag check always passes (there is no
tag), matching the Go wrapper's `panic`-on-`!ok` never firing in this configuration. -/
def sprpDecrypt (key : Array UInt8) (iv : ByteArray) (msg : ByteArray) : ByteArray :=
  let e := initState key
  let delta := aezHashNoAD e iv
  decipher e delta msg

/-! ## Length preservation

AEZ in `τ = 0` mode is a length-preserving permutation by construction: every branch of
`aezTiny`/`aezCore` assembles its output from pieces sized off `inArr.size` itself
(`aezCore`'s three regions total `initialBytes + fragBytes + 32 = inArr.size`), and all 12
`sprp_aez.json` vectors confirm it (ciphertext always exactly as long as plaintext). Proved from
`aezTiny`/`aezCore`'s definitions by pushing each `for`-loop's size invariant through `Id.run do`
(`aezTinyLR_size`, `pass1_size`/`pass2_size`, `aezCore_size`). `Sphinx.Interface` is what actually
needs this: it's how `unwrap` gets a packet-size-preserving type. -/

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

end CryptWalker.Sphinx.Crypto.AEZ

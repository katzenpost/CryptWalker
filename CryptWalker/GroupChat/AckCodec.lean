/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Mathlib.Combinatorics.Colex
import Mathlib.Data.Nat.BitIndices
import Mathlib.Data.List.Sort
import Mathlib.Tactic.Ring
import Mathlib.Tactic.Linarith
import Mathlib.Tactic.Push
import Mathlib.Tactic.Set

/-! # The `Acks` field of a group chat message

See "Rosters" (Layout, Parsing) in the group chat spec, and katzenqt's `ack_codec.py`, which this
follows. A field names the acknowledged members by roster index, as a list of index bytes or a
bitmap, whichever is shorter, and then carries one value of `v` bytes for each, in ascending order
of roster index. Nothing frames the parts: a reader divides the field's length by `v`, and the
quotient is the number of values and the remainder the length of the naming.

Bytes are natural numbers here; `decode` is only ever handed real bytes (each `< 256`).

* `decode_encode`: decoding undoes encoding whenever `v > 32`.
* `decode_encode_iff`: and only then. For every `v ≤ 32` some acknowledgement set is misread,
  which is the spec's "were a value ever made shorter than 33 bytes, the field would need an
  explicit count".
* `encode_decode`: with `strict`, a field that decodes is the encoding of what it decodes to, so
  each set of acknowledgements has exactly one field.
* `spec_decode_malleable`: the spec's parser (not `strict`) also accepts a list where the bitmap
  is shorter, so one set of acknowledgements has two fields. -/

namespace CryptWalker.GroupChat.AckCodec

/-- Roster indexes are one byte. -/
def rosterMax : ℕ := 256

/-- The longest naming: a bitmap reaching roster index 255. -/
def maxNaming : ℕ := 32

/-- Bytes a bitmap needs to reach roster index `i`. -/
def width (i : ℕ) : ℕ := i / 8 + 1

/-- The bits of byte `j` of the bitmap for `idx`, counted from the least significant: index `i`
is bit `7 - i % 8` of byte `i / 8`. -/
def byteBits (idx : List ℕ) (j : ℕ) : Finset ℕ :=
  ((idx.filter (fun i => i / 8 = j)).map (fun i => 7 - i % 8)).toFinset

def bitmapByte (idx : List ℕ) (j : ℕ) : ℕ := ∑ k ∈ byteBits idx j, 2 ^ k

def bitmap (idx : List ℕ) (w : ℕ) : List ℕ := (List.range w).map (bitmapByte idx)

/-- Ascending roster indexes as a list or a bitmap, whichever is shorter. -/
def nameMembers (idx : List ℕ) : List ℕ :=
  match idx.getLast? with
  | none => []
  | some last => if idx.length ≤ width last then idx else bitmap idx (width last)

def bitSet (naming : List ℕ) (i : ℕ) : Bool := (naming.getD (i / 8) 0).testBit (7 - i % 8)

/-- The roster indexes a bitmap marks, in ascending order. -/
def setBits (naming : List ℕ) : List ℕ := (List.range (naming.length * 8)).filter (bitSet naming)

/-- Whether a list naming is no longer than the bitmap for the same members. -/
def listShortest (naming : List ℕ) : Bool :=
  match naming.getLast? with
  | none => true
  | some last => decide (naming.length ≤ width last)

/-- What precedes `count` values. `strict` also refuses a list where the bitmap is shorter,
which the spec does not ask for. -/
def readMembers (strict : Bool) (naming : List ℕ) (count : ℕ) : Option (List ℕ) :=
  if naming.length = count then
    if naming.IsChain (· < ·) ∧ (strict → listShortest naming) then some naming else none
  else if count < naming.length then none
  else if maxNaming < naming.length then none
  else if naming = [] ∨ naming.getLast? = some 0 then none
  else if (setBits naming).length = count then some (setBits naming) else none

/-- The `n` values of `v` bytes that follow the naming. -/
def chunks (v : ℕ) : List ℕ → ℕ → List (List ℕ)
  | _, 0 => []
  | l, n + 1 => l.take v :: chunks v (l.drop v) n

/-- The field for `acks`, pairs of roster index and value in ascending order of index. -/
def encode (acks : List (ℕ × List ℕ)) : List ℕ :=
  nameMembers (acks.map Prod.fst) ++ (acks.map Prod.snd).flatten

/-- The acknowledgements a field carries, or `none` when it is malformed. -/
def decode (strict : Bool) (v : ℕ) (field : List ℕ) : Option (List (ℕ × List ℕ)) :=
  if v = 0 then none
  else
    let count := field.length / v
    let w := field.length % v
    (readMembers strict (field.take w) count).map fun idx =>
      idx.zip (chunks v (field.drop w) count)

/-- What a sender may encode: ascending roster indexes, each one byte, each value `v` bytes. -/
structure WF (v : ℕ) (acks : List (ℕ × List ℕ)) : Prop where
  sorted : (acks.map Prod.fst).Pairwise (· < ·)
  lt : ∀ a ∈ acks, a.1 < rosterMax
  size : ∀ a ∈ acks, a.2.length = v

/-! ## Lemmas -/

theorem testBit_bitmapByte (idx : List ℕ) (j k : ℕ) :
    (bitmapByte idx j).testBit k ↔ k ∈ byteBits idx j := by
  rw [bitmapByte, ← Nat.mem_bitIndices, ← List.mem_toFinset, Finset.toFinset_bitIndices_sum_two_pow]

theorem mem_byteBits {idx : List ℕ} {i : ℕ} :
    7 - i % 8 ∈ byteBits idx (i / 8) ↔ i ∈ idx := by
  simp only [byteBits, List.mem_toFinset, List.mem_map, List.mem_filter, decide_eq_true_eq]
  constructor
  · rintro ⟨i', ⟨hi', hj⟩, hk⟩
    have : i' = i := by omega
    exact this ▸ hi'
  · intro h; exact ⟨i, ⟨h, rfl⟩, rfl⟩

theorem bitSet_bitmap {idx : List ℕ} {w i : ℕ} (hi : i < w * 8) :
    bitSet (bitmap idx w) i = true ↔ i ∈ idx := by
  have hj : i / 8 < w := by omega
  simp only [bitSet, bitmap, List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hj,
    Option.map_some, Option.getD_some]
  rw [testBit_bitmapByte, mem_byteBits]

/-- The members of a strictly ascending list below `n`, read off `0..n-1` in order, are the list. -/
theorem filter_range_eq {l : List ℕ} {n : ℕ} (hs : l.Pairwise (· < ·)) (hl : ∀ x ∈ l, x < n)
    (p : ℕ → Bool) (hp : ∀ x < n, p x = true ↔ x ∈ l) : (List.range n).filter p = l := by
  apply List.Perm.eq_of_pairwise' (r := (· < ·))
  · exact (List.pairwise_lt_range).filter _
  · exact hs
  · rw [List.perm_ext_iff_of_nodup ((List.nodup_range).filter _) (hs.imp (fun h => ne_of_lt h))]
    intro x
    simp only [List.mem_filter, List.mem_range]
    constructor
    · rintro ⟨hx, h⟩; exact (hp x hx).1 h
    · intro h; exact ⟨hl x h, (hp x (hl x h)).2 h⟩

theorem setBits_bitmap {idx : List ℕ} {w : ℕ} (hs : idx.Pairwise (· < ·)) (hl : ∀ x ∈ idx, x < w * 8) :
    setBits (bitmap idx w) = idx := by
  have hlen : (bitmap idx w).length = w := by simp [bitmap]
  rw [setBits, hlen]
  exact filter_range_eq hs hl _ (fun _ hx => bitSet_bitmap hx)

theorem bitmapByte_ne_zero {idx : List ℕ} {i : ℕ} (h : i ∈ idx) : bitmapByte idx (i / 8) ≠ 0 := by
  intro h0
  have := (testBit_bitmapByte idx (i / 8) (7 - i % 8)).2 (mem_byteBits.2 h)
  rw [h0, Nat.zero_testBit] at this
  exact Bool.false_ne_true this

theorem length_flatten_uniform {v : ℕ} : ∀ {vals : List (List ℕ)}, (∀ a ∈ vals, a.length = v) →
    vals.flatten.length = vals.length * v
  | [], _ => by simp
  | a :: rest, h => by
    simp only [List.flatten_cons, List.length_append, List.length_cons]
    rw [h a (by simp), length_flatten_uniform (fun b hb => h b (by simp [hb]))]
    ring

theorem chunks_flatten {v : ℕ} : ∀ {vals : List (List ℕ)}, (∀ a ∈ vals, a.length = v) →
    chunks v vals.flatten vals.length = vals
  | [], _ => rfl
  | a :: rest, h => by
    have ha := h a (by simp)
    simp only [List.flatten_cons, List.length_cons, chunks]
    rw [List.take_left' ha, List.drop_left' ha, chunks_flatten (fun b hb => h b (by simp [hb]))]

theorem flatten_chunks {v : ℕ} : ∀ {n : ℕ} {l : List ℕ}, l.length = n * v →
    (chunks v l n).flatten = l
  | 0, l, h => by simp at h; simp [chunks, h]
  | n + 1, l, h => by
    simp only [chunks, List.flatten_cons]
    rw [flatten_chunks (by simp [h]; ring_nf; omega), List.take_append_drop]

theorem chunks_length_mem {v : ℕ} : ∀ {n : ℕ} {l : List ℕ}, l.length = n * v →
    ∀ c ∈ chunks v l n, c.length = v
  | 0, _, _ => by simp [chunks]
  | n + 1, l, h => by
    simp only [chunks, List.mem_cons]
    rintro c (rfl | hc)
    · simp [List.length_take, h]; nlinarith
    · exact chunks_length_mem (by simp [h]; ring_nf; omega) c hc

theorem length_chunks {v : ℕ} : ∀ {n : ℕ} {l : List ℕ}, (chunks v l n).length = n
  | 0, _ => rfl
  | _ + 1, _ => by simp [chunks, length_chunks]

/-! ## Decoding undoes encoding -/

theorem width_le {i : ℕ} (h : i < rosterMax) : width i ≤ maxNaming := by
  simp only [width, rosterMax, maxNaming] at *; omega

/-- **Decoding undoes encoding**, under either parser, whenever a value is longer than the
longest naming. -/
theorem decode_encode (strict : Bool) {v : ℕ} (hv : maxNaming < v) {acks : List (ℕ × List ℕ)}
    (h : WF v acks) : decode strict v (encode acks) = some acks := by
  obtain ⟨hs, hlt, hsz⟩ := h
  set idx := acks.map Prod.fst with hidx
  set vals := acks.map Prod.snd with hvals
  have hvals_sz : ∀ a ∈ vals, a.length = v := by
    intro a ha; obtain ⟨b, hb, rfl⟩ := List.mem_map.1 ha; exact hsz b hb
  have hflat : vals.flatten.length = acks.length * v := by
    rw [length_flatten_uniform hvals_sz]; simp [hvals]
  have hidx_lt : ∀ x ∈ idx, x < rosterMax := by
    intro x hx; obtain ⟨b, hb, rfl⟩ := List.mem_map.1 hx; exact hlt b hb
  have hzip : idx.zip vals = acks := by
    rw [hidx, hvals]; clear hs hidx hvals hvals_sz hflat hidx_lt hlt hsz
    induction acks with
    | nil => rfl
    | cons a t ih => simp [ih]
  have hv0 : v ≠ 0 := by unfold maxNaming at hv; omega
  -- the naming is shorter than a value, so length arithmetic recovers the parts
  have split : ∀ naming : List ℕ, naming.length < v →
      decode strict v (naming ++ vals.flatten) =
        (readMembers strict naming acks.length).map (fun ix => ix.zip vals) := by
    intro naming hn
    have hlen : (naming ++ vals.flatten).length = naming.length + acks.length * v := by simp [hflat]
    have hdiv : (naming.length + acks.length * v) / v = acks.length := by
      rw [Nat.add_mul_div_right _ _ (Nat.pos_of_ne_zero hv0), Nat.div_eq_of_lt hn, zero_add]
    have hmod : (naming.length + acks.length * v) % v = naming.length := by
      rw [Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hn]
    simp only [decode, hv0, if_false, hlen, hdiv, hmod, List.take_left, List.drop_left]
    have : vals.length = acks.length := by simp [hvals]
    rw [← this, chunks_flatten hvals_sz]
  cases hlast : idx.getLast? with
  | none =>
    have hnil : acks = [] := by simpa [hidx] using hlast
    subst hnil
    simp [decode, encode, nameMembers, hv0, readMembers, chunks, listShortest]
  | some last =>
    have hmem : last ∈ idx := List.mem_of_getLast? hlast
    have hw : width last ≤ maxNaming := width_le (hidx_lt last hmem)
    have hnlen : idx.length = acks.length := by simp [hidx]
    by_cases hshort : idx.length ≤ width last
    · -- named by a list
      have hname : nameMembers idx = idx := by simp [nameMembers, hlast, hshort]
      have : encode acks = idx ++ vals.flatten := by simp [encode, ← hidx, ← hvals, hname]
      rw [this, split idx (by omega)]
      have hchain : idx.IsChain (· < ·) := List.isChain_iff_pairwise.2 hs
      simp [readMembers, hnlen, hchain, listShortest, hlast, hzip]
      intro _; omega
    · -- named by a bitmap of `width last` bytes
      have hname : nameMembers idx = bitmap idx (width last) := by simp [nameMembers, hlast, hshort]
      have : encode acks = bitmap idx (width last) ++ vals.flatten := by
        simp [encode, ← hidx, ← hvals, hname]
      have hblen : (bitmap idx (width last)).length = width last := by simp [bitmap]
      rw [this, split _ (by omega)]
      -- every index sits below the last, so inside the bitmap
      have hbelow : ∀ x ∈ idx, x < width last * 8 := by
        intro x hx
        have : x ≤ last := by
          rcases List.mem_iff_getElem.1 hx with ⟨k, hk, rfl⟩
          have hl := List.getLast?_eq_getElem? (l := idx)
          rw [hlast] at hl
          have hlt : idx.length - 1 < idx.length := by omega
          have heq : idx[idx.length - 1] = last := by
            rw [List.getElem?_eq_getElem hlt] at hl; exact (Option.some.inj hl).symm
          rcases Nat.lt_or_ge k (idx.length - 1) with hk' | hk'
          · rw [← heq]; exact le_of_lt (List.pairwise_iff_getElem.1 hs k _ hk hlt hk')
          · have : k = idx.length - 1 := by omega
            subst this; exact le_of_eq heq
        simp only [width]; omega
      have hbits := setBits_bitmap (w := width last) hs hbelow
      have hne : bitmap idx (width last) ≠ [] := by
        intro h0; rw [h0] at hblen; simp [width] at hblen
      have hlastb : (bitmap idx (width last)).getLast? ≠ some 0 := by
        rw [List.getLast?_eq_getElem?, hblen]
        have : width last - 1 < width last := by simp [width]
        simp only [bitmap, List.getElem?_map, List.getElem?_range this, Option.map_some, ne_eq,
          Option.some.injEq]
        have : width last - 1 = last / 8 := by simp [width]
        rw [this]; exact bitmapByte_ne_zero hmem
      simp only [readMembers, hblen]
      rw [if_neg (by omega), if_neg (by omega), if_neg (by omega), if_neg (by simp [hne, hlastb]),
        hbits, if_pos hnlen]
      simp [hzip]

/-! ## Only then: a value of 32 bytes or fewer is misread -/

/-- **The layout needs values longer than 32 bytes.** Decoding undoes encoding for every set of
acknowledgements exactly when it does. -/
theorem decode_encode_iff (strict : Bool) (v : ℕ) :
    (∀ acks, WF v acks → decode strict v (encode acks) = some acks) ↔ maxNaming < v := by
  refine ⟨fun h => ?_, fun hv acks hw => decode_encode strict hv hw⟩
  by_contra hle
  push Not at hle
  rcases Nat.eq_zero_or_pos v with rfl | hpos
  · have := h [] ⟨by simp, by simp, by simp⟩
    simp [decode] at this
  · -- every roster index below 8v: a bitmap of v bytes, then 8v values
    set acks := (List.range (8 * v)).map fun i => (i, List.replicate v 0) with hacks
    have hwf : WF v acks := by
      refine ⟨?_, ?_, ?_⟩
      · simpa [hacks, Function.comp_def] using List.pairwise_lt_range
      · intro a ha
        obtain ⟨i, hi, rfl⟩ := List.mem_map.1 ha
        simp only [List.mem_range] at hi; simp only [rosterMax, maxNaming] at *; omega
      · intro a ha; obtain ⟨i, _, rfl⟩ := List.mem_map.1 ha; simp
    have hidx : acks.map Prod.fst = List.range (8 * v) := by simp [hacks, Function.comp_def]
    have hlast : (List.range (8 * v)).getLast? = some (8 * v - 1) := by
      rw [List.getLast?_range]; simp; omega
    have hwidth : width (8 * v - 1) = v := by simp only [width]; omega
    have hname : nameMembers (acks.map Prod.fst) = bitmap (List.range (8 * v)) v := by
      rw [hidx, nameMembers, hlast]; simp only [List.length_range, hwidth]; rw [if_neg (by omega)]
    have hflat : ((acks.map Prod.snd).flatten).length = 8 * v * v := by
      rw [length_flatten_uniform (v := v)]
      · simp [hacks]
      · intro a ha; simp [hacks] at ha; obtain ⟨_, _, rfl⟩ := ha; simp
    have hlen : (encode acks).length = 0 + (8 * v + 1) * v := by
      simp [encode, hname, bitmap, hflat]; ring
    have hdec := h acks hwf
    have hv0 : v ≠ 0 := by omega
    have hcount : (encode acks).length / v = 8 * v + 1 := by
      rw [hlen, zero_add, Nat.mul_div_cancel _ hpos]
    have hrem : (encode acks).length % v = 0 := by rw [hlen, zero_add, Nat.mul_mod_left]
    simp [decode, hv0, hcount, hrem, readMembers] at hdec


/-- A strictly ascending list's last element is at least every element. -/
theorem le_of_getLast? {l : List ℕ} (hs : l.Pairwise (· < ·)) {last : ℕ} (h : l.getLast? = some last)
    {x : ℕ} (hx : x ∈ l) : x ≤ last := by
  rcases List.mem_iff_getElem.1 hx with ⟨k, hk, rfl⟩
  have hl := List.getLast?_eq_getElem? (l := l)
  rw [h] at hl
  have hlt : l.length - 1 < l.length := by omega
  have heq : l[l.length - 1] = last := by
    rw [List.getElem?_eq_getElem hlt] at hl; exact (Option.some.inj hl).symm
  rcases Nat.lt_or_ge k (l.length - 1) with hk' | hk'
  · rw [← heq]; exact le_of_lt (List.pairwise_iff_getElem.1 hs k _ hk hlt hk')
  · have : k = l.length - 1 := by omega
    subst this; exact le_of_eq heq

theorem mem_setBits {naming : List ℕ} {i : ℕ} :
    i ∈ setBits naming ↔ i < naming.length * 8 ∧ bitSet naming i = true := by
  simp [setBits]

theorem setBits_pairwise (naming : List ℕ) : (setBits naming).Pairwise (· < ·) :=
  (List.pairwise_lt_range).filter _

theorem lt_eight_of_testBit {b k : ℕ} (hb : b < 256) (h : b.testBit k = true) : k < 8 := by
  by_contra hk
  have : b < 2 ^ k := lt_of_lt_of_le hb (by
    calc 256 = 2 ^ 8 := by norm_num
      _ ≤ 2 ^ k := Nat.pow_le_pow_right (by norm_num) (by omega))
  rw [Nat.testBit_lt_two_pow this] at h; exact Bool.false_ne_true h

/-- Under the strict parser, a well-formed bitmap is the bitmap of the members it marks. -/
theorem nameMembers_setBits {naming : List ℕ} (hbytes : ∀ b ∈ naming, b < 256) (hne : naming ≠ [])
    (hlast : naming.getLast? ≠ some 0) (hcount : naming.length < (setBits naming).length) :
    nameMembers (setBits naming) = naming := by
  set L := naming.length with hL
  have hL0 : 0 < L := List.length_pos_iff.2 hne
  have hget : ∀ j (hj : j < L), naming.getD j 0 = naming[j] := by
    intro j hj; simp [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem hj]
  -- the last byte marks some member in the last eighth
  have hb : naming[L - 1] ≠ 0 := by
    intro h0; apply hlast; rw [List.getLast?_eq_getElem?, List.getElem?_eq_getElem (by omega), h0]
  obtain ⟨k, hk⟩ := Nat.exists_testBit_of_ne_zero hb
  have hk8 : k < 8 := lt_eight_of_testBit (hbytes _ (List.getElem_mem _)) hk
  have hi : 8 * (L - 1) + (7 - k) ∈ setBits naming := by
    rw [mem_setBits]
    refine ⟨by omega, ?_⟩
    simp only [bitSet]
    have h1 : (8 * (L - 1) + (7 - k)) / 8 = L - 1 := by omega
    have h2 : 7 - (8 * (L - 1) + (7 - k)) % 8 = k := by omega
    rw [h1, h2, hget _ (by omega)]; exact hk
  obtain ⟨last, hlast'⟩ : ∃ last, (setBits naming).getLast? = some last := by
    cases h : (setBits naming).getLast? with
    | none => simp at h; rw [h] at hi; simp at hi
    | some x => exact ⟨x, rfl⟩
  have hge := le_of_getLast? (setBits_pairwise naming) hlast' hi
  have hlt : last < L * 8 := (mem_setBits.1 (List.mem_of_getLast? hlast')).1
  have hw : width last = L := by simp only [width]; omega
  simp only [nameMembers, hlast', hw]
  rw [if_neg (by omega)]
  -- byte by byte, the bitmap of the marked members is the naming
  apply List.ext_getElem (by simp [bitmap, hL])
  intro j hj1 hj2
  simp only [bitmap, List.getElem_map, List.getElem_range]
  apply Nat.eq_of_testBit_eq
  intro t
  rw [Bool.eq_iff_iff, testBit_bitmapByte]
  simp only [byteBits, List.mem_toFinset, List.mem_map, List.mem_filter, decide_eq_true_eq]
  constructor
  · rintro ⟨i, ⟨hi, hij⟩, rfl⟩
    obtain ⟨-, hbit⟩ := mem_setBits.1 hi
    simpa [bitSet, hij, List.getElem?_eq_getElem hj2] using hbit
  · intro ht
    have ht8 : t < 8 := lt_eight_of_testBit (hbytes _ (List.getElem_mem _)) ht
    refine ⟨8 * j + (7 - t), ⟨mem_setBits.2 ⟨by omega, ?_⟩, by omega⟩, by omega⟩
    simp only [bitSet]
    have h1 : (8 * j + (7 - t)) / 8 = j := by omega
    have h2 : 7 - (8 * j + (7 - t)) % 8 = t := by omega
    rw [h1, h2, hget j hj2]; exact ht

/-- **One field per set of acknowledgements.** Under the strict parser, a field that decodes is
exactly the encoding of what it decodes to, and what it decodes to is well formed. -/
theorem encode_decode {v : ℕ} {field : List ℕ} {acks : List (ℕ × List ℕ)}
    (hbytes : ∀ b ∈ field, b < 256) (h : decode true v field = some acks) :
    WF v acks ∧ encode acks = field := by
  unfold decode at h
  split_ifs at h with hv0
  set count := field.length / v with hcount
  set w := field.length % v with hw
  have hdrop : (field.drop w).length = count * v := by
    simp only [List.length_drop, hcount, hw]
    have := Nat.div_add_mod field.length v
    rw [Nat.mul_comm] ; omega
  have hwlen : (field.take w).length = w := by
    simp only [List.length_take]
    exact min_eq_left (Nat.mod_le _ _)
  obtain ⟨idx, hread, rfl⟩ := Option.map_eq_some_iff.1 h
  have hch := length_chunks (v := v) (n := count) (l := field.drop w)
  -- whichever form named them, the members are `idx`, ascending, `count` of them
  have key : idx.length = count ∧ idx.Pairwise (· < ·) ∧ (∀ i ∈ idx, i < rosterMax) ∧
      nameMembers idx = field.take w := by
    simp only [readMembers] at hread
    split_ifs at hread with h1 h2 h3 h4 h5 h6 <;> simp at hread
    · subst hread
      obtain ⟨hchain, hshort⟩ := h2
      have hp := List.isChain_iff_pairwise.1 hchain
      refine ⟨h1, hp, fun i hi => hbytes i (List.mem_of_mem_take hi), ?_⟩
      cases hl : (field.take w).getLast? with
      | none => rw [List.getLast?_eq_none_iff] at hl; simp [nameMembers, hl]
      | some last =>
        have := hshort trivial
        simp only [listShortest, hl, decide_eq_true_eq] at this
        simp only [nameMembers, hl]; rw [if_pos this]
    · subst hread
      push Not at h5
      refine ⟨h6, setBits_pairwise _, ?_, ?_⟩
      · intro i hi
        have := (mem_setBits.1 hi).1
        simp only [maxNaming, rosterMax] at *; omega
      · exact nameMembers_setBits (fun b hb => hbytes b (List.mem_of_mem_take hb)) h5.1 h5.2
          (by omega)
  obtain ⟨hlen, hp, hlt, hname⟩ := key
  have hzip_fst : (idx.zip (chunks v (field.drop w) count)).map Prod.fst = idx := by
    rw [List.map_fst_zip]; omega
  have hzip_snd : (idx.zip (chunks v (field.drop w) count)).map Prod.snd =
      chunks v (field.drop w) count := by
    rw [List.map_snd_zip]; omega
  refine ⟨⟨by rw [hzip_fst]; exact hp, ?_, ?_⟩, ?_⟩
  · intro a ha; exact hlt a.1 (hzip_fst ▸ List.mem_map_of_mem ha)
  · intro a ha
    exact chunks_length_mem hdrop a.2 (hzip_snd ▸ List.mem_map_of_mem ha)
  · rw [encode, hzip_fst, hzip_snd, hname, flatten_chunks hdrop, List.take_append_drop]

/-! ## The spec's parser is malleable; a strict one is not -/

/-- The members 0, 1 and 2, named by a list where the bitmap `0xe0` is shorter, with three
33-byte values: the spec's parser accepts it, and it is not what `encode` writes. -/
theorem spec_decode_malleable :
    let field := [0, 1, 2] ++ List.replicate 99 0
    ∃ acks, decode false 33 field = some acks ∧ encode acks ≠ field ∧
      decode false 33 (encode acks) = some acks := by
  refine ⟨[(0, List.replicate 33 0), (1, List.replicate 33 0), (2, List.replicate 33 0)], ?_, ?_, ?_⟩
  · decide
  · decide
  · decide

end CryptWalker.GroupChat.AckCodec

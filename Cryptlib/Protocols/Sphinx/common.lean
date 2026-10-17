/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Cryptlib.Protocols.Sphinx.geometry
import Cryptlib.Protocols.Sphinx.commands
import Cryptlib.Primitives.MAC.HMAC
import Cryptlib.Util.Bytes

/-! # Helpers shared by NIKE-Sphinx and KEM-Sphinx -/

namespace Cryptlib.Protocols.Sphinx.Common

open Cryptlib.Protocols.Sphinx.Geometry (Geometry)
open Cryptlib.Protocols.Sphinx.Commands
open Cryptlib.Primitives.MAC.HMAC (hmacSha256)
open Cryptlib.Util.Bytes (ofVector size_ofVector extract_append_le extract_append_of_le
  extract_append_of_ge append_extract)

def v0AD : ByteArray := ⟨#[0, 0]⟩

def toVec32 (a : ByteArray) : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => a.get! i.val

/-- As `toVec32`, at width `n`. -/
def toVecN (n : Nat) (a : ByteArray) : Vector UInt8 n := Vector.ofFn fun i : Fin n => a.get! i.val

/-- `toVecN` undoes `ofVector`. -/
@[simp] theorem toVecN_ofVector {n : Nat} (v : Vector UInt8 n) : toVecN n (ofVector v) = v := by
  apply Vector.ext
  intro i hi
  simp only [toVecN, Vector.getElem_ofFn]
  show (ofVector v).get! i = v[i]
  show v.toArray[i]! = v[i]
  simp [getElem!_pos, hi]

/-- `ofVector` undoes `toVecN`. -/
theorem ofVector_toVecN {n : Nat} (X : ByteArray) (h : X.size = n) : ofVector (toVecN n X) = X := by
  apply ByteArray.ext_getElem
  · show (Array.ofFn (fun i : Fin n => X.get! i.val)).size = X.size
    rw [Array.size_ofFn, h]
  · intro i hi hi'
    rw [size_ofVector] at hi
    have hi2 : i < (Array.ofFn (fun i : Fin n => X.get! i.val)).size := by
      rw [Array.size_ofFn]; exact hi
    show (Array.ofFn (fun i : Fin n => X.get! i.val))[i]'hi2 = X[i]'hi'
    rw [Array.getElem_ofFn]
    obtain ⟨bs⟩ := X
    show bs[i]! = (⟨bs⟩ : ByteArray)[i]'hi'
    rw [getElem!_pos bs i hi']
    rfl

theorem toVec32_eq_toVecN (a : ByteArray) : toVec32 a = toVecN 32 a := rfl

/-- As `ofVector_toVecN`, at width 32. -/
theorem ofVector_toVec32 (X : ByteArray) (h : X.size = 32) : ofVector (toVec32 X) = X := by
  rw [toVec32_eq_toVecN]; exact ofVector_toVecN X h

def xorBytes (a b : ByteArray) : ByteArray := ⟨a.data.mapIdx fun i x => x ^^^ b.data.getD i 0⟩

@[simp] theorem size_xorBytes (a b : ByteArray) : (xorBytes a b).size = a.size := by
  show (a.data.mapIdx _).size = a.size
  simp

/-- XOR against a fixed `b` is an involution. -/
theorem xorBytes_xorBytes (a b : ByteArray) : xorBytes (xorBytes a b) b = a := by
  ext i h
  · simp [xorBytes]
  · simp only [xorBytes, Array.getElem_mapIdx, Array.getD]
    split <;> simp [UInt8.xor_assoc, UInt8.xor_self]

/-- With a known keystream `ks`, `xorBytes · ks` can produce any `target`. -/
theorem xorBytes_achieves_any_target (ks target : ByteArray) :
    ∃ raw : ByteArray, xorBytes raw ks = target :=
  ⟨xorBytes target ks, xorBytes_xorBytes target ks⟩

/-- Byte `i` of `xorBytes a b`: `a[i] ^^^ b[i]` if `b` reaches that far, else `a[i]`. -/
theorem xorBytes_getElem (a b : ByteArray) (i : Nat) (hi : i < a.size) :
    (xorBytes a b)[i]'(by simp only [size_xorBytes]; exact hi)
      = a[i]'hi ^^^ (if h2 : i < b.size then b[i]'h2 else 0) := by
  simp only [xorBytes, ByteArray.getElem_eq_getElem_data]
  rw [Array.getElem_mapIdx]
  rw [Array.getD_eq_getD_getElem?]
  by_cases h2 : i < b.size
  · rw [dif_pos h2]
    have heq : b.data[i]? = some (b.data[i]'(by simpa using h2)) := by simp
    rw [heq, Option.getD_some]
  · rw [dif_neg h2]
    have heq : b.data[i]? = none := by
      rw [Array.getElem?_eq_none_iff]
      simpa using h2
    rw [heq, Option.getD_none]

/-- `xorBytes` distributes over `++` when widths match. -/
theorem xorBytes_append (a1 a2 b1 b2 : ByteArray) (h : a1.size = b1.size)
    (h' : a2.size ≤ b2.size) :
    xorBytes (a1 ++ a2) (b1 ++ b2) = xorBytes a1 b1 ++ xorBytes a2 b2 := by
  apply ByteArray.ext_getElem
  · simp [ByteArray.size_append]
  · intro i hi hi'
    have hi2 : i < (a1 ++ a2).size := by simp only [size_xorBytes] at hi; exact hi
    rw [xorBytes_getElem (a1 ++ a2) (b1 ++ b2) i hi2]
    by_cases h1 : i < a1.size
    · have h1' : i < b1.size := by rw [← h]; exact h1
      have h1bb : i < (b1 ++ b2).size := by simp only [ByteArray.size_append]; omega
      rw [ByteArray.getElem_append_left h1, dif_pos h1bb, ByteArray.getElem_append_left h1']
      have hi1' : i < (xorBytes a1 b1).size := by simpa using h1
      rw [ByteArray.getElem_append_left hi1', xorBytes_getElem a1 b1 i h1, dif_pos h1']
    · push Not at h1
      have h1'' : b1.size ≤ i := by rw [← h]; omega
      have hi2a : i < a1.size + a2.size := by simpa [ByteArray.size_append] using hi2
      have h1bb : i < (b1 ++ b2).size := by
        simp only [ByteArray.size_append]; omega
      rw [ByteArray.getElem_append_right h1, dif_pos h1bb, ByteArray.getElem_append_right h1'']
      have hi1' : (xorBytes a1 b1).size ≤ i := by simp only [size_xorBytes]; omega
      rw [ByteArray.getElem_append_right hi1']
      have hi2' : i - (xorBytes a1 b1).size < a2.size := by
        simp only [size_xorBytes]; omega
      rw [xorBytes_getElem a2 b2 (i - (xorBytes a1 b1).size) (by simpa using hi2')]
      simp only [size_xorBytes]
      rw [dif_pos (by omega : i - a1.size < b2.size)]
      congr 2
      omega

/-- `xorBytes` is commutative when both sides have the same width. -/
theorem xorBytes_comm_of_size_eq (a b : ByteArray) (h : a.size = b.size) :
    xorBytes a b = xorBytes b a := by
  apply ByteArray.ext_getElem
  · simp [h]
  · intro i hi hi'
    have hia : i < a.size := by simpa using hi
    have hib : i < b.size := by simpa using hi'
    rw [xorBytes_getElem a b i hia, xorBytes_getElem b a i hib, dif_pos (h ▸ hia : i < b.size),
      dif_pos (h ▸ hib : i < a.size)]
    exact UInt8.xor_comm _ _

/-- XOR against an all-zero buffer of matching width is the identity. -/
theorem xorBytes_zero_left (n : Nat) (X : ByteArray) (h : n = X.size) :
    xorBytes (⟨Array.replicate n 0⟩ : ByteArray) X = X := by
  apply ByteArray.ext_getElem
  · rw [size_xorBytes]
    show (Array.replicate n (0 : UInt8)).size = X.size
    rw [Array.size_replicate]; exact h
  · intro i hi hi'
    have hin : i < (⟨Array.replicate n 0⟩ : ByteArray).size := by
      have hi2 := hi
      rwa [size_xorBytes] at hi2
    rw [xorBytes_getElem (⟨Array.replicate n 0⟩ : ByteArray) X i hin, dif_pos (h ▸ hi' : i < X.size)]
    have hin2 : i < (Array.replicate n (0 : UInt8)).size := hin
    have hzero : (⟨Array.replicate n 0⟩ : ByteArray)[i]'hin = (0 : UInt8) := by
      show (Array.replicate n (0 : UInt8))[i]'hin2 = 0
      rw [Array.getElem_replicate]
    rw [hzero]
    simp

/-- Cascading padding (§3.2), at the byte level: XOR-ing the sender's
`Rk := xorBytes (riFragment ++ Rk1) riKeyStream` against the full keystream `ks` recovers
`riFragment ++ Rk1` in its first `ksLen` bytes and the next padding in its trailing bytes. -/
theorem cascading_xor_step (ks riFragment Rk1 prevPad : ByteArray) (ksLen perHop : Nat)
    (hks : ks.size = ksLen + prevPad.size + perHop) (hRk1 : riFragment.size + Rk1.size = ksLen) :
    (xorBytes (xorBytes (riFragment ++ Rk1) (ks.extract 0 ksLen) ++ prevPad
        ++ (⟨Array.replicate perHop 0⟩ : ByteArray)) ks).extract 0 ksLen
      = riFragment ++ Rk1 ∧
    (xorBytes (xorBytes (riFragment ++ Rk1) (ks.extract 0 ksLen) ++ prevPad
        ++ (⟨Array.replicate perHop 0⟩ : ByteArray)) ks).extract ksLen (ksLen + prevPad.size + perHop)
      = xorBytes ((ks.extract ksLen ks.size).extract 0 prevPad.size) prevPad
        ++ (ks.extract ksLen ks.size).extract prevPad.size (ks.extract ksLen ks.size).size := by
  have hzsize : (⟨Array.replicate perHop 0⟩ : ByteArray).size = perHop := Array.size_replicate
  have hRksize : (ks.extract 0 ksLen).size = ksLen := by rw [ByteArray.size_extract]; omega
  have hthisPad0size : (ks.extract ksLen ks.size).size = prevPad.size + perHop := by
    rw [ByteArray.size_extract]; omega
  have hRk_def_size : (xorBytes (riFragment ++ Rk1) (ks.extract 0 ksLen)).size = ksLen := by
    rw [size_xorBytes, ByteArray.size_append]; omega
  have hprevpadle : prevPad.size ≤ (ks.extract ksLen ks.size).size := by rw [hthisPad0size]; omega
  have hRfk1size : (riFragment ++ Rk1).size = ksLen := by rw [ByteArray.size_append]; omega
  -- Generalize the two extracts first, so `rw` does not substitute `ks` inside them.
  generalize hrKS : ks.extract 0 ksLen = riKeyStream at hRksize hRk_def_size ⊢
  generalize htp : ks.extract ksLen ks.size = thisPad0 at hthisPad0size hprevpadle ⊢
  have hks_eq : ks = riKeyStream ++ thisPad0 := by
    rw [← hrKS, ← htp]; exact (append_extract ks ksLen (by omega)).symm
  have hthisPad0_eq : thisPad0 = thisPad0.extract 0 prevPad.size
      ++ thisPad0.extract prevPad.size thisPad0.size :=
    (append_extract thisPad0 prevPad.size hprevpadle).symm
  have hpad2 : xorBytes (prevPad ++ (⟨Array.replicate perHop 0⟩ : ByteArray)) thisPad0
      = xorBytes (thisPad0.extract 0 prevPad.size) prevPad
        ++ thisPad0.extract prevPad.size thisPad0.size := by
    conv_lhs => rw [hthisPad0_eq]
    rw [xorBytes_append prevPad (⟨Array.replicate perHop 0⟩ : ByteArray)
        (thisPad0.extract 0 prevPad.size) (thisPad0.extract prevPad.size thisPad0.size)
        (by rw [ByteArray.size_extract]; omega)
        (by rw [hzsize, ByteArray.size_extract]; omega)]
    rw [xorBytes_comm_of_size_eq prevPad (thisPad0.extract 0 prevPad.size)
        (by rw [ByteArray.size_extract]; omega)]
    rw [xorBytes_zero_left perHop (thisPad0.extract prevPad.size thisPad0.size)
        (by rw [ByteArray.size_extract]; omega)]
  have hxor : xorBytes (xorBytes (riFragment ++ Rk1) riKeyStream ++ prevPad
      ++ (⟨Array.replicate perHop 0⟩ : ByteArray)) ks
      = (riFragment ++ Rk1) ++ (xorBytes (thisPad0.extract 0 prevPad.size) prevPad
        ++ thisPad0.extract prevPad.size thisPad0.size) := by
    rw [hks_eq, ByteArray.append_assoc,
      xorBytes_append (xorBytes (riFragment ++ Rk1) riKeyStream)
        (prevPad ++ (⟨Array.replicate perHop 0⟩ : ByteArray)) riKeyStream thisPad0
        (by rw [hRk_def_size, hRksize])
        (by rw [ByteArray.size_append, hzsize, hthisPad0size])]
    rw [xorBytes_xorBytes, hpad2]
  refine ⟨?_, ?_⟩
  · rw [hxor, extract_append_le (riFragment ++ Rk1) _ (by omega : (riFragment ++ Rk1).size ≤ ksLen)]
    rw [show ksLen - (riFragment ++ Rk1).size = 0 from by omega, ByteArray.extract_same,
      ByteArray.append_empty]
  · rw [hxor, extract_append_of_ge (riFragment ++ Rk1) _
      (by omega : (riFragment ++ Rk1).size ≤ ksLen)]
    rw [show ksLen - (riFragment ++ Rk1).size = 0 from by omega,
      show ksLen + prevPad.size + perHop - (riFragment ++ Rk1).size = prevPad.size + perHop
        from by omega]
    have hpadsizeeq : (xorBytes (thisPad0.extract 0 prevPad.size) prevPad
        ++ thisPad0.extract prevPad.size thisPad0.size).size = prevPad.size + perHop := by
      rw [ByteArray.size_append, size_xorBytes, ByteArray.size_extract, ByteArray.size_extract,
        hthisPad0size]
      omega
    rw [← hpadsizeeq]
    exact ByteArray.extract_zero_size

theorem Except.eq_ok_of_map_eq_ok {ε α β : Type} {f : α → β} {e : Except ε α} {b : β}
    (h : f <$> e = Except.ok b) : ∃ a, e = Except.ok a ∧ f a = b := by
  cases e with
  | error _ => simp at h
  | ok a => exact ⟨a, rfl, by simpa using h⟩

theorem Except.eq_ok_of_bind_eq_ok {ε α β : Type} {e : Except ε α} {f : α → Except ε β} {b : β}
    (h : e >>= f = Except.ok b) : ∃ a, e = Except.ok a ∧ f a = Except.ok b := by
  cases e with
  | error _ => injection h
  | ok a => exact ⟨a, rfl, h⟩

/-- A `forIn` whose every step leaves `φ` unchanged leaves it unchanged overall. -/
theorem List.forIn_congr_of_forall_mem {α β ε γ : Type} (l : List β)
    (f : β → α → Except ε (ForInStep α)) (φ : α → γ)
    (hyield : ∀ (a a' : α) (b : β), b ∈ l → f b a = Except.ok (ForInStep.yield a') → φ a' = φ a)
    (hdone : ∀ (a a' : α) (b : β), b ∈ l → f b a = Except.ok (ForInStep.done a') → φ a' = φ a) :
    ∀ (init final : α), forIn l init f = Except.ok final → φ final = φ init := by
  induction l with
  | nil =>
    intro init final hfinal
    simp only [List.forIn_nil] at hfinal
    injection hfinal with hfinal
    simp [← hfinal]
  | cons b bs ih =>
    intro init final hfinal
    rw [List.forIn_cons] at hfinal
    obtain ⟨step, hstep, hfinal'⟩ := Except.eq_ok_of_bind_eq_ok hfinal
    cases step with
    | yield a' =>
      simp only at hfinal'
      rw [ih (fun a a' b' hb' hgb' => hyield a a' b' (List.mem_cons_of_mem b hb') hgb')
        (fun a a' b' hb' hgb' => hdone a a' b' (List.mem_cons_of_mem b hb') hgb') a' final hfinal']
      exact hyield init a' b List.mem_cons_self hstep
    | done a' =>
      simp only at hfinal'
      injection hfinal' with hfinal'
      rw [← hfinal']
      exact hdone init a' b List.mem_cons_self hstep

/-- A `forIn` that never exits early and grows `φ` by `k` per step grows it by `l.length * k`. -/
theorem List.forIn_add_of_forall_mem {α β ε : Type} (l : List β)
    (f : β → α → Except ε (ForInStep α)) (φ : α → ℕ) (k : ℕ)
    (hyield : ∀ (a a' : α) (b : β), b ∈ l → f b a = Except.ok (ForInStep.yield a') → φ a' = φ a + k)
    (hdone : ∀ (a a' : α) (b : β), b ∈ l → f b a = Except.ok (ForInStep.done a') → False) :
    ∀ (init final : α), forIn l init f = Except.ok final → φ final = φ init + l.length * k := by
  induction l with
  | nil =>
    intro init final hfinal
    simp only [List.forIn_nil] at hfinal
    injection hfinal with hfinal
    simp [← hfinal]
  | cons b bs ih =>
    intro init final hfinal
    rw [List.forIn_cons] at hfinal
    obtain ⟨step, hstep, hfinal'⟩ := Except.eq_ok_of_bind_eq_ok hfinal
    cases step with
    | yield a' =>
      simp only at hfinal'
      rw [ih (fun a a' b' hb' hgb' => hyield a a' b' (List.mem_cons_of_mem b hb') hgb')
        (fun a a' b' hb' hgb' => hdone a a' b' (List.mem_cons_of_mem b hb') hgb') a' final hfinal',
        hyield init a' b List.mem_cons_self hstep, List.length_cons]
      ring
    | done a' =>
      exact absurd hstep (fun hh => hdone init a' b List.mem_cons_self hh)

/-- A `forIn` over a nonempty list that never exits early and sets `ψ` to `v` at every step ends
with `ψ = v`. -/
theorem List.forIn_const_of_forall_mem {α β ε γ : Type} (l : List β) (hl : l ≠ [])
    (f : β → α → Except ε (ForInStep α)) (ψ : α → γ) (v : γ)
    (hyield : ∀ (a a' : α) (b : β), b ∈ l → f b a = Except.ok (ForInStep.yield a') → ψ a' = v)
    (hdone : ∀ (a a' : α) (b : β), b ∈ l → f b a = Except.ok (ForInStep.done a') → False) :
    ∀ (init final : α), forIn l init f = Except.ok final → ψ final = v := by
  induction l with
  | nil => exact absurd rfl hl
  | cons b bs ih =>
    intro init final hfinal
    rw [List.forIn_cons] at hfinal
    obtain ⟨step, hstep, hfinal'⟩ := Except.eq_ok_of_bind_eq_ok hfinal
    cases step with
    | yield a' =>
      simp only at hfinal'
      by_cases hbsnil : bs = []
      · subst hbsnil
        simp only [List.forIn_nil] at hfinal'
        injection hfinal' with hfinal'
        rw [← hfinal']
        exact hyield init a' b List.mem_cons_self hstep
      · exact ih hbsnil (fun a a' b' hb' hgb' => hyield a a' b' (List.mem_cons_of_mem b hb') hgb')
          (fun a a' b' hb' hgb' => hdone a a' b' (List.mem_cons_of_mem b hb') hgb') a' final hfinal'
    | done a' =>
      exact absurd hstep (fun hh => hdone init a' b List.mem_cons_self hh)

/-- A `forIn` that never exits early has a trace of intermediate accumulator values. -/
theorem List.forIn_exists_trace {α β ε : Type} (l : List β) (f : β → α → Except ε (ForInStep α))
    (hnd : ∀ (b : β) (a a' : α), b ∈ l → f b a ≠ Except.ok (ForInStep.done a')) :
    ∀ (init final : α), forIn l init f = Except.ok final →
      ∃ s : Nat → α, s 0 = init ∧ s l.length = final ∧
        ∀ j (hj : j < l.length), f (l[j]'hj) (s j) = Except.ok (ForInStep.yield (s (j + 1))) := by
  induction l with
  | nil =>
    intro init final hfinal
    simp only [List.forIn_nil, pure, Except.pure, Except.ok.injEq] at hfinal
    exact ⟨fun _ => init, rfl, hfinal, by simp⟩
  | cons hd tl ih =>
    intro init final hfinal
    rw [List.forIn_cons] at hfinal
    obtain ⟨r, hr, hfinal2⟩ := Except.eq_ok_of_bind_eq_ok hfinal
    cases r with
    | done a' => exact absurd hr (hnd hd init a' List.mem_cons_self)
    | yield a =>
      simp only [] at hfinal2
      have hnd' : ∀ (b : β) (a a' : α), b ∈ tl → f b a ≠ Except.ok (ForInStep.done a') :=
        fun b a a' hb => hnd b a a' (List.mem_cons_of_mem hd hb)
      obtain ⟨s, hs0, hsl, hstep⟩ := ih hnd' a final hfinal2
      refine ⟨fun j => match j with | 0 => init | j' + 1 => s j', rfl, ?_, ?_⟩
      · show s tl.length = final
        exact hsl
      · intro j hj
        cases j with
        | zero =>
          show f hd init = Except.ok (ForInStep.yield (s 0))
          rw [hs0]; exact hr
        | succ j' =>
          have hj' : j' < tl.length := by simpa using hj
          show f (tl[j']'hj') (s j') = Except.ok (ForInStep.yield (s (j' + 1)))
          exact hstep j' hj'

/-- `l.foldl g init` has a trace of intermediate accumulator values. -/
theorem List.foldl_exists_trace {α β : Type} (l : List β) (g : α → β → α) (init : α) :
    ∃ s : Nat → α, s 0 = init ∧ s l.length = l.foldl g init ∧
      ∀ j (hj : j < l.length), s (j + 1) = g (s j) (l[j]'hj) := by
  induction l generalizing init with
  | nil => exact ⟨fun _ => init, rfl, rfl, by simp⟩
  | cons hd tl ih =>
    obtain ⟨s, hs0, hsl, hstep⟩ := ih (g init hd)
    refine ⟨fun j => match j with | 0 => init | j' + 1 => s j', rfl, ?_, ?_⟩
    · show s tl.length = (hd :: tl).foldl g init
      rw [List.foldl_cons]; exact hsl
    · intro j hj
      cases j with
      | zero =>
        show s 0 = g init ((hd :: tl)[0]'hj)
        exact hs0
      | succ j' =>
        have hj' : j' < tl.length := by simpa using hj
        show s (j' + 1) = g (s j') ((hd :: tl)[j' + 1]'hj)
        exact hstep j' hj'

/-- Pushing onto an array never disturbs an existing index. -/
theorem Array.getElem!_push_stable {α : Type} [Inhabited α] (a : Array α) (x : α) (i : Nat)
    (h : i < a.size) : (a.push x)[i]! = a[i]! := by
  rw [getElem!_pos (a.push x) i (by rw [Array.size_push]; omega), getElem!_pos a i h,
    Array.getElem_push_lt h]

/-- In a sequence of arrays each obtained from the last by one push, index `i` never changes after
it is written. -/
theorem Array.getElem!_stable_of_pushes {α : Type} [Inhabited α] (t : Nat → Array α) (n : Nat)
    (hpush : ∀ j, j < n → ∃ x, t (j + 1) = (t j).push x) (hsize : ∀ j, j ≤ n → (t j).size = j) :
    ∀ i m, i < m → m ≤ n → (t m)[i]! = (t (i + 1))[i]! := by
  intro i m him hmn
  induction m with
  | zero => omega
  | succ m ih =>
    rcases Nat.lt_or_ge i m with h | h
    · obtain ⟨x, hx⟩ := hpush m (by omega)
      rw [hx, Array.getElem!_push_stable _ _ _ (by rw [hsize m (by omega)]; omega), ih h (by omega)]
    · have hie : i = m := by omega
      rw [hie]

def mac (key : Vector UInt8 32) (msg : ByteArray) : Vector UInt8 32 := hmacSha256 (ofVector key) msg

def zeroPadTo (n : Nat) (b : ByteArray) : ByteArray :=
  if b.size ≥ n then b else b ++ ⟨Array.replicate (n - b.size) 0⟩

/-- `ByteArray.size` unfolding restricted to a literal `⟨_⟩`, avoiding a simp loop. -/
@[simp] private theorem byteArray_mk_size (a : Array UInt8) : (⟨a⟩ : ByteArray).size = a.size := rfl

/-- `zeroPadTo n b` has size `n` when `b.size ≤ n`. -/
theorem zeroPadTo_size {n : Nat} {b : ByteArray} (h : b.size ≤ n) : (zeroPadTo n b).size = n := by
  unfold zeroPadTo
  split
  · omega
  · simp only [ByteArray.size_append, byteArray_mk_size, Array.size_replicate]
    omega

/-- `zeroPadTo`, as an explicit append. -/
theorem zeroPadTo_eq_append (b : ByteArray) (n : Nat) (h : b.size ≤ n) :
    zeroPadTo n b = b ++ ⟨Array.replicate (n - b.size) 0⟩ := by
  unfold zeroPadTo
  split
  · next hge =>
    have hz : n - b.size = 0 := by omega
    rw [hz]
    show b = b ++ ByteArray.empty
    rw [ByteArray.append_empty]
  · rfl

theorem replicate_extract (k lo hi : Nat) (h : hi ≤ k) :
    (⟨Array.replicate k (0 : UInt8)⟩ : ByteArray).extract lo hi = ⟨Array.replicate (hi - lo) 0⟩ := by
  apply ByteArray.ext_getElem
  · simp [ByteArray.size_extract]; omega
  · intro i h1 h2
    have hik : lo + i < (Array.replicate k (0 : UInt8)).size := by
      rw [Array.size_replicate]
      simp [ByteArray.size_extract] at h1
      omega
    have hij : i < (Array.replicate (hi - lo) (0 : UInt8)).size := by
      rw [Array.size_replicate]; simpa using h2
    simp only [ByteArray.getElem_extract]
    show (Array.replicate k (0:UInt8))[lo + i]'hik = (Array.replicate (hi - lo) (0:UInt8))[i]'hij
    rw [Array.getElem_replicate, Array.getElem_replicate]

/-- Serialize `cmds`, failing if the result exceeds `budget` bytes. -/
def commandsToBytes (budget : Nat) (cmds : List RoutingCommand) : Except String ByteArray := do
  let b := cmds.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty
  if b.size > budget then
    throw "sphinx: invalid commands, oversized serialized block"
  pure b

/-- A successful `commandsToBytes` fits within `budget`. -/
theorem commandsToBytes_size_le {budget : Nat} {cmds : List RoutingCommand} {b : ByteArray}
    (h : commandsToBytes budget cmds = .ok b) : b.size ≤ budget := by
  unfold commandsToBytes at h
  dsimp only at h
  split at h
  · injection h
  · next hle =>
      injection h with h
      rw [← h]
      omega

/-- Appending one command to a successful `commandsToBytes` call still succeeds, under a large
enough budget. -/
theorem commandsToBytes_append_singleton {budget budget' : Nat} {cmds : List RoutingCommand}
    {b : ByteArray} (hcb : commandsToBytes budget' cmds = .ok b) (c : RoutingCommand)
    (hbudget : b.size + c.toBytes.size ≤ budget) :
    commandsToBytes budget (cmds ++ [c]) = .ok (b ++ c.toBytes) := by
  have hbeq : b = cmds.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty := by
    unfold commandsToBytes at hcb
    dsimp only at hcb
    split at hcb
    · injection hcb
    · injection hcb with hcb; exact hcb.symm
  unfold commandsToBytes
  dsimp only
  have hfold : (cmds ++ [c]).foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty
      = b ++ c.toBytes := by
    rw [List.foldl_append, List.foldl_cons, List.foldl_nil, ← hbeq]
  rw [hfold]
  have hle : ¬ (b ++ c.toBytes).size > budget := by
    rw [ByteArray.size_append]; omega
  simp only [hle, if_false, pure, Except.pure]

/-- `parseAll` undoes `commandsToBytes` followed by `zeroPadTo`, given no `.null` commands. -/
theorem parseAll_commandsToBytes (n budget : Nat) (cmds : List RoutingCommand)
    (hn : ∀ c ∈ cmds, c ≠ .null) (b : ByteArray)
    (hcb : commandsToBytes budget cmds = .ok b) (_hble : b.size ≤ n) :
    parseAll (zeroPadTo n b) = .ok cmds := by
  have hbeq : b = cmds.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty := by
    unfold commandsToBytes at hcb
    dsimp only at hcb
    split at hcb
    · injection hcb
    · injection hcb with hcb; exact hcb.symm
  unfold zeroPadTo
  split
  · next hge =>
    have := parseAll_append_zeros cmds hn ByteArray.empty (by simp)
    rwa [ByteArray.append_empty, ← hbeq] at this
  · next hlt =>
    have hzeros : ((⟨Array.replicate (n - b.size) 0⟩ : ByteArray)).data.all (· == 0) := by
      rw [Array.all_eq_true]
      intro i hi
      simp [Array.getElem_replicate]
    have := parseAll_append_zeros cmds hn (⟨Array.replicate (n - b.size) 0⟩ : ByteArray) hzeros
    rwa [← hbeq] at this

/-- A fold whose step preserves `ByteArray` size preserves it overall. -/
theorem List.foldl_size_preserving {α : Type} (l : List α) (step : ByteArray → α → ByteArray)
    (hstep : ∀ b a, (step b a).size = b.size) (init : ByteArray) :
    (l.foldl step init).size = init.size := by
  induction l generalizing init with
  | nil => rfl
  | cons hd tl ih => rw [List.foldl_cons, ih, hstep]

/-- If every step of a `forIn` only pushes a `ByteArray` of size `n`, and the initial array's
entries all have size `n`, so do the final array's. -/
theorem List.forIn_push_size_of_forall_mem {α β ε : Type} (l : List β) (n : Nat)
    (π : α → Array ByteArray) (f : β → α → Except ε (ForInStep α))
    (hyield : ∀ (a a' : α) (b : β), b ∈ l →
      f b a = Except.ok (ForInStep.yield a') → ∃ x, x.size = n ∧ π a' = (π a).push x)
    (hdone : ∀ (a a' : α) (b : β), b ∈ l →
      f b a = Except.ok (ForInStep.done a') → False) :
    ∀ (init final : α), (∀ j (hj : j < (π init).size), ((π init)[j]'hj).size = n) →
      forIn l init f = Except.ok final →
      ∀ j (hj : j < (π final).size), ((π final)[j]'hj).size = n := by
  induction l with
  | nil =>
    intro init final hinit hfinal
    simp only [List.forIn_nil] at hfinal
    injection hfinal with hfinal
    rw [← hfinal]; exact hinit
  | cons b bs ih =>
    intro init final hinit hfinal
    rw [List.forIn_cons] at hfinal
    obtain ⟨step, hstep, hfinal'⟩ := Except.eq_ok_of_bind_eq_ok hfinal
    cases step with
    | yield a' =>
      simp only at hfinal'
      obtain ⟨x, hx, hxeq⟩ := hyield init a' b List.mem_cons_self hstep
      have hinit' : ∀ j (hj : j < (π a').size), ((π a')[j]'hj).size = n := by
        rw [hxeq]
        intro j hj
        simp only [Array.size_push] at hj
        rcases Nat.lt_or_ge j (π init).size with hjlt | hjge
        · rw [Array.getElem_push_lt hjlt]
          exact hinit j hjlt
        · have hje : j = (π init).size := by omega
          subst hje
          rw [Array.getElem_push_eq]
          exact hx
      exact ih (fun a a' b' hb' hgb' => hyield a a' b' (List.mem_cons_of_mem b hb') hgb')
        (fun a a' b' hb' hgb' => hdone a a' b' (List.mem_cons_of_mem b hb') hgb') a' final hinit' hfinal'
    | done a' =>
      exact absurd hstep (fun hh => hdone init a' b List.mem_cons_self hh)

end Cryptlib.Protocols.Sphinx.Common

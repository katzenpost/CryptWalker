/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Geometry
import CryptWalker.Sphinx.Commands
import CryptWalker.Sphinx.Crypto.HMAC
import CryptWalker.Util.Bytes

/-! # Helpers shared by NIKE-Sphinx and KEM-Sphinx

`sphinx.go`/`kemsphinx.go` share these via `package sphinx` (`v0AD`, `xorBytes`,
`commandsToBytes` as a `*Sphinx` method, etc.); `NIKESphinx`/`KEMSphinx` share them via this
file instead, since Lean's `private` is file-scoped. -/

namespace CryptWalker.Sphinx.Common

open CryptWalker.Sphinx.Geometry (Geometry)
open CryptWalker.Sphinx.Commands
open CryptWalker.Sphinx.Crypto.HMAC (hmacSha256)
open CryptWalker.Util.Bytes (ofVector size_ofVector extract_append_le extract_append_of_le
  extract_append_of_ge append_extract)

def v0AD : ByteArray := ⟨#[0, 0]⟩

def toVec32 (a : ByteArray) : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => a.get! i.val

/-- As `toVec32`, but for a byte width chosen at the call site rather than fixed to 32 — what a
NIKE/KEM-generic caller needs, since a scheme's own `publicKeySize`/`privateKeySize`/
`sharedSecretSize`/`ciphertextSize` aren't necessarily 32. -/
def toVecN (n : Nat) (a : ByteArray) : Vector UInt8 n := Vector.ofFn fun i : Fin n => a.get! i.val

/-- `toVecN` undoes `ofVector`: reinterpreting an already-fixed-width vector's own bytes at that
same width recovers it exactly. Bridges an encode/decode round trip (`decodePrivateKey
(encodePrivateKey sk) = some sk`-shaped, e.g. `KEM.decode_encode_priv`) stated over `Vector UInt8
n` into one stated over the raw `ByteArray` a caller like `KEMSphinx.kemSelfPublicKeyBytes`
actually has in hand. -/
@[simp] theorem toVecN_ofVector {n : Nat} (v : Vector UInt8 n) : toVecN n (ofVector v) = v := by
  apply Vector.ext
  intro i hi
  simp only [toVecN, Vector.getElem_ofFn]
  show (ofVector v).get! i = v[i]
  show v.toArray[i]! = v[i]
  simp [getElem!_pos, hi]

/-- `ofVector` undoes `toVecN`, the other direction from `toVecN_ofVector`: reinterpreting a
byte string of exactly the right width as a fixed-size vector and back is the identity. Bridges
`unwrapKEM`'s `nextCiphertext := ofVector (toVecN kem.ciphertextSize ...)` back into a bare
`ByteArray` equality. -/
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

/-- As `ofVector_toVecN`, at the fixed 32-byte width `toVec32` uses. -/
theorem ofVector_toVec32 (X : ByteArray) (h : X.size = 32) : ofVector (toVec32 X) = X := by
  rw [toVec32_eq_toVecN]; exact ofVector_toVecN X h

def xorBytes (a b : ByteArray) : ByteArray := ⟨a.data.mapIdx fun i x => x ^^^ b.data.getD i 0⟩

@[simp] theorem size_xorBytes (a b : ByteArray) : (xorBytes a b).size = a.size := by
  show (a.data.mapIdx _).size = a.size
  simp

/-- XOR against a fixed `b` is its own inverse. This is the whole reason a known keystream lets
you hit *any* target plaintext exactly: encrypt the target with the same `b` you'll decrypt
with, and decryption returns it unchanged. -/
theorem xorBytes_xorBytes (a b : ByteArray) : xorBytes (xorBytes a b) b = a := by
  ext i h
  · simp [xorBytes]
  · simp only [xorBytes, Array.getElem_mapIdx, Array.getD]
    split <;> simp [UInt8.xor_assoc, UInt8.xor_self]

/-- Whoever knows a keystream `ks` can make `xorBytes · ks` decrypt to *any* chosen `target`:
encrypt `target` with `ks` first, by `xorBytes_xorBytes`. This is the general fact behind
`KEMSphinx`'s failure of wrap-resistance — a known-key adversary hits an arbitrary target with
certainty, not merely with some bounded probability. -/
theorem xorBytes_achieves_any_target (ks target : ByteArray) :
    ∃ raw : ByteArray, xorBytes raw ks = target :=
  ⟨xorBytes target ks, xorBytes_xorBytes target ks⟩

/-- `xorBytes`'s `i`-th byte, spelled out: XOR `a`'s own `i`-th byte against `b`'s if `b` reaches
that far, or against `0` (unchanged) otherwise — the `getD` in `xorBytes`'s definition, made
explicit as an ordinary `if`. -/
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

/-- **`xorBytes` distributes over `++`**, given the two left-hand pieces match the two
right-hand pieces in width: XOR-ing a concatenation against another of the same shape is the same
as XOR-ing the pieces separately and reassembling. Lets a multi-hop XOR argument work one
byte-range at a time instead of only on whole buffers — the byte-level heart of the
cascading-padding argument (`a1`/`a2` the routing-info slot split at a hop boundary, `b1`/`b2` the
matching split of the keystream). -/
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
    · push_neg at h1
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

/-- `xorBytes` is commutative once the two sides agree in width — not in general, since `xorBytes
a b` pads a short `b` with zeros using `a`'s own length. Matches how the cascading-padding
argument needs to swap the two operands of one of `kemRiFragment`'s XORs mid-derivation. -/
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

/-- XOR-ing against an all-zero buffer of matching width is the identity — the trailing "as-is"
half of the cascading-padding argument's recursive step, where the receiver's zero-padded tail
XORs against the keystream's own trailing bytes unchanged. -/
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

/-- **The cascading-padding argument, at the byte level.** The core mathematical crux of Sphinx's
completeness (Danezis–Goldberg §3.2): given the sender's `Rk := xorBytes (riFragment ++ Rk1)
riKeyStream` (where `riKeyStream` is the exact-length prefix `ks.extract 0 ksLen` of the full
keystream `ks` requested at this hop), the *receiver*'s single XOR against the *whole* `ks`
recovers `riFragment ++ Rk1` in its first `ksLen` bytes (`xorBytes_xorBytes` cancels the
sender's own construction exactly) and reproduces `riPadding`'s own recursive definition
term-for-term in its trailing bytes (`prevPad` cascaded against `ks`'s own tail, zeros left
unchanged) — the two halves of `loop3`/`loop2`'s constructions the receiver's one XOR undoes at
once. Fully generic in `ks`/`riFragment`/`Rk1`/`prevPad` — no `KEM`/`NIKE` dependence, so both
`KEMSphinx.lean` and `NIKESphinx.lean` share this one copy. -/
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
  -- Abstract the two extracts as opaque values before touching `ks` itself, to avoid `rw`
  -- re-substituting `ks` inside its own extract subterms (the term-blowup trap).
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

/-- A `List.foldl` step that leaves some projection `φ` of the accumulator alone at every element
of `l` leaves `φ` alone overall — the general shape behind `createHeader`'s "this loop never
touches `groupElements[0]!`" invariant. -/
theorem foldl_congr_of_forall_mem {α β γ : Type} (l : List β) (g : α → β → α) (φ : α → γ)
    (h : ∀ a b, b ∈ l → φ (g a b) = φ a) (init : α) :
    φ (l.foldl g init) = φ init := by
  induction l generalizing init with
  | nil => rfl
  | cons b bs ih =>
    rw [List.foldl_cons, ih (fun a b' hb' => h a b' (List.mem_cons_of_mem b hb'))]
    exact h init b List.mem_cons_self

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

/-- As `foldl_congr_of_forall_mem`, for an `Except`-monadic fold: if every step that *succeeds*
adds a fixed `k` to `φ`, and the whole fold succeeds, `φ` grew by `l.length * k` overall. This is
what lets a `for`-loop that can fail (like `createHeader`'s routing-info assembly, via
`commandsToBytes`) still support an exact size bound once it's known to have succeeded. -/
theorem foldlM_add_of_forall_mem {α β ε : Type} (l : List β) (g : α → β → Except ε α) (φ : α → ℕ)
    (k : ℕ) (h : ∀ (a a' : α) (b : β), b ∈ l → g a b = Except.ok a' → φ a' = φ a + k) :
    ∀ (init final : α), l.foldlM g init = Except.ok final → φ final = φ init + l.length * k := by
  induction l with
  | nil =>
    intro init final hfinal
    simp only [List.foldlM_nil] at hfinal
    injection hfinal with hfinal
    simp [← hfinal]
  | cons b bs ih =>
    intro init final hfinal
    rw [List.foldlM_cons] at hfinal
    obtain ⟨a', ha', hfinal'⟩ := Except.eq_ok_of_bind_eq_ok hfinal
    rw [ih (fun a a' b' hb' hgb' => h a a' b' (List.mem_cons_of_mem b hb') hgb') a' final hfinal',
      h init a' b List.mem_cons_self ha', List.length_cons]
    ring

/-- As `foldl_congr_of_forall_mem`, for an `Except`-monadic fold: if every step that *succeeds*
leaves `φ` unchanged, and the whole fold succeeds, `φ` is unchanged overall — regardless of
whatever else that step does or how it can fail. This is what lets a loop whose body now has a
new failure path (e.g. a NIKE decode/safety check) still support an invariant that never actually
depended on that path. -/
theorem foldlM_congr_of_forall_mem {α β ε γ : Type} (l : List β) (g : α → β → Except ε α) (φ : α → γ)
    (h : ∀ (a a' : α) (b : β), b ∈ l → g a b = Except.ok a' → φ a' = φ a) :
    ∀ (init final : α), l.foldlM g init = Except.ok final → φ final = φ init := by
  induction l with
  | nil =>
    intro init final hfinal
    simp only [List.foldlM_nil] at hfinal
    injection hfinal with hfinal
    simp [← hfinal]
  | cons b bs ih =>
    intro init final hfinal
    rw [List.foldlM_cons] at hfinal
    obtain ⟨a', ha', hfinal'⟩ := Except.eq_ok_of_bind_eq_ok hfinal
    rw [ih (fun a a' b' hb' hgb' => h a a' b' (List.mem_cons_of_mem b hb') hgb') a' final hfinal',
      h init a' b List.mem_cons_self ha']

/-- As `foldlM_congr_of_forall_mem`, directly for a `for`-loop (`List.forIn`) rather than a
`foldlM` — lets a loop whose step can `.done`-exit early (none of this project's loops do, but the
general `forIn` shape allows it) still support an invariant that doesn't depend on that path. -/
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

/-- As `List.forIn_congr_of_forall_mem`, but for a loop that *grows* `φ` by a fixed `k` at every
successful step rather than leaving it unchanged — what `createHeader`/`createKEMHeader`'s
routing-info assembly loop needs (`φ` = the accumulated routing-info block's size, `k` =
`geom.perHopRoutingInfoLength`). None of this project's loops ever exit via `.done` (no `break`),
so `hdone` only needs to rule that outcome out, not describe it. -/
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

/-- As `List.forIn_congr_of_forall_mem`, but for a loop whose step *overwrites* `ψ` to a fixed
value `v` at every successful step (rather than leaving it unchanged) — what
`createHeader`/`createKEMHeader`'s routing-info loop needs for its `macBytes` component: every
iteration recomputes it fresh from `mac`, always 32 bytes, regardless of what it was before. Needs
`l ≠ []` (unlike `forIn_add_of_forall_mem`'s `+k`, which is vacuously true at `0`): an empty loop
never overwrites anything, so `ψ`'s final value is just whatever `init` had. -/
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

/-- **The full trace of a `forIn` loop**, when it never exits early: not just a size/count/overwrite
invariant (the three lemmas above), but the *entire* sequence of intermediate accumulator values,
recoverable one step at a time. `createKEMHeader`'s routing-info loop composes `kemRiFragment`, an
XOR, and a MAC in a way none of `forIn_congr_of_forall_mem`/`forIn_add_of_forall_mem`/
`forIn_const_of_forall_mem`'s single-invariant shapes can express — the multi-hop completeness
proof needs the actual per-hop values, not a derived numeric fact about them. Fully generic in the
step function `f`, so it costs nothing to state once here rather than duplicating the induction at
the call site. -/
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
      simp only [Except.pure] at hfinal2
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

/-- As `List.forIn_exists_trace`, for a plain (non-monadic) `List.foldl` instead of a `forIn` loop
that can throw or exit early: the trace of intermediate accumulator values through `l.foldl g init`,
recoverable one step at a time. What a loop body with no `throw`/`←` reduces to once
`List.forIn_pure_yield_eq_foldl` fires (`createKEMHeader`/`createHeader`'s per-hop keystream/padding
loop, e.g. — it never fails, so its own `forIn` collapses to a bare `foldl` under that simp lemma,
losing the `Except`-bind structure `forIn_exists_trace` was built for). -/
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

/-- **Array-index stability across a chain of pushes**: for a `Nat`-indexed sequence of arrays
each obtained from the last by pushing one element (`t (i+1)`'s size tracking `i+1`, as
`List.foldl_exists_trace`/`List.forIn_exists_trace`'s own traces do when the step is `Array.push`),
index `i`'s value is already fixed the moment it's first written — every later snapshot agrees
with `t (i+1)`, the first one big enough to contain it. Exactly what's needed to read
`riKeyStream[i]!`/`riPadding[i]!` off the loop's *final* array from a one-step fact proved about
the trace at step `i+1`. -/
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

/-- Targeted version of `ByteArray.size`'s unfolding, applying only to a literal `⟨_⟩` constructor
rather than an arbitrary `ByteArray`-valued term — as `AEZ.lean`'s `byteArray_mk_size`, avoids
touching a plain variable's `.size` (which desyncs it from unrelated hypotheses) and the
`ByteArray.size`/`ByteArray.size_data` simp-loop that arises from unfolding `.size` generically. -/
@[simp] private theorem byteArray_mk_size (a : Array UInt8) : (⟨a⟩ : ByteArray).size = a.size := rfl

/-- `zeroPadTo` only ever *grows* `b` up to exactly `n` — given the caller already knows
`b.size ≤ n` (as `createHeader`/`createKEMHeader` do, from `commandsToBytes`'s budget check), the
result is always exactly `n` bytes, not merely "at least `n`". -/
theorem zeroPadTo_size {n : Nat} {b : ByteArray} (h : b.size ≤ n) : (zeroPadTo n b).size = n := by
  unfold zeroPadTo
  split
  · omega
  · simp only [ByteArray.size_append, byteArray_mk_size, Array.size_replicate]
    omega

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

/-- Padding to a wider target and then taking a prefix that still reaches or exceeds the original
content is the same as padding to that narrower width directly — what lets `kemRiFragment`'s
terminal-hop fragment (zero-padded to the full per-hop budget) still support extracting just its
leading `perHopRoutingInfoLength - kem.ciphertextSize` bytes as if it had been padded to exactly
that width. -/
theorem zeroPadTo_extract_prefix {n m : Nat} (b : ByteArray) (h1 : b.size ≤ m) (h2 : m ≤ n) :
    (zeroPadTo n b).extract 0 m = zeroPadTo m b := by
  unfold zeroPadTo
  by_cases hbn : b.size ≥ n
  · have heqm : b.size = m := by omega
    rw [if_pos hbn, if_pos (show b.size ≥ m by omega), ← heqm, ByteArray.extract_zero_size]
  · by_cases hbm : b.size ≥ m
    · have heqm : b.size = m := by omega
      rw [if_neg hbn, if_pos hbm, ← heqm, extract_append_of_le b _ (le_refl b.size),
        ByteArray.extract_zero_size]
    · rw [if_neg hbn, if_neg hbm, extract_append_le b _ h1, replicate_extract _ _ _ (by omega)]
      simp

/-- Go's "leave spare room for one" check: `budget` is what's left of `perHopRoutingInfoLength`
for the caller's *own* commands once whatever `createHeader`/`createKEMHeader` appends
afterward (a `NextNodeHop` command, plus a KEM's embedded next-hop ciphertext) is accounted for. -/
def commandsToBytes (budget : Nat) (cmds : List RoutingCommand) : Except String ByteArray := do
  let b := cmds.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty
  if b.size > budget then
    throw "sphinx: invalid commands, oversized serialized block"
  pure b

/-- `commandsToBytes`'s only failure path is its own explicit budget check, so success always
means the serialized block fit within `budget`. -/
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

/-- Appending one more command to an already-successful `commandsToBytes` call, under a large
enough budget, still succeeds — with the obvious serialized content. What lets `createKEMHeader`'s
embedded `NextNodeHop` command (appended after a non-terminal hop's own `commandsToBytes` call
already succeeded) be re-characterized as a *single* `commandsToBytes` call over the extended
command list, matching what `parseAll_commandsToBytes` expects. -/
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
  simp only [hle, if_false, Bool.false_eq_true, pure, Except.pure]

/-- **`parseAll` undoes `commandsToBytes`/`zeroPadTo`** — the exact shape `KEMSphinx`/
`NIKESphinx`'s completeness proofs need: real commands serialized under a budget, then zero-padded
out to `n` bytes (or left alone, if they already reached or exceeded `n`), parse back to exactly
the same command list. Reduces to `Commands.parseAll_append_zeros`, which needs only that no
command in `cmds` is itself `.null` (so no real command's own tag byte could be mistaken for the
`0x00` terminator) — the terminator itself is never load-bearing for termination, since an
exactly-exhausted buffer stops parsing just as cleanly. -/
theorem parseAll_commandsToBytes (n budget : Nat) (cmds : List RoutingCommand)
    (hn : ∀ c ∈ cmds, c ≠ .null) (b : ByteArray)
    (hcb : commandsToBytes budget cmds = .ok b) (hble : b.size ≤ n) :
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

/-- A `List.foldl` whose step preserves a `ByteArray`'s size leaves the fold's overall size
unchanged — what `newNIKEPacket`/`newNIKESURB`'s (and their KEM counterparts') per-hop
`sprpEncrypt`/`sprpDecrypt` fold need, since each is length-preserving
(`AEZ.sprpEncrypt_size`/`sprpDecrypt_size`) regardless of how many hops the fold runs over. -/
theorem List.foldl_size_preserving {α : Type} (l : List α) (step : ByteArray → α → ByteArray)
    (hstep : ∀ b a, (step b a).size = b.size) (init : ByteArray) :
    (l.foldl step init).size = init.size := by
  induction l generalizing init with
  | nil => rfl
  | cons hd tl ih => rw [List.foldl_cons, ih, hstep]

/-- What `createKEMHeader`'s per-hop encapsulation loop needs for its `kemElements` array: if
every successful step only ever *pushes* one more fixed-size `ByteArray` (never touching earlier
entries), then every entry of the final array has that size, given every entry of the initial
array already does. -/
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

end CryptWalker.Sphinx.Common

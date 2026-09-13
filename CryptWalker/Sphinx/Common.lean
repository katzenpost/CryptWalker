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
open CryptWalker.Util.Bytes (ofVector)

def v0AD : ByteArray := ⟨#[0, 0]⟩

def toVec32 (a : ByteArray) : Vector UInt8 32 := Vector.ofFn fun i : Fin 32 => a.get! i.val

/-- As `toVec32`, but for a byte width chosen at the call site rather than fixed to 32 — what a
NIKE/KEM-generic caller needs, since a scheme's own `publicKeySize`/`privateKeySize`/
`sharedSecretSize`/`ciphertextSize` aren't necessarily 32. -/
def toVecN (n : Nat) (a : ByteArray) : Vector UInt8 n := Vector.ofFn fun i : Fin n => a.get! i.val

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

def mac (key : Vector UInt8 32) (msg : ByteArray) : Vector UInt8 32 := hmacSha256 (ofVector key) msg

def zeroPadTo (n : Nat) (b : ByteArray) : ByteArray :=
  if b.size ≥ n then b else b ++ ⟨Array.replicate (n - b.size) 0⟩

/-- Go's "leave spare room for one" check: `budget` is what's left of `perHopRoutingInfoLength`
for the caller's *own* commands once whatever `createHeader`/`createKEMHeader` appends
afterward (a `NextNodeHop` command, plus a KEM's embedded next-hop ciphertext) is accounted for. -/
def commandsToBytes (budget : Nat) (cmds : List RoutingCommand) : Except String ByteArray := do
  let b := cmds.foldl (fun acc c => acc ++ c.toBytes) ByteArray.empty
  if b.size > budget then
    throw "sphinx: invalid commands, oversized serialized block"
  pure b

end CryptWalker.Sphinx.Common

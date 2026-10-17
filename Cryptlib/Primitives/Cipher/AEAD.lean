/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace Cryptlib.Primitives.Cipher.AEAD

/-! # Authenticated encryption with associated data

Confidentiality and authenticity are computational and are not stated as laws. The laws are
correctness (`decrypt_encrypt`), fixed tag expansion (`size_encrypt`), and soundness
(`decrypt_sound`): `decrypt` only accepts ciphertexts that `encrypt` produces. Together they make
`decrypt` the partial inverse of `encrypt` (`decrypt_eq_some_iff`).

The nonce is an explicit argument; choosing unique nonces is the caller's responsibility.
Failure is `Option` so that no failure reason is reported. -/

structure AEAD where
  /-- Opaque, so an implementation may carry a precomputed key schedule. -/
  Key : Type

  name : String

  keySize   : Nat
  nonceSize : Nat
  tagSize   : Nat

  /-- The largest plaintext, in bytes, for which the security claim holds. Not used by any law. -/
  maxPlaintextSize : Nat
  /-- The largest associated data, in bytes, for which the security claim holds. -/
  maxADSize : Nat

  keyFromBytes : Vector UInt8 keySize → Key

  encrypt : Key → Vector UInt8 nonceSize → (ad pt : ByteArray) → ByteArray
  decrypt : Key → Vector UInt8 nonceSize → (ad ct : ByteArray) → Option ByteArray

  /-- The tag is the only expansion. -/
  size_encrypt : ∀ k n ad pt, (encrypt k n ad pt).size = pt.size + tagSize

  /-- Correctness, unconditional on length limits. -/
  decrypt_encrypt : ∀ k n ad pt, decrypt k n ad (encrypt k n ad pt) = some pt

  /-- Soundness: only ciphertexts produced by `encrypt` under the same key, nonce and associated
  data are accepted. -/
  decrypt_sound : ∀ k n ad ct pt, decrypt k n ad ct = some pt → encrypt k n ad pt = ct

namespace AEAD

variable (A : AEAD)

/-- A ciphertext decrypts to a plaintext exactly when it is that plaintext's encryption. -/
theorem decrypt_eq_some_iff (k : A.Key) (n : Vector UInt8 A.nonceSize) (ad ct pt : ByteArray) :
    A.decrypt k n ad ct = some pt ↔ A.encrypt k n ad pt = ct := by
  constructor
  · exact A.decrypt_sound k n ad ct pt
  · rintro rfl
    exact A.decrypt_encrypt k n ad pt

/-- Nothing shorter than a tag is accepted. -/
theorem decrypt_of_size_lt (k : A.Key) (n : Vector UInt8 A.nonceSize) (ad ct : ByteArray)
    (h : ct.size < A.tagSize) : A.decrypt k n ad ct = none := by
  cases hd : A.decrypt k n ad ct with
  | none => rfl
  | some pt =>
    have hct := A.decrypt_sound k n ad ct pt hd
    have hsz := A.size_encrypt k n ad pt
    rw [hct] at hsz
    omega

/-- A ciphertext's length determines its plaintext's length. -/
theorem size_of_decrypt (k : A.Key) (n : Vector UInt8 A.nonceSize) (ad ct pt : ByteArray)
    (h : A.decrypt k n ad ct = some pt) : ct.size = pt.size + A.tagSize := by
  rw [← A.decrypt_sound k n ad ct pt h]
  exact A.size_encrypt k n ad pt

/-- Distinct ciphertexts cannot decrypt to the same plaintext under one key, nonce and associated
data. -/
theorem decrypt_inj (k : A.Key) (n : Vector UInt8 A.nonceSize) (ad ct₁ ct₂ pt : ByteArray)
    (h₁ : A.decrypt k n ad ct₁ = some pt) (h₂ : A.decrypt k n ad ct₂ = some pt) : ct₁ = ct₂ := by
  rw [← A.decrypt_sound k n ad ct₁ pt h₁, ← A.decrypt_sound k n ad ct₂ pt h₂]

end AEAD

/-- The identity cipher, showing the laws are satisfiable. Provides no security. -/
instance : Inhabited AEAD := ⟨{
  Key := Unit

  name      := "none"
  keySize   := 0
  nonceSize := 0
  tagSize   := 0

  maxPlaintextSize := 0
  maxADSize        := 0

  keyFromBytes := fun _ => ()

  encrypt := fun _ _ _ pt => pt
  decrypt := fun _ _ _ ct => some ct

  size_encrypt    := fun _ _ _ _ => rfl
  decrypt_encrypt := fun _ _ _ _ => rfl
  decrypt_sound   := fun _ _ _ _ _ h => (Option.some.inj h).symm
}⟩

end Cryptlib.Primitives.Cipher.AEAD

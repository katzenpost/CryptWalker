/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

namespace CryptWalker.Cipher.AEAD

/-! # Authenticated encryption with associated data

The same shape as `NIKE`, `KEM`, `Signature` and `Hash`: a plain structure whose laws are
*fields*, so no instance can exist without discharging them.

## What can and cannot be a law here

Confidentiality and authenticity are computational — they quantify over adversaries and
negligible functions — so neither can be a field, for the same reason `Hash` cannot state
collision resistance. Attempting one would produce a proposition no instance could ever
discharge.

Three things *are* statable, and between them they say everything a caller relies on:

* `decrypt_encrypt` — correctness. What was sealed comes back.
* `size_encrypt` — a ciphertext is its plaintext plus a fixed-width tag. Ciphertext length
  therefore leaks the plaintext length and nothing else, which is what lets a protocol reason
  about padding at all. BACAP sizes a pigeonhole box this way.
* `decrypt_sound` — the converse of correctness: the only plaintext `decrypt` ever returns is
  one that re-encrypts to exactly the ciphertext it was handed.

`decrypt_sound` is the one that earns its keep. It rules out any parsing slack — two encodings
of the same message, an ignored padding byte, a tag compared on a prefix — because such a
scheme would accept a ciphertext it could not itself have produced. Together with
`decrypt_encrypt` it pins `decrypt` down completely: `decrypt_eq_some_iff` below shows the two
laws force `decrypt` to be *the* partial inverse of `encrypt`, leaving an implementation no
freedom whatsoever about which ciphertexts to accept.

## Why `encrypt` is a function and not a state action

`Signature.sign` lives in `StateM State` because a randomized signer draws a nonce. Nothing
of the kind is needed here: the nonce is an explicit *argument*, so encryption is a pure
function of key, nonce, associated data and plaintext. Every nonce-based AEAD is deterministic
once the nonce is fixed — that is what "nonce-based" means — and hoisting the nonce out to the
caller is exactly what makes `decrypt_sound` statable. A scheme that generated its own nonce
internally would have no unique ciphertext to be sound *about*.

Choosing nonces is therefore the caller's problem, as key generation is in `NIKE`. This is not
a detail to wave at: for a conventional AEAD, repeating a nonce under one key is
catastrophic. It is why BACAP encrypts under AES-256-GCM-SIV, a misuse-resistant mode, whose
worst case under nonce reuse is revealing that two plaintexts were equal.

## Failure is `Option`, deliberately not an error enum

`KEM` distinguishes `badCiphertext` from `unsafePublicKey`; an AEAD must not make the
corresponding distinction. Reporting *why* an open failed — bad tag, short input, malformed
framing — is precisely the oracle that padding-oracle attacks are built from. There is one
failure, it is "this is not a ciphertext I produced", and `Option` says exactly that.

## No key encoding

`NIKE`, `KEM` and `Signature` all carry `encode`/`decode` pairs because their keys go on the
wire. A symmetric key never does: it is derived, used and dropped. `keyFromBytes` is the whole
interface, taking a `Vector UInt8 keySize` because that is what a KDF hands you — BACAP's key
comes straight out of HKDF. `Key` stays abstract so an implementation may precompute a key
schedule instead of re-expanding it on every call.
-/

structure AEAD where
  /-- Opaque, so an implementation may carry a precomputed key schedule rather than raw bytes. -/
  Key : Type

  name : String

  keySize   : Nat
  nonceSize : Nat
  tagSize   : Nat

  /-- The largest plaintext, in bytes, for which the scheme's *security* claim holds. RFC 8452
  caps AES-256-GCM-SIV at 2^36 bytes per key/nonce pair, for instance. No law below mentions
  this: correctness is unconditional, and the bound is a cryptographic limit rather than a
  functional one, so recording it as data is as far as this interface can honestly go. A
  caller that has to chunk a large message needs the number regardless. -/
  maxPlaintextSize : Nat
  /-- The same, for associated data. -/
  maxADSize : Nat

  keyFromBytes : Vector UInt8 keySize → Key

  encrypt : Key → Vector UInt8 nonceSize → (ad pt : ByteArray) → ByteArray
  decrypt : Key → Vector UInt8 nonceSize → (ad ct : ByteArray) → Option ByteArray

  /-- The tag is the only expansion. -/
  size_encrypt : ∀ k n ad pt, (encrypt k n ad pt).size = pt.size + tagSize

  /-- Correctness. Unconditional: length limits are a security matter, not a functional one. -/
  decrypt_encrypt : ∀ k n ad pt, decrypt k n ad (encrypt k n ad pt) = some pt

  /-- Soundness: nothing is accepted that the scheme could not itself have produced, from that
  key, that nonce and that associated data. -/
  decrypt_sound : ∀ k n ad ct pt, decrypt k n ad ct = some pt → encrypt k n ad pt = ct

namespace AEAD

variable (A : AEAD)

/-- The two laws taken together: a ciphertext opens to a plaintext exactly when it *is* that
plaintext's encryption. Everything below is a corollary of this one statement, which is the
sense in which `AEAD` leaves an implementation no discretion. -/
theorem decrypt_eq_some_iff (k : A.Key) (n : Vector UInt8 A.nonceSize) (ad ct pt : ByteArray) :
    A.decrypt k n ad ct = some pt ↔ A.encrypt k n ad pt = ct := by
  constructor
  · exact A.decrypt_sound k n ad ct pt
  · rintro rfl
    exact A.decrypt_encrypt k n ad pt

/-- Nothing shorter than a tag is ever accepted. Derived rather than assumed: a scheme that
accepted a truncated ciphertext would have to return a plaintext of negative length. -/
theorem decrypt_of_size_lt (k : A.Key) (n : Vector UInt8 A.nonceSize) (ad ct : ByteArray)
    (h : ct.size < A.tagSize) : A.decrypt k n ad ct = none := by
  cases hd : A.decrypt k n ad ct with
  | none => rfl
  | some pt =>
    have hct := A.decrypt_sound k n ad ct pt hd
    have hsz := A.size_encrypt k n ad pt
    rw [hct] at hsz
    omega

/-- A ciphertext's length determines its plaintext's length, before any key is applied. -/
theorem size_of_decrypt (k : A.Key) (n : Vector UInt8 A.nonceSize) (ad ct pt : ByteArray)
    (h : A.decrypt k n ad ct = some pt) : ct.size = pt.size + A.tagSize := by
  rw [← A.decrypt_sound k n ad ct pt h]
  exact A.size_encrypt k n ad pt

/-- Distinct ciphertexts cannot open to the same plaintext under one key, nonce and associated
data. A scheme with malleable framing would fail this. -/
theorem decrypt_inj (k : A.Key) (n : Vector UInt8 A.nonceSize) (ad ct₁ ct₂ pt : ByteArray)
    (h₁ : A.decrypt k n ad ct₁ = some pt) (h₂ : A.decrypt k n ad ct₂ = some pt) : ct₁ = ct₂ := by
  rw [← A.decrypt_sound k n ad ct₁ pt h₁, ← A.decrypt_sound k n ad ct₂ pt h₂]

end AEAD

/-- The identity "cipher": no key, no nonce, no tag, no secrecy, no authentication. It is here
for the same reason `Hash`'s empty digest and `Signature`'s always-verifies scheme are: to
demonstrate that the laws above are jointly satisfiable, and to give downstream constructions
something to smoke-test against. `maxPlaintextSize := 0` is the honest entry — there is no
length at which this claims anything. -/
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

end CryptWalker.Cipher.AEAD

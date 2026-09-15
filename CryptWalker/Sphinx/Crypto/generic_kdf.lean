/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.Sphinx.Crypto.kdf

namespace CryptWalker.Sphinx.Crypto.GenericKDF

/-! # Key-derivation functions, generically

The same shape as `NIKE`, `KEM`, `Hash`, `StreamCipher`, `MAC`, `WideBlockCipher`: a plain
structure whose one law is a field.

Lighter than `Hash.HKDF`, which models the full Extract-then-Expand construction: Sphinx's own
KDF skips Extract, feeding the raw shared secret directly to Expand, so there's no `PRK` type to
abstract over — just expand a raw input into exactly `len` bytes, deterministically. -/

structure KDF where
  /-- Expand `(ikm, info)` into exactly `len` bytes of output key material. -/
  expand : ByteArray → ByteArray → (len : Nat) → ByteArray

  expand_size : ∀ ikm info len, (expand ikm info len).size = len

/-- The empty KDF: a placeholder so `KDF` is demonstrably inhabited. Obviously not a KDF
(all-zero output, ignores both inputs). -/
instance : Inhabited KDF := ⟨{
  expand := fun _ _ len => ⟨Array.replicate len 0⟩
  expand_size := fun _ _ len => by simp [ByteArray.size]
}⟩

/-! ## HKDF-SHA256-Expand-only, as a `KDF` -/

namespace HKDFSha256Expand

private theorem go_size (prk info : ByteArray) (len : Nat) :
    ∀ fuel i prev out, len ≤ 32 * fuel + out.size →
      (CryptWalker.Sphinx.Crypto.KDF.expand.go prk info len fuel i prev out).size = len := by
  intro fuel
  induction fuel with
  | zero =>
    intro i prev out hle
    unfold CryptWalker.Sphinx.Crypto.KDF.expand.go
    rw [ByteArray.size_extract]
    omega
  | succ fuel ih =>
    intro i prev out hle
    unfold CryptWalker.Sphinx.Crypto.KDF.expand.go
    dsimp only
    apply ih
    simp only [ByteArray.size_append, CryptWalker.Util.Bytes.size_ofVector]
    omega

theorem expand_size (ikm info : ByteArray) (len : Nat) :
    (CryptWalker.Sphinx.Crypto.KDF.expand ikm info len).size = len := by
  unfold CryptWalker.Sphinx.Crypto.KDF.expand
  split
  · simp_all
  · dsimp only
    apply go_size
    omega

end HKDFSha256Expand

def hkdfSha256Expand : KDF where
  expand      := CryptWalker.Sphinx.Crypto.KDF.expand
  expand_size := HKDFSha256Expand.expand_size

/-- `PacketKeys`, generic over which `KDF` does the expansion — Sphinx's domain-separation string
and the five fields' offsets/widths are fixed, only the KDF algorithm varies. Agrees with
`KDF.sphinxKDF` exactly when `kdf = hkdfSha256Expand`. `blindingFactorSeed` is included for
parity even though KEM-Sphinx never reads it. -/
def packetKeysFrom (kdf : KDF) (ikm : ByteArray) : CryptWalker.Sphinx.Crypto.KDF.PacketKeys :=
  let okm := kdf.expand ikm CryptWalker.Sphinx.Crypto.KDF.kdfInfo (32 + 32 + 16 + 48 + 32)
  { headerMAC          := CryptWalker.Sphinx.Crypto.KDF.sliceV okm 0 32
    headerEncryption   := CryptWalker.Sphinx.Crypto.KDF.sliceV okm 32 32
    headerEncryptionIV := CryptWalker.Sphinx.Crypto.KDF.sliceV okm 64 16
    payloadEncryption  := CryptWalker.Sphinx.Crypto.KDF.sliceV okm 80 48
    blindingFactorSeed := CryptWalker.Sphinx.Crypto.KDF.sliceV okm 128 32 }

/-- Sanity check: `packetKeysFrom` at the concrete `hkdfSha256Expand` instance is definitionally
`KDF.sphinxKDF` — the generalization above didn't change Sphinx's actual key derivation. -/
theorem packetKeysFrom_hkdfSha256Expand (ikm : ByteArray) :
    packetKeysFrom hkdfSha256Expand ikm = CryptWalker.Sphinx.Crypto.KDF.sphinxKDF ikm := rfl

end CryptWalker.Sphinx.Crypto.GenericKDF

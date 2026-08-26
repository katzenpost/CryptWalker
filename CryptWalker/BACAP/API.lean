/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.BACAP.Impl

/-! # BACAP API: the stateless surface, specialized to BLAKE2b-512 and AES-256-GCM-SIV

`Impl.lean` supplies the concrete cryptographic operations as bare functions over root keys.
This file is the surface callers use: the same operations named and shaped as in
`hpqc/bacap/bacap_impl.go` and `hpqc/py/hpqc/bacap/stateless.py`, taking capabilities rather
than loose key material, with the HKDF fixed to BLAKE2b-512.

Only the *stateless* API is ported. Go and Python also ship `StatefulReader` and
`StatefulWriter`, mutable wrappers that hold a next-index pointer and advance it after each
successful operation; a caller who wants that can hold a `MessageBoxIndex` and call
`nextIndex` themselves.

Passing a `WriteCap` rather than a separate scalar and public key is not only tidier: the two
are derived from one seed, so the `pk = publicKey sk` side condition that `BACAPSpec` carries
is discharged by construction. `decrypt_encryptForContext` below states that consequence. -/

namespace CryptWalker.BACAP.Types

open CryptWalker.BACAP.Ratchet
open CryptWalker.BACAP.Impl
open CryptWalker.BACAP.Protocol
open CryptWalker.Hash.HKDF
open CryptWalker.Sign.Ed25519Blinded

/-! ## MessageBoxIndex: ratchet advancement -/

/-- Advance the ratchet to `target`, or `none` if that would rewind.

    Matches `AdvanceIndexTo` in Go and `advance_index_to` in Python, which signal the rewind as
    an error and a `CannotRewind` exception respectively. -/
def MessageBoxIndex.advanceIndexTo (m : MessageBoxIndex) (target : UInt64) :
    Option MessageBoxIndex :=
  advanceTo m blake2b512_hkdf target

/-- Advance the ratchet by one step. -/
def MessageBoxIndex.nextIndex (m : MessageBoxIndex) : Option MessageBoxIndex :=
  CryptWalker.BACAP.Ratchet.nextIndex m blake2b512_hkdf

/-- Re-seed the ratchet state from `ctx`, preserving `idx64`.
    See `CryptWalker.BACAP.Ratchet.mutateKDFState`. -/
def MessageBoxIndex.mutateKDFState (m : MessageBoxIndex) (ctx : ByteArray) : MessageBoxIndex :=
  CryptWalker.BACAP.Ratchet.mutateKDFState m blake2b512_hkdf ctx

/-- A fresh index from 48 caller-supplied random bytes.
    See `CryptWalker.BACAP.Ratchet.ofRandomBytes`. -/
def MessageBoxIndex.random (rb : Vector UInt8 48) : MessageBoxIndex :=
  ofRandomBytes rb blake2b512_hkdf

/-! ## MessageBoxIndex: box IDs -/

/-- Box ID for this index under `rootPublicKey`, with no context applied. -/
def MessageBoxIndex.deriveMessageBoxID (m : MessageBoxIndex) (rootPublicKey : PubBytes) :
    PubBytes :=
  implDeriveMessageBoxID rootPublicKey m

/-- Box ID for this index and `ctx`, read off a `ReadCap`. -/
def MessageBoxIndex.boxIDForContext (m : MessageBoxIndex) (rc : ReadCap) (ctx : ByteArray) :
    PubBytes :=
  implDeriveBoxID rc.rootPublicKey m ctx

/-! ## MessageBoxIndex: sign, verify, encrypt, decrypt -/

/-- Sign `ciphertext` under the blinded private key for this index and `ctx`.

    Returns the box ID and the signature. The signature is plain Ed25519 against the box ID, so
    any conforming verifier accepts it. -/
def MessageBoxIndex.signBox (m : MessageBoxIndex) (owner : WriteCap) (ctx ciphertext : ByteArray) :
    PubBytes × SigBytes :=
  implSignBox owner.rootPrivateKey m ctx ciphertext

/-- Verify a signature under a box ID.

    The box ID is the public key, so this needs no index; Go hangs it off `MessageBoxIndex`
    with an unused receiver and Python makes it a `@staticmethod`. Here it is a plain function. -/
def verifyBox (box : PubBytes) (ciphertext : ByteArray) (sig : SigBytes) : Bool :=
  implVerifyBox box ciphertext sig

/-- Encrypt `plaintext` for this index and `ctx`, returning the box ID, ciphertext and signature.

    The box ID is both the AEAD nonce prefix (first 12 bytes) and the associated data (all 32). -/
def MessageBoxIndex.encryptForContext (m : MessageBoxIndex) (owner : WriteCap)
    (ctx plaintext : ByteArray) : PubBytes × ByteArray × SigBytes :=
  implEncryptBox owner.rootPrivateKey owner.rootPublicKey m ctx plaintext

/-- Verify the signature, then decrypt.

    An empty ciphertext is a tombstone: the signature is checked over the empty payload and an
    empty plaintext is returned without decrypting. `none` means the signature failed or the
    AEAD tag did not authenticate. -/
def MessageBoxIndex.decryptForContext (m : MessageBoxIndex) (box : PubBytes)
    (ctx ciphertext : ByteArray) (sig : SigBytes) : Option ByteArray :=
  implDecryptBox box m ctx ciphertext sig

/-! ## Capabilities -/

/-- Box ID for `idx` under this cap's root key, with no context applied. -/
def WriteCap.deriveBoxID (wc : WriteCap) (idx : MessageBoxIndex) : PubBytes :=
  implDeriveMessageBoxID wc.rootPublicKey idx

/-- Box ID for `idx` under this cap's root key, with no context applied. -/
def ReadCap.deriveBoxID (rc : ReadCap) (idx : MessageBoxIndex) : PubBytes :=
  implDeriveMessageBoxID rc.rootPublicKey idx

/-- Re-seed this cap's index from `ctx`, sharing the root key.

    Applying this with the same `ctx` as `ReadCap.mutateKDFState` on the paired read cap keeps
    writer and readers in lockstep. -/
def WriteCap.mutateKDFState (wc : WriteCap) (ctx : ByteArray) : WriteCap :=
  { wc with messageBoxIndex := wc.messageBoxIndex.mutateKDFState ctx }

/-- Re-seed this cap's index from `ctx`, sharing the root public key.
    The counterpart to `WriteCap.mutateKDFState` on the paired write cap. -/
def ReadCap.mutateKDFState (rc : ReadCap) (ctx : ByteArray) : ReadCap :=
  { rc with messageBoxIndex := rc.messageBoxIndex.mutateKDFState ctx }

/-- Mutating a write cap and its read cap by the same context lands them on the same sequence. -/
theorem readCap_mutateKDFState (wc : WriteCap) (ctx : ByteArray) :
    wc.readCap.mutateKDFState ctx = (wc.mutateKDFState ctx).readCap := by
  simp only [WriteCap.readCap, WriteCap.mutateKDFState, ReadCap.mutateKDFState,
    WriteCap.rootPublicKey, WriteCap.rootPrivateKey]

/-! ## Key generation

Randomness enters only here. The pure constructors above take the bytes as an argument, so
everything below `IO` stays testable against fixed vectors. -/

private def randomVector (n : Nat) : IO (Vector UInt8 n) := do
  let bs ← IO.getRandomBytes (USize.ofNat n)
  pure (Vector.ofFn fun i : Fin n => bs[i.val]!)

/-- A fresh index seeded from the system CSPRNG. -/
def MessageBoxIndex.randomIO : IO MessageBoxIndex := do
  pure (MessageBoxIndex.random (← randomVector 48))

/-- A fresh write capability: a new root keypair and a new starting index, both from the system
    CSPRNG. Matches `NewWriteCap` in Go and `WriteCap.generate` in Python. -/
def WriteCap.generate : IO WriteCap := do
  pure { rootSeed := ← randomVector 32, messageBoxIndex := ← MessageBoxIndex.randomIO }

/-! ## Correctness -/

/-- A cap's public key is the one its private key derives, by construction. -/
theorem writeCap_pub (wc : WriteCap) : wc.rootPublicKey = publicKey wc.rootPrivateKey := rfl

/-- Decrypting a box encrypted under the same cap, index and context returns the plaintext.

    This is `BACAPSpec.decrypt_encrypt` with its `pk = publicKey sk` hypothesis discharged:
    a `WriteCap` cannot hold a mismatched pair. -/
theorem decrypt_encryptForContext (wc : WriteCap) (m : MessageBoxIndex) (ctx pt : ByteArray) :
    m.decryptForContext (m.encryptForContext wc ctx pt).1 ctx
      (m.encryptForContext wc ctx pt).2.1 (m.encryptForContext wc ctx pt).2.2 = some pt :=
  implDecrypt_implEncrypt wc.rootPrivateKey wc.rootPublicKey m ctx pt (writeCap_pub wc)

end CryptWalker.BACAP.Types

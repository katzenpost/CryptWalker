/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import CryptWalker.BACAP.Impl

/-! # BACAP API over BLAKE2b-512 HKDF and AES-256-GCM-SIV

Stateless: callers hold their own index. Operations take capabilities rather than loose keys, so
`pk = publicKey sk` holds by construction. -/

namespace CryptWalker.BACAP.Types

open CryptWalker.BACAP.Ratchet
open CryptWalker.BACAP.Impl
open CryptWalker.BACAP.Protocol
open CryptWalker.Hash.HKDF
open CryptWalker.Sign.Ed25519Blinded

/-! ## MessageBoxIndex: ratchet advancement -/

/-- Advance the ratchet to `target`, or `none` if that would rewind. -/
def MessageBoxIndex.advanceIndexTo (m : MessageBoxIndex) (target : UInt64) :
    Option MessageBoxIndex :=
  advanceTo m blake2b512_hkdf target

def MessageBoxIndex.nextIndex (m : MessageBoxIndex) : Option MessageBoxIndex :=
  CryptWalker.BACAP.Ratchet.nextIndex m blake2b512_hkdf

/-- See `Ratchet.mutateKDFState`. -/
def MessageBoxIndex.mutateKDFState (m : MessageBoxIndex) (ctx : ByteArray) : MessageBoxIndex :=
  CryptWalker.BACAP.Ratchet.mutateKDFState m blake2b512_hkdf ctx

/-- See `Ratchet.ofRandomBytes`. -/
def MessageBoxIndex.random (rb : Vector UInt8 48) : MessageBoxIndex :=
  ofRandomBytes rb blake2b512_hkdf

/-! ## MessageBoxIndex: box IDs -/

/-- Box ID for this index under `rootPublicKey`, with no context applied. -/
def MessageBoxIndex.deriveMessageBoxID (m : MessageBoxIndex) (rootPublicKey : PubBytes) :
    PubBytes :=
  implDeriveMessageBoxID rootPublicKey m

/-- Box ID for this index and `ctx`. -/
def MessageBoxIndex.boxIDForContext (m : MessageBoxIndex) (rc : ReadCap) (ctx : ByteArray) :
    PubBytes :=
  implDeriveBoxID rc.rootPublicKey m ctx

/-! ## MessageBoxIndex: sign, verify, encrypt, decrypt -/

/-- Sign `ciphertext` with the blinded key for this index and `ctx`; returns (box ID, signature).
    The signature is plain Ed25519 under the box ID. -/
def MessageBoxIndex.signBox (m : MessageBoxIndex) (owner : WriteCap) (ctx ciphertext : ByteArray) :
    PubBytes × SigBytes :=
  implSignBox owner.rootPrivateKey m ctx ciphertext

/-- Verify a signature under a box ID. -/
def verifyBox (box : PubBytes) (ciphertext : ByteArray) (sig : SigBytes) : Bool :=
  implVerifyBox box ciphertext sig

/-- Returns (box ID, ciphertext, signature). The box ID's first 12 bytes are the AEAD nonce;
    all 32 bytes are the AD. -/
def MessageBoxIndex.encryptForContext (m : MessageBoxIndex) (owner : WriteCap)
    (ctx plaintext : ByteArray) : PubBytes × ByteArray × SigBytes :=
  implEncryptBox owner.rootPrivateKey owner.rootPublicKey m ctx plaintext

/-- Verify the signature, then decrypt. A tombstone (empty ciphertext) decrypts to empty. -/
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

/-- Re-seed this cap's index from `ctx`. -/
def WriteCap.mutateKDFState (wc : WriteCap) (ctx : ByteArray) : WriteCap :=
  { wc with messageBoxIndex := wc.messageBoxIndex.mutateKDFState ctx }

/-- Re-seed this cap's index from `ctx`. -/
def ReadCap.mutateKDFState (rc : ReadCap) (ctx : ByteArray) : ReadCap :=
  { rc with messageBoxIndex := rc.messageBoxIndex.mutateKDFState ctx }

/-- Mutating a write cap and its read cap by the same context lands them on the same sequence. -/
theorem readCap_mutateKDFState (wc : WriteCap) (ctx : ByteArray) :
    wc.readCap.mutateKDFState ctx = (wc.mutateKDFState ctx).readCap := by
  simp only [WriteCap.readCap, WriteCap.mutateKDFState, ReadCap.mutateKDFState,
    WriteCap.rootPublicKey, WriteCap.rootPrivateKey]

/-! ## Key generation from the system CSPRNG -/

private def randomVector (n : Nat) : IO (Vector UInt8 n) := do
  let bs ← IO.getRandomBytes (USize.ofNat n)
  pure (Vector.ofFn fun i : Fin n => bs[i.val]!)

def MessageBoxIndex.randomIO : IO MessageBoxIndex := do
  pure (MessageBoxIndex.random (← randomVector 48))

/-- A fresh root keypair and starting index. -/
def WriteCap.generate : IO WriteCap := do
  pure { rootSeed := ← randomVector 32, messageBoxIndex := ← MessageBoxIndex.randomIO }

/-! ## Correctness -/

/-- A cap's public key is the one its private key derives. -/
theorem writeCap_pub (wc : WriteCap) : wc.rootPublicKey = publicKey wc.rootPrivateKey := rfl

/-- Decrypting a box encrypted under the same cap, index and context returns the plaintext. -/
theorem decrypt_encryptForContext (wc : WriteCap) (m : MessageBoxIndex) (ctx pt : ByteArray) :
    m.decryptForContext (m.encryptForContext wc ctx pt).1 ctx
      (m.encryptForContext wc ctx pt).2.1 (m.encryptForContext wc ctx pt).2.2 = some pt :=
  implDecrypt_implEncrypt wc.rootPrivateKey wc.rootPublicKey m ctx pt (writeCap_pub wc)

end CryptWalker.BACAP.Types

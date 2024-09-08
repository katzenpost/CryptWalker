/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

import CryptWalker.kem.kem
import CryptWalker.nike.nike

-- NIKE to KEM adapter: a hashed ElGamal construction

namespace CryptWalker.kem.adapter

open CryptWalker.nike.nike
open CryptWalker.kem.kem

structure PrivateKey where
  data : ByteArray

structure PublicKey where
  data : ByteArray

def createKEMAdapter (hash : ByteArray → ByteArray) (nike : NIKE) : KEM :=
{
  PublicKeyType := PublicKey,
  PrivateKeyType := PrivateKey,
  privateKeySize := nike.privateKeySize,
  publicKeySize := nike.publicKeySize,
  ciphertextSize := nike.publicKeySize,
  name := nike.name,

  generateKeyPair := do
    let keyPair ← nike.generateKeyPair
    let pubkey := PublicKey.mk (nike.encodePublicKey keyPair.1)
    let privkey := PrivateKey.mk (nike.encodePrivateKey keyPair.2)
    pure (pubkey, privkey),

  encapsulate := fun theirPubKey => do
    let (pubkey, privkey) ← nike.generateKeyPair
    match nike.decodePublicKey theirPubKey.data with
    | none => panic! "Failed to decode NIKE public key"
    | some pubkey2 =>
      let ss1 := nike.groupAction privkey pubkey2
      let ss2 := hash (nike.encodePublicKey ss1)
      let ciphertext := nike.encodePublicKey pubkey
      pure (ciphertext, ss2),

  decapsulate := fun privKey ct =>
    match nike.decodePublicKey ct with
    | none => panic! "Failed to decode NIKE public key"
    | some pubkey2 =>
      match nike.decodePrivateKey privKey.data with
      | none => panic! "Failed to decode NIKE private key"
      | some privkey2 =>
        let ss1 := nike.groupAction privkey2 pubkey2
        hash (nike.encodePublicKey ss1),

  encodePrivateKey := fun sk => sk.data,
  decodePrivateKey := fun bytes => some { data := bytes },
  encodePublicKey := fun pk => pk.data,
  decodePublicKey := fun bytes => some { data := bytes }
}

end CryptWalker.kem.adapter

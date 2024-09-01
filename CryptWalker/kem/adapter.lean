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

instance : kem.Key PrivateKey where
  encode : PrivateKey → ByteArray := fun (key : PrivateKey) => key.data
  decode (_kem : KEM) (bytes : ByteArray) : Option PrivateKey :=
    some (PrivateKey.mk bytes)

instance : kem.Key PublicKey where
  encode : PublicKey → ByteArray := fun (key : PublicKey) => key.data
  decode (_kem : KEM) (bytes : ByteArray) : Option PublicKey :=
    some (PublicKey.mk bytes)


structure Adapter where
  hash : ByteArray → ByteArray
  nike : NIKE

instance (adapter : Adapter) : KEM where
  PublicKeyType := PublicKey
  PrivateKeyType := PrivateKey

  name : String := adapter.nike.name

  generateKeyPair : IO (PublicKey × PrivateKey) := do
    let keyPair ← adapter.nike.generateKeyPair
    let pubkey := keyPair.1
    let privkey := keyPair.2
    let pubkeyData := adapter.nike.encodePublicKey pubkey
    let privkeyData := adapter.nike.encodePrivateKey privkey
    pure (PublicKey.mk pubkeyData, PrivateKey.mk privkeyData)

  encapsulate (theirPubKey : PublicKey) : IO (ByteArray × ByteArray) := do
    let (pubkey, privkey) ← adapter.nike.generateKeyPair
    let theirNikePubKeyOpt : Option (adapter.nike.PublicKeyType) := adapter.nike.decodePublicKey theirPubKey.data
    match theirNikePubKeyOpt with
    | none => panic! "Failed to decode NIKE public key"
    | some theirNikePubKey =>
      let ss1 := adapter.nike.groupAction privkey theirNikePubKey
      let ss1Bytes := adapter.nike.encodePublicKey ss1
      let pubkeyBytes := adapter.nike.encodePublicKey pubkey
      let blob := ByteArray.append ss1Bytes $ ByteArray.append theirPubKey.data pubkeyBytes
      let ss2 := adapter.hash blob
      let ciphertext := adapter.nike.encodePublicKey pubkey
      pure (ciphertext, ss2)

  decapsulate (privKey : PrivateKey) (ct : ByteArray) : ByteArray :=
    let theirPubKeyOpt : Option (adapter.nike.PublicKeyType) := adapter.nike.decodePublicKey ct
    match theirPubKeyOpt with
    | none => panic! "adapter decap failure: failed to decode NIKE public key"
    | some theirPubKey =>
      let myPrivKeyOpt : Option (adapter.nike.PrivateKeyType) := adapter.nike.decodePrivateKey privKey.data
      match myPrivKeyOpt with
      | none => panic! "adapter decap failure: failed to decode NIKE private key"
      | some myPrivKey =>
        let ss1 := adapter.nike.groupAction myPrivKey theirPubKey
        let a := adapter.nike.encodePublicKey ss1
        let myPubKey := adapter.nike.derivePublicKey myPrivKey
        let myPubKeyBytes := adapter.nike.encodePublicKey myPubKey
        let theirPubKeyBytes := adapter.nike.encodePublicKey theirPubKey
        let b := ByteArray.append myPubKeyBytes theirPubKeyBytes
        let blob := ByteArray.append a b
        adapter.hash blob

  privateKeySize := adapter.nike.privateKeySize
  publicKeySize := adapter.nike.publicKeySize

  encodePrivateKey (sk : PrivateKey) : ByteArray := sk.data
  decodePrivateKey (bytes : ByteArray) : Option PrivateKey := some {data := bytes}
  encodePublicKey (pk : PublicKey) : ByteArray := pk.data
  decodePublicKey (bytes : ByteArray) : Option PublicKey := some {data := bytes}


def toKEM (adapter : Adapter) : KEM :=
  {
    PublicKeyType := PublicKey,
    PrivateKeyType := PrivateKey,
    name := adapter.nike.name,
    generateKeyPair := do
      let keyPair ← adapter.nike.generateKeyPair
      let pubkey := PublicKey.mk (adapter.nike.encodePublicKey keyPair.1)
      let privkey := PrivateKey.mk (adapter.nike.encodePrivateKey keyPair.2)
      pure (pubkey, privkey),
    encapsulate := fun theirPubKey => do
      let (pubkey, privkey) ← adapter.nike.generateKeyPair
      match adapter.nike.decodePublicKey theirPubKey.data with
      | none => panic! "type coercion failure"
      | some pubkey2 =>
        let ss1 := adapter.nike.groupAction privkey pubkey2
        let ss2 := adapter.hash (adapter.nike.encodePublicKey ss1)
        let ciphertext := adapter.nike.encodePublicKey pubkey
        pure (ciphertext, ss2),
    decapsulate := fun privKey ct =>
      match adapter.nike.decodePublicKey ct with
      | none => panic! "type coercion failure"
      | some pubkey2 =>
        match adapter.nike.decodePrivateKey privKey.data with
        | none => panic! "type coercion failure"
        | some privkey2 =>
          let ss1 := adapter.nike.groupAction privkey2 pubkey2
          adapter.hash (adapter.nike.encodePublicKey ss1),
    privateKeySize := adapter.nike.privateKeySize,
    publicKeySize := adapter.nike.publicKeySize,
    encodePrivateKey := fun sk => sk.data,
    decodePrivateKey := fun bytes => some {data := bytes},
    encodePublicKey := fun pk => pk.data,
    decodePublicKey := fun bytes => some {data := bytes}
  }

end CryptWalker.kem.adapter

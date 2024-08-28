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
  decode : ByteArray → Option PrivateKey := fun (bytes : ByteArray) => some (PrivateKey.mk bytes)

instance : kem.Key PublicKey where
  encode : PublicKey → ByteArray := fun (key : PublicKey) => key.data
  decode : ByteArray → Option PublicKey := fun (bytes : ByteArray) => some (PublicKey.mk bytes)


class Adapter (α : Type) [NIKE α] where
  hash : ByteArray → ByteArray

instance {α : Type} [nikeInstance : NIKE α] [adapter : Adapter α] : KEM α where
  PublicKeyType := PublicKey
  PrivateKeyType := PrivateKey

  name : String := NIKE.name α

  generateKeyPair : IO (PublicKey × PrivateKey) := do
    let keyPair ← nikeInstance.generateKeyPair
    let pubkey := keyPair.1
    let privkey := keyPair.2
    let pubkeyData := NIKE.encodePublicKey pubkey
    let privkeyData := NIKE.encodePrivateKey privkey
    pure (PublicKey.mk pubkeyData, PrivateKey.mk privkeyData)

  encapsulate (_self : α) (theirPubKey : PublicKey) : IO (ByteArray × ByteArray) := do
    let (pubkey, privkey) ← NIKE.generateKeyPair
    let theirNikePubKeyOpt : Option (NIKE.PublicKeyType α) := NIKE.decodePublicKey theirPubKey.data
    match theirNikePubKeyOpt with
    | none => panic! "Failed to decode NIKE public key"
    | some theirNikePubKey =>
      let ss1 := NIKE.groupAction privkey theirNikePubKey
      let ss1Bytes := NIKE.encodePublicKey ss1
      let pubkeyBytes := NIKE.encodePublicKey pubkey
      let blob := ByteArray.append ss1Bytes $ ByteArray.append theirPubKey.data pubkeyBytes
      let ss2 := adapter.hash blob
      let ciphertext := NIKE.encodePublicKey pubkey
      pure (ciphertext, ss2)

  decapsulate (_self : α) (privKey : PrivateKey) (ct : ByteArray) : ByteArray :=
    let theirPubKeyOpt : Option (NIKE.PublicKeyType α) := NIKE.decodePublicKey ct
    match theirPubKeyOpt with
    | none => panic! "adapter decap failure: failed to decode NIKE public key"
    | some theirPubKey =>
      let myPrivKeyOpt : Option (NIKE.PrivateKeyType α) := NIKE.decodePrivateKey privKey.data
      match myPrivKeyOpt with
      | none => panic! "adapter decap failure: failed to decode NIKE private key"
      | some myPrivKey =>
        let ss1 := NIKE.groupAction myPrivKey theirPubKey
        let a := NIKE.encodePublicKey ss1
        let myPubKey := NIKE.derivePublicKey myPrivKey
        let myPubKeyBytes := NIKE.encodePublicKey myPubKey
        let theirPubKeyBytes := NIKE.encodePublicKey theirPubKey
        let b := ByteArray.append myPubKeyBytes theirPubKeyBytes
        let blob := ByteArray.append a b
        adapter.hash blob

  privateKeySize := nikeInstance.privateKeySize
  publicKeySize := nikeInstance.publicKeySize

  encodePrivateKey := fun (sk : PrivateKey) => kem.Key.encode sk
  decodePrivateKey := fun (bytes : ByteArray) => kem.Key.decode bytes
  encodePublicKey := fun (pk : PublicKey) => kem.Key.encode pk
  decodePublicKey := fun (bytes : ByteArray) => kem.Key.decode bytes

end CryptWalker.kem.adapter

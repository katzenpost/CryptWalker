/-
SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
 -/

-- NIKE to KEM adapter: a hashed ElGamal construction
/-
Here's pseudo code of what we are implementing here:

func ENCAPSULATE(their_pubkey publickey) ([]byte, []byte) {
        my_privkey, my_pubkey = GEN_KEYPAIR(RNG)
        ss = DH(my_privkey, their_pubkey)
        ciphertext = ENCODE_PUBKEY(my_pubkey)
        shared_secret = HASH(ENCODE_PUBKEY(ss))
        return ciphertext, shared_secret
}

func DECAPSULATE(my_privkey privatekey, ciphertext []byte) []byte {
        their_pubkey = DECODE_PUBKEY(ciphertext)
        ss = DH(my_privkey, their_pubkey)
        return HASH(ENCODE_PUBKEY(ss))
}
-/

import CryptWalker.KEM.KEM
import CryptWalker.NIKE.NIKE

namespace CryptWalker.KEM.Adapter

open CryptWalker.NIKE.NIKE
open CryptWalker.KEM.KEM

structure PrivateKey where
  data : ByteArray

structure PublicKey where
  data : ByteArray

/- returns  2-tuple (ciphertext, shared_secret) -/
def encapsulateWith (hash : ByteArray → { out : ByteArray // out.size = 32 }) (nike : NIKE)
    (ephPriv : nike.PrivateKeyType) (theirPubBytes : ByteArray) :
    Option (ByteArray × ByteArray) :=
  match nike.decodePublicKey theirPubBytes with
  | none => none
  | some theirPub =>
      some (nike.encodePublicKey (nike.derivePublicKey ephPriv),
            (hash (nike.encodePublicKey (nike.groupAction ephPriv theirPub))).val)

def createKEMAdapter (hash : ByteArray → { out : ByteArray // out.size = 32 }) (nike : NIKE) : KEM :=
{
  PublicKeyType := PublicKey,
  PrivateKeyType := PrivateKey,
  privateKeySize := nike.privateKeySize,
  publicKeySize := nike.publicKeySize,
  ciphertextSize := nike.publicKeySize,
  name := nike.name,

  generateKeyPairWith := fun seed =>
    let sk := nike.privateKeyFromSeed seed
    (PublicKey.mk (nike.encodePublicKey (nike.derivePublicKey sk)),
     PrivateKey.mk (nike.encodePrivateKey sk)),

  generateKeyPair := do
    let sk ← nike.generatePrivateKey
    let pk := nike.derivePublicKey sk
    let pubkey := PublicKey.mk (nike.encodePublicKey pk)
    let privkey := PrivateKey.mk (nike.encodePrivateKey sk)
    pure (pubkey, privkey),

  encapsulateWith := fun seed theirPubKey =>
    match nike.decodePrivateKey seed with
    | none => none
    | some ephPriv => Adapter.encapsulateWith hash nike ephPriv theirPubKey.data,

  encapsulate := fun theirPubKey => do
    let ephPriv ← nike.generatePrivateKey
    match Adapter.encapsulateWith hash nike ephPriv theirPubKey.data with
    | none => panic! "Failed to decode NIKE public key"
    | some result => pure result,

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

end CryptWalker.KEM.Adapter

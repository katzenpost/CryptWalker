
import CryptWalker.nike.x25519
import CryptWalker.nike.x448
import CryptWalker.nike.x41417
import CryptWalker.nike.nike
import CryptWalker.kem.kem
import CryptWalker.kem.adapter
import CryptWalker.hash.Sha2

open CryptWalker.nike
open CryptWalker.nike.nike
open CryptWalker.kem.kem
open CryptWalker.kem.adapter
open CryptWalker.hash.Sha2

namespace CryptWalker.kem.schemes

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

def Schemes : List KEM :=
[
    toKEM $ Adapter.mk Sha256.hash x25519.Scheme,
    toKEM $ Adapter.mk Sha256.hash x448.Scheme,
    toKEM $ Adapter.mk Sha256.hash x41417.Scheme
]

end CryptWalker.kem.schemes

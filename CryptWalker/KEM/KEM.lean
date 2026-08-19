
namespace CryptWalker.KEM.KEM

  structure KEM where
    PublicKeyType : Type
    PrivateKeyType : Type

    name : String
    privateKeySize : Nat
    publicKeySize : Nat
    ciphertextSize : Nat

    generateKeyPair : IO (PublicKeyType × PrivateKeyType)
    generateKeyPairWith : { s : ByteArray // s.size = 32 } → (PublicKeyType × PrivateKeyType)

    encapsulate : PublicKeyType → IO (ByteArray × ByteArray)
    encapsulateWith : { s : ByteArray // s.size = 32 } → PublicKeyType → Option (ByteArray × ByteArray)

    decapsulate : PrivateKeyType → ByteArray → ByteArray

    encodePrivateKey : PrivateKeyType → ByteArray
    decodePrivateKey : ByteArray → Option PrivateKeyType

    encodePublicKey : PublicKeyType → ByteArray
    decodePublicKey : ByteArray → Option PublicKeyType


  structure LawfulKEM (kem : KEM) where
    correctness : ∀ kseed eseed pk sk ct ss,
      kem.generateKeyPairWith kseed = (pk, sk) →
      kem.encapsulateWith eseed pk = some (ct, ss) →
      kem.decapsulate sk ct = ss

end CryptWalker.KEM.KEM

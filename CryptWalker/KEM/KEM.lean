import Batteries.Classes.SatisfiesM

namespace CryptWalker.kem.kem

  class KEM where
    PublicKeyType : Type
    PrivateKeyType : Type

    name : String
    privateKeySize : Nat
    publicKeySize : Nat
    ciphertextSize : Nat

    generateKeyPair : IO (PublicKeyType × PrivateKeyType)
    encapsulate : PublicKeyType → IO (ByteArray × ByteArray)
    decapsulate : PrivateKeyType → ByteArray → ByteArray
    encodePrivateKey : PrivateKeyType → ByteArray
    decodePrivateKey : ByteArray → Option PrivateKeyType
    encodePublicKey : PublicKeyType → ByteArray
    decodePublicKey : ByteArray → Option PublicKeyType

end CryptWalker.kem.kem

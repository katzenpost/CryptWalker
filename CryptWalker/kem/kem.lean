import Batteries.Classes.SatisfiesM

namespace CryptWalker.kem.kem

  structure KEM where
    PublicKeyType : Type
    PrivateKeyType : Type

    name : String
    privateKeySize : Nat
    publicKeySize : Nat

    generateKeyPair : IO (PublicKeyType × PrivateKeyType)
    encapsulate : PublicKeyType → IO (ByteArray × ByteArray)
    decapsulate : PrivateKeyType → ByteArray → ByteArray
    encodePrivateKey : PrivateKeyType → ByteArray
    decodePrivateKey : ByteArray → Option PrivateKeyType
    encodePublicKey : PublicKeyType → ByteArray
    decodePublicKey : ByteArray → Option PublicKeyType

  structure Key (key : Type) where
    encode : key → ByteArray
    decode : KEM → ByteArray → Option key

  structure PrivateKey (privkey : Type) extends Key privkey

  structure PublicKey (pubkey : Type) extends Key pubkey

end CryptWalker.kem.kem

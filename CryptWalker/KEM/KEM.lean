
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
    encapsulateWith : ByteArray → PublicKeyType → Option (ByteArray × ByteArray)

    decapsulate : PrivateKeyType → ByteArray → ByteArray

    encodePrivateKey : PrivateKeyType → ByteArray
    decodePrivateKey : ByteArray → Option PrivateKeyType

    encodePublicKey : PublicKeyType → ByteArray
    decodePublicKey : ByteArray → Option PublicKeyType

/-
  structure LawfulKEM (kem : KEM) where
    correctness : ∀ sk₁ pk₁ sk₂ pk₂,
      have res := kem.encapsulateWith seed pk₁,
-/


end CryptWalker.KEM.KEM

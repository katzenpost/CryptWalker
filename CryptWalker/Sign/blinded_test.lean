import Lean

import CryptWalker.Hash.Sha512
import CryptWalker.Sign.Ed25519_blinded
import CryptWalker.Sign.Ed25519_math
import CryptWalker.Util.newhex

open CryptWalker.Sign.Ed25519Blinded
open CryptWalker.Sign.Ed25519Math
open CryptWalker.Hash.Sha512
open CryptWalker.Util.newhex

private def hexToVec32 (s : String) : Option (Vector UInt8 32) := do
  let bytes ← hexStringToByteArray s
  if h : bytes.data.size = 32 then some ⟨bytes.data, h⟩ else none

private def hexToBytes (s : String) : Option ByteArray :=
  hexStringToByteArray s

private def check (condition : Bool) (message : String) : IO Unit :=
  if condition then pure () else throw (IO.userError message)

def main : IO Unit := do
  let some seed := hexToVec32
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" |
    throw (IO.userError "invalid RFC seed")
  let some message := hexToBytes "" | throw (IO.userError "invalid message")
  let root := CryptWalker.Sign.Ed25519Blinded.scalarFromSeed seed
  let factorBytes := "blinding factor".toUTF8
  let factor := CryptWalker.Sign.Ed25519Blinded.scalarOfBytes factorBytes
  let blinded := CryptWalker.Sign.Ed25519Blinded.blindPriv root factor
  let rootPublic := CryptWalker.Sign.Ed25519Blinded.publicKey root
  let blindedPublic := CryptWalker.Sign.Ed25519Blinded.publicKey blinded

  check (rootPublic = CryptWalker.Sign.Ed25519Math.publicKey seed)
    "scalar expansion did not preserve the RFC public key"
  check (byteArrayToHex ⟨(sha512_256 ByteArray.empty).toArray⟩ =
      "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a")
    "SHA-512/256 empty-message test vector failed"
  check (CryptWalker.Sign.Ed25519Blinded.verifyNative rootPublic message
      (CryptWalker.Sign.Ed25519Blinded.signNative root message))
    "scalar-based root signature did not verify"
  check (blindedPublic = CryptWalker.Sign.Ed25519Blinded.blindPub rootPublic factor)
    "private and public blinding disagree"
  check (CryptWalker.Sign.Ed25519Blinded.verifyNative blindedPublic message
      (CryptWalker.Sign.Ed25519Blinded.signNative blinded message))
    "scalar-based blinded signature did not verify"
  check (CryptWalker.Sign.Ed25519Blinded.blindPub
      (CryptWalker.Sign.Ed25519Blinded.blindPub rootPublic factor)
      (CryptWalker.Sign.Ed25519Blinded.inv factor) = rootPublic)
    "public-key unblinding did not restore the root key"
  IO.println "All blinded Ed25519 tests passed!"

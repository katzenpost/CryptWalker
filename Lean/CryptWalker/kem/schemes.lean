
import CryptWalker.nike.x25519
import CryptWalker.kem.kem
import CryptWalker.kem.adapter
import CryptWalker.hash.Sha2

open CryptWalker.nike.x25519
open CryptWalker.kem
open CryptWalker.hash.Sha2

namespace CryptWalker.kem.schemes

def defaultHash := fun x => Sha256.Digest.toBytes $ Sha256.hash x
def nikeSchemeInstance : CryptWalker.nike.x25519.X25519Scheme := {}
def X25519Adapter : adapter.Adapter X25519Scheme := CryptWalker.kem.adapter.Adapter.mk nikeSchemeInstance defaultHash
def X25519AsKEM := inferInstanceAs (CryptWalker.kem.kem.KEM (adapter.Adapter X25519Scheme))

end CryptWalker.kem.schemes

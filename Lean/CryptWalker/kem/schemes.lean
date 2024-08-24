
import CryptWalker.nike.x25519
import CryptWalker.nike.x448
import CryptWalker.nike.x41417
import CryptWalker.nike.nike
import CryptWalker.kem.kem
import CryptWalker.kem.adapter
import CryptWalker.hash.Sha2
import CryptWalker.util.HList

open CryptWalker.nike.x25519
open CryptWalker.nike.x448
open CryptWalker.nike.x41417
open CryptWalker.nike.nike
open CryptWalker.kem.kem
open CryptWalker.kem.adapter
open CryptWalker.hash.Sha2
open CryptWalker.util.HList

namespace CryptWalker.kem.schemes

def defaultHash := fun x => Sha256.Digest.toBytes $ Sha256.hash x

instance : Adapter X25519Scheme where
  hash := defaultHash

instance : Adapter X448Scheme where
  hash := defaultHash

instance : Adapter X41417Scheme where
  hash := defaultHash

def X25519AsKEM : KEM X25519Scheme := inferInstance
def X448AsKEM : KEM X448Scheme := inferInstance
def X41417AsKEM : KEM X41417Scheme := inferInstance

def Schemes : HList [KEM X25519Scheme, KEM X448Scheme, KEM X41417Scheme] :=
  HList.cons (X25519AsKEM) $
  HList.cons (X448AsKEM) $
  HList.cons (X41417AsKEM) $
  HList.nil

end CryptWalker.kem.schemes

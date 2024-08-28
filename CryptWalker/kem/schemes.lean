
import CryptWalker.nike.x25519
import CryptWalker.nike.x448
import CryptWalker.nike.x41417
import CryptWalker.nike.nike
import CryptWalker.kem.kem
import CryptWalker.kem.adapter
import CryptWalker.hash.Sha2

open CryptWalker.nike.x25519
open CryptWalker.nike.x448
open CryptWalker.nike.x41417
open CryptWalker.nike.nike
open CryptWalker.kem.kem
open CryptWalker.kem.adapter
open CryptWalker.hash.Sha2

namespace CryptWalker.kem.schemes

def defaultHash := fun x => Sha256.hash x

instance : Adapter X25519Scheme where
  hash := defaultHash

instance : Adapter X448Scheme where
  hash := defaultHash

instance : Adapter X41417Scheme where
  hash := defaultHash

def X25519AsKEM : KEM X25519Scheme := inferInstance
def X448AsKEM : KEM X448Scheme := inferInstance
def X41417AsKEM : KEM X41417Scheme := inferInstance

def X25519Instance : X25519Scheme := {}
def X448Instance : X448Scheme := {}
def X41417Instance : X41417Scheme := {}

def Schemes : List (Σ α : Type, KEM α × α) :=
  [
    ⟨X25519Scheme, (X25519AsKEM, X25519Instance)⟩,
    ⟨X448Scheme, (X448AsKEM, X448Instance)⟩,
    ⟨X41417Scheme, (X41417AsKEM, X41417Instance)⟩,
  ]

end CryptWalker.kem.schemes

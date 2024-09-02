
import CryptWalker.nike.x25519
import CryptWalker.nike.x448
import CryptWalker.nike.x41417
import CryptWalker.nike.nike
import CryptWalker.kem.kem
import CryptWalker.kem.adapter
import CryptWalker.kem.combiner
import CryptWalker.hash.Sha2

open CryptWalker.nike
open CryptWalker.nike.nike
open CryptWalker.kem.kem
open CryptWalker.kem.adapter
open CryptWalker.kem.combiner
open CryptWalker.hash.Sha2

namespace CryptWalker.kem.schemes

def kemX25519 := toKEM $ Adapter.mk Sha256.hash x25519.Scheme
def kemX448 := toKEM $ Adapter.mk Sha256.hash x448.Scheme
def kem41417 := toKEM $ Adapter.mk Sha256.hash x41417.Scheme
def combinedKEM := createKEMCombiner "CombinedKEM" Sha256.hash [kemX25519, kemX448, kem41417]

def Schemes : List KEM :=
[
    toKEM $ Adapter.mk Sha256.hash x25519.Scheme,
    toKEM $ Adapter.mk Sha256.hash x448.Scheme,
    toKEM $ Adapter.mk Sha256.hash x41417.Scheme,
    combinedKEM
]

end CryptWalker.kem.schemes

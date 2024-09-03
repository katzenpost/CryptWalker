
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

def kemX25519 := createKEMAdapter Sha256.hash x25519.Scheme
def kemX448 := createKEMAdapter Sha256.hash x448.Scheme
def kemX41417 := createKEMAdapter Sha256.hash x41417.Scheme

def combinedClassicalKEM := createKEMCombiner "combinedClassicalKEM" Sha256.hash [kemX25519, kemX448, kemX41417]


def Schemes : List KEM :=
[
    kemX25519,
    kemX448,
    kemX41417,
    combinedClassicalKEM
]

end CryptWalker.kem.schemes

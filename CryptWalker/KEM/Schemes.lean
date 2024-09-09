
import CryptWalker.NIKE.X25519
import CryptWalker.NIKE.NIKE
import CryptWalker.KEM.KEM
import CryptWalker.KEM.Adapter
import CryptWalker.KEM.Combiner
import CryptWalker.Hash.Sha2

open CryptWalker.NIKE
open CryptWalker.NIKE.NIKE
open CryptWalker.KEM.KEM
open CryptWalker.KEM.Adapter
open CryptWalker.KEM.Combiner
open CryptWalker.Hash.Sha2

namespace CryptWalker.KEM

def kemX25519 := createKEMAdapter Sha256.hash X25519.Scheme

--def combinedClassicalKEM := createKEMCombiner "combinedClassicalKEM" Sha256.hash [kemX25519, kemX448, kemX41417]


def Schemes : List KEM :=
[
    kemX25519,
--    combinedClassicalKEM
]

end CryptWalker.KEM

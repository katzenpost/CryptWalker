
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


/-- SHA-256 as the adapter's hash, retyped to `Vector UInt8 32`. -/
def sha256V (b : ByteArray) : Vector UInt8 32 :=
  let r := Sha256.hash b
  ⟨r.val.data, r.property⟩


def kemX25519 : KEM := kemOfNike sha256V X25519.Scheme

def Schemes : List String := ["X25519"]


end CryptWalker.KEM

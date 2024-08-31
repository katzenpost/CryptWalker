import CryptWalker.nike.x25519
import CryptWalker.nike.x448
import CryptWalker.nike.x41417
import CryptWalker.nike.nike

namespace CryptWalker.nike.schemes

def Schemes : List CryptWalker.nike.nike.NIKE :=
  [
    CryptWalker.nike.x25519.Scheme,
    CryptWalker.nike.x448.Scheme,
    CryptWalker.nike.x41417.Scheme,
  ]

end CryptWalker.nike.schemes

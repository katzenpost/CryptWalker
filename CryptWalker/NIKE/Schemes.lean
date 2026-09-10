import CryptWalker.NIKE.X25519_montgomery_ladder
import CryptWalker.NIKE.X25519
import CryptWalker.NIKE.NIKE

open CryptWalker.NIKE.NIKE

namespace CryptWalker.NIKE

/-! # The X25519 schemes

Two implementations of the same exchange, kept side by side on purpose.

`X25519Scheme` is the group formulation: public keys are points on Curve25519 and the group
action is Mathlib's scalar multiplication, so `commutes` is proved rather than assumed.

`X25519LadderScheme` is the byte-level Montgomery ladder of RFC 7748. It is the faster and more
conventional one, but it has to take `curve25519_commutes` and `derivePub_safe` as axioms,
because it computes over byte strings with no group structure to appeal to.

They differ in two visible ways. Public keys encode differently — 65 bytes `0x04 ‖ x ‖ y` for
the group version, 32-byte u-coordinates for the ladder — and their `Safe` predicates differ:
the ladder rejects the small-order points, while in the group scalar multiplication is total
and there is nothing to reject. -/

def X25519Scheme : NIKE := X25519_math.Scheme

def X25519LadderScheme : NIKE := X25519.LadderScheme

def Schemes : List NIKE :=
  [
    X25519Scheme,
    X25519LadderScheme
  ]

end CryptWalker.NIKE

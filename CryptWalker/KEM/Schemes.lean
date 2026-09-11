
import CryptWalker.NIKE.X25519_montgomery_ladder
import CryptWalker.NIKE.NIKE
import CryptWalker.KEM.KEM
import CryptWalker.KEM.Adapter
import CryptWalker.KEM.Combiner
import CryptWalker.Hash.Sha2

open CryptWalker.NIKE
open CryptWalker.NIKE.NIKE
open CryptWalker.KEM.KEM
open CryptWalker.KEM.Adapter
open CryptWalker.Hash.Sha2

namespace CryptWalker.KEM


/-- SHA-256, retyped to `Vector UInt8 32`. -/
def sha256V (b : ByteArray) : Vector UInt8 32 :=
  let r := Sha256.hash b
  ⟨r.val.data, r.property⟩

/-- Big-endian `u32`, matching Go's `binary.BigEndian.PutUint32`. -/
def u32be (n : Nat) : ByteArray :=
  ⟨#[(n >>> 24).toUInt8, (n >>> 16).toUInt8, (n >>> 8).toUInt8, n.toUInt8]⟩

/-- A field under a big-endian 32-bit length prefix. -/
def lenPrefixed (b : ByteArray) : ByteArray := u32be b.size ++ b

/-- Domain-separation tag, identical to `sha256v1Label` in
`hpqc/kem/adapter/kem.go`. -/
def sha256v1Label : ByteArray := "kemadapter-sha256-v1".toUTF8

/-- The `sha256-v1` PRF:

```
SHA256(label || u32be(len(ss))       || ss
             || u32be(len(pkStatic)) || pkStatic
             || u32be(len(pkEph))    || pkEph)
```

Every variable-length field is length-prefixed, so the encoding is unambiguous
regardless of the NIKE's key sizes. This is a portable stand-in for hpqc's
deployed BLAKE2b XOF, not the deployed construction; it exists so that
implementations with SHA-256 but no BLAKE2b can still check shared vectors.

Defined only at `outLen = 32`, one SHA-256 digest. Go returns an error for any
other width; this returns zero-padding instead, since making it partial would
push an `Option` through `encapM`/`decapM` and their correctness proof for a
case no NIKE here reaches (X25519 has `sharedSecretSize = 32`). Callers must not
use it at another width. -/
def sha256v1Derive (ss pkStatic pkEph : ByteArray) (outLen : Nat) : Vector UInt8 outLen :=
  let d := sha256V (sha256v1Label ++ lenPrefixed ss ++ lenPrefixed pkStatic ++ lenPrefixed pkEph)
  Vector.ofFn (fun i => if h : i.val < 32 then d[i.val]'h else 0)

def sha256v1PRF : Adapter.PRF where
  name   := "sha256-v1"
  derive := sha256v1Derive

def kemX25519 : KEM := kemOfNike sha256v1PRF X25519_montgomery_ladder.LadderScheme

def Schemes : List String := ["X25519"]


end CryptWalker.KEM

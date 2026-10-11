
import CryptWalker.NIKE.X25519_montgomery_ladder
import CryptWalker.NIKE.X25519
import CryptWalker.NIKE.NIKE
import CryptWalker.KEM.KEM
import CryptWalker.KEM.Adapter
import CryptWalker.KEM.Combiner
import CryptWalker.KEM.MLKEM.MLKEM512
import CryptWalker.KEM.MLKEM.MLKEM768
import CryptWalker.KEM.MLKEM.MLKEM1024
import CryptWalker.KEM.MLKEMHedged.MLKEMHedged512
import CryptWalker.KEM.MLKEMHedged.MLKEMHedged768
import CryptWalker.KEM.MLKEMHedged.MLKEMHedged1024
import CryptWalker.Hash.Sha2
import CryptWalker.Hash.Blake2b
import CryptWalker.MAC.HMAC
import CryptWalker.Util.Bytes

open CryptWalker.NIKE
open CryptWalker.NIKE.NIKE
open CryptWalker.KEM.KEM
open CryptWalker.KEM.Adapter
open CryptWalker.Hash.Sha2
open CryptWalker.MAC.HMAC (hmacSha256)
open CryptWalker.Util.Bytes (ofVector toVecN)

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

/-- The `blake2b-xof` PRF, the deployed adapter configuration. `ss` keys the XOF directly only at
exactly 32 bytes -- the only width any NIKE here produces -- otherwise it's first collapsed to 32
bytes via an unkeyed BLAKE2b-256 hash. `xof`'s `size`/`readLen` coincide here (`outLen`/`ss.size`),
per `Adapter.lean`'s "wart" note. -/
def blake2bXOFDerive (ss pkStatic pkEph : ByteArray) (outLen : Nat) : Vector UInt8 outLen :=
  let xofKey := if ss.size == 32 then ss else ofVector (CryptWalker.Hash.Blake2b.hash256 ss)
  toVecN outLen (CryptWalker.Hash.Blake2b.xof xofKey outLen ss.size (pkStatic ++ pkEph))

def blake2bXOFPRF : Adapter.PRF where
  name   := "blake2b-xof"
  derive := blake2bXOFDerive

/-- The Montgomery-ladder X25519 implementation, wrapped into a KEM. Registered under
`"X25519LadderKEM"` — see the registry section below for why this diverges from `hpqc`'s own
naming. -/
def kemX25519Ladder : KEM := kemOfNike sha256v1PRF X25519_montgomery_ladder.LadderScheme

/-- The limb-ladder X25519 implementation (`NIKE.Schemes`'s `"x25519"`), wrapped into a KEM.
Registered under `"X25519KEM"`. The X25519 NIKEs agree byte-for-byte
(`CryptWalker.NIKE.test`'s `testX25519GroupAgreesWithLadder`, `NIKE.field25519_test`), so this is
the same KEM as before, computed by the fastest of them. -/
def kemX25519 : KEM := kemOfNike sha256v1PRF X25519_montgomery_ladder.FeScheme

/-- X25519 under the deployed `blake2b-xof` adapter PRF, vs. `kemX25519`'s portable `sha256-v1`
stand-in. Not in `registry`: `kemX25519` already fills that slot; callers wanting the deployed
PRF use this value directly. -/
def kemX25519Blake2b : KEM := kemOfNike blake2bXOFPRF CryptWalker.NIKE.X25519.Scheme

/-! ## The KEM registry

Names follow Noise protocol-name rules (`[A-Za-z0-9/]`, no `+`, which separates an ephemeral from a
static KEM), so a protocol string can name any registered KEM. `Sphinx.Schemes.schemeNames` merges
this registry with `NIKE.registry`, so the X25519 KEMs carry a `KEM` suffix their NIKEs lack.
ML-KEM private keys are in the seed form `ek ‖ d ‖ z`. -/

/-- A registered scheme: its name and the implementation `byName` returns for it. -/
structure RegistryEntry where
  name : String
  scheme : KEM

/-- `Combiner.PRF` with BLAKE2b-256: an unkeyed hash for key derivation and a keyed hash as the
per-component PRF, as in hpqc's `kem/combiner`. -/
def blake2b256CombinerPRF : Combiner.PRF where
  hash  := CryptWalker.Hash.Blake2b.hash256
  keyed := fun key msg => CryptWalker.Hash.Blake2b.hash256Keyed (Combiner.toBytes key) msg

/-- X25519 combined with a post-quantum KEM via the split-PRF combiner: IND-CCA2 as long as at
least one component is (Giacon, Heuer & Poettering, https://eprint.iacr.org/2018/024.pdf,
Theorem 1). This is hpqc's generic `"MLKEM768-X25519"` construction, not X-Wing. -/
def withX25519 (pq : KEM) : KEM := Combiner.combineKEM blake2b256CombinerPRF kemX25519 [pq]

def kemMLKEM512X25519 : KEM := withX25519 CryptWalker.KEM.MLKEM512.kemMLKEM512Seed
def kemMLKEM768X25519 : KEM := withX25519 CryptWalker.KEM.MLKEM768.kemMLKEM768Seed
def kemMLKEM1024X25519 : KEM := withX25519 CryptWalker.KEM.MLKEM1024.kemMLKEM1024Seed

def kemMLKEMHedged512X25519 : KEM := withX25519 CryptWalker.KEM.MLKEMHedged.kemMLKEMHedged512Seed
def kemMLKEMHedged768X25519 : KEM := withX25519 CryptWalker.KEM.MLKEMHedged.kemMLKEMHedged768Seed
def kemMLKEMHedged1024X25519 : KEM := withX25519 CryptWalker.KEM.MLKEMHedged.kemMLKEMHedged1024Seed

/-- `kemMLKEM768X25519` over `kemX25519Blake2b` instead of `kemX25519`. Not in `registry`, same
reason as `kemX25519Blake2b`. -/
def kemMLKEM768X25519Blake2b : KEM :=
  Combiner.combineKEM blake2b256CombinerPRF kemX25519Blake2b
    [CryptWalker.KEM.MLKEM768.kemMLKEM768Seed]

/-- Every registered KEM. ML-KEM's `Reliable` is a real condition, unlike the X25519 KEMs' trivial
one, so a caller building a `KEMSphinxScheme` from an ML-KEM entry must discharge it. The hedged
schemes restore round-3 Kyber's `m ← H(m)` and are not FIPS 203. -/
def registry : List RegistryEntry :=
  [ { name := "X25519LadderKEM", scheme := kemX25519Ladder },
    { name := "X25519KEM", scheme := kemX25519 },
    { name := "MLKEM512", scheme := CryptWalker.KEM.MLKEM512.kemMLKEM512Seed },
    { name := "MLKEM768", scheme := CryptWalker.KEM.MLKEM768.kemMLKEM768Seed },
    { name := "MLKEM1024", scheme := CryptWalker.KEM.MLKEM1024.kemMLKEM1024Seed },
    { name := "MLKEM512Hedged", scheme := CryptWalker.KEM.MLKEMHedged.kemMLKEMHedged512Seed },
    { name := "MLKEM768Hedged", scheme := CryptWalker.KEM.MLKEMHedged.kemMLKEMHedged768Seed },
    { name := "MLKEM1024Hedged", scheme := CryptWalker.KEM.MLKEMHedged.kemMLKEMHedged1024Seed },
    { name := "MLKEM512X25519", scheme := kemMLKEM512X25519 },
    { name := "MLKEM768X25519", scheme := kemMLKEM768X25519 },
    { name := "MLKEM1024X25519", scheme := kemMLKEM1024X25519 },
    { name := "MLKEM512HedgedX25519", scheme := kemMLKEMHedged512X25519 },
    { name := "MLKEM768HedgedX25519", scheme := kemMLKEMHedged768X25519 },
    { name := "MLKEM1024HedgedX25519", scheme := kemMLKEMHedged1024X25519 } ]

/-- Case-insensitive lookup by registry name. -/
def byName (name : String) : Option KEM :=
  (registry.find? (·.name.toLower == name.toLower)).map (·.scheme)

end CryptWalker.KEM

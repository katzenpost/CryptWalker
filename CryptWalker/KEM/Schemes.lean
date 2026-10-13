
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

/-- Big-endian `u32`. -/
def u32be (n : Nat) : ByteArray :=
  ⟨#[(n >>> 24).toUInt8, (n >>> 16).toUInt8, (n >>> 8).toUInt8, n.toUInt8]⟩

/-- A field under a big-endian 32-bit length prefix. -/
def lenPrefixed (b : ByteArray) : ByteArray := u32be b.size ++ b

/-- Domain-separation tag for `sha256-v1`. -/
def sha256v1Label : ByteArray := "kemadapter-sha256-v1".toUTF8

/-- The `sha256-v1` PRF:

```
SHA256(label || u32be(len(ss))       || ss
             || u32be(len(pkStatic)) || pkStatic
             || u32be(len(pkEph))    || pkEph)
```

Only meaningful at `outLen = 32`; other widths are zero-padded or truncated. -/
def sha256v1Derive (ss pkStatic pkEph : ByteArray) (outLen : Nat) : Vector UInt8 outLen :=
  let d := sha256V (sha256v1Label ++ lenPrefixed ss ++ lenPrefixed pkStatic ++ lenPrefixed pkEph)
  Vector.ofFn (fun i => if h : i.val < 32 then d[i.val]'h else 0)

def sha256v1PRF : Adapter.PRF where
  name   := "sha256-v1"
  derive := sha256v1Derive

/-- The `blake2b-xof` PRF: a BLAKE2b XOF keyed by `ss`, or by BLAKE2b-256 of `ss` if it is not
32 bytes. -/
def blake2bXOFDerive (ss pkStatic pkEph : ByteArray) (outLen : Nat) : Vector UInt8 outLen :=
  let xofKey := if ss.size == 32 then ss else ofVector (CryptWalker.Hash.Blake2b.hash256 ss)
  toVecN outLen (CryptWalker.Hash.Blake2b.xof xofKey outLen ss.size (pkStatic ++ pkEph))

def blake2bXOFPRF : Adapter.PRF where
  name   := "blake2b-xof"
  derive := blake2bXOFDerive

/-- X25519 (Montgomery ladder) as a KEM. -/
def kemX25519Ladder : KEM := kemOfNike sha256v1PRF X25519_montgomery_ladder.LadderScheme

/-- X25519 (limb ladder) as a KEM. -/
def kemX25519 : KEM := kemOfNike sha256v1PRF X25519_montgomery_ladder.FeScheme

/-- X25519 as a KEM with the `blake2b-xof` PRF. Not registered. -/
def kemX25519Blake2b : KEM := kemOfNike blake2bXOFPRF CryptWalker.NIKE.X25519.Scheme

/-! ## The KEM registry

Names use only `[A-Za-z0-9/]`, as in Noise protocol names. X25519 KEMs carry a `KEM` suffix to
stay distinct from the X25519 NIKEs. ML-KEM private keys are in the seed form `ek ‖ d ‖ z`. -/

structure RegistryEntry where
  name : String
  scheme : KEM

/-- `Combiner.PRF` with unkeyed and keyed BLAKE2b-256. -/
def blake2b256CombinerPRF : Combiner.PRF where
  hash  := CryptWalker.Hash.Blake2b.hash256
  keyed := fun key msg => CryptWalker.Hash.Blake2b.hash256Keyed (Combiner.toBytes key) msg

/-- X25519 combined with a post-quantum KEM via the split-PRF combiner (not X-Wing). IND-CCA2 if
either component is (https://eprint.iacr.org/2018/024.pdf, Theorem 1). -/
def withX25519 (pq : KEM) : KEM := Combiner.combineKEM blake2b256CombinerPRF kemX25519 [pq]

def kemMLKEM512X25519 : KEM := withX25519 CryptWalker.KEM.MLKEM512.kemMLKEM512Seed
def kemMLKEM768X25519 : KEM := withX25519 CryptWalker.KEM.MLKEM768.kemMLKEM768Seed
def kemMLKEM1024X25519 : KEM := withX25519 CryptWalker.KEM.MLKEM1024.kemMLKEM1024Seed

def kemMLKEMHedged512X25519 : KEM := withX25519 CryptWalker.KEM.MLKEMHedged.kemMLKEMHedged512Seed
def kemMLKEMHedged768X25519 : KEM := withX25519 CryptWalker.KEM.MLKEMHedged.kemMLKEMHedged768Seed
def kemMLKEMHedged1024X25519 : KEM := withX25519 CryptWalker.KEM.MLKEMHedged.kemMLKEMHedged1024Seed

/-- `kemMLKEM768X25519` over `kemX25519Blake2b`. Not registered. -/
def kemMLKEM768X25519Blake2b : KEM :=
  Combiner.combineKEM blake2b256CombinerPRF kemX25519Blake2b
    [CryptWalker.KEM.MLKEM768.kemMLKEM768Seed]

/-- Every registered KEM. The hedged schemes restore round-3 Kyber's `m ← H(m)` and are not
FIPS 203. -/
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

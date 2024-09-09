import CryptWalker.Util.Hex
import CryptWalker.Util.ByteArray
import CryptWalker.Util.UInt64
import CryptWalker.Util.Nat
import CryptWalker.Util.newhex

open CryptWalker.Util.newhex
open CryptWalker.Util.Hex
open CryptWalker.Util.ByteArray
open CryptWalker.Util.UInt64
open CryptWalker.Util.Nat

namespace CryptWalker.Hash.Sha2
namespace Sha512

def Nat.to_be64 (x: Nat): ByteArray := {
  data := #[
    UInt8.ofNat (x >>> (8*7)),
    UInt8.ofNat (x >>> (8*6)),
    UInt8.ofNat (x >>> (8*5)),
    UInt8.ofNat (x >>> (8*4)),
    UInt8.ofNat (x >>> (8*3)),
    UInt8.ofNat (x >>> (8*2)),
    UInt8.ofNat (x >>> (8*1)),
    UInt8.ofNat x
  ]
}

structure Digest where
  h0: UInt64
  h1: UInt64
  h2: UInt64
  h3: UInt64
  h4: UInt64
  h5: UInt64
  h6: UInt64
  h7: UInt64
  deriving BEq

def Digest.new (h0 h1 h2 h3 h4 h5 h6 h7: UInt64): Digest :=
  { h0, h1, h2, h3, h4, h5, h6, h7 }

instance : Inhabited Digest where
  default := Digest.new 0 0 0 0 0 0 0 0

def Digest.add (d1 d2: Digest): Digest :=
  { h0 := d1.h0 + d2.h0,
    h1 := d1.h1 + d2.h1,
    h2 := d1.h2 + d2.h2,
    h3 := d1.h3 + d2.h3,
    h4 := d1.h4 + d2.h4,
    h5 := d1.h5 + d2.h5,
    h6 := d1.h6 + d2.h6,
    h7 := d1.h7 + d2.h7 }

def Digest.toBytes (d: Digest): ByteArray :=
  UInt64.to_be d.h0 ++
  UInt64.to_be d.h1 ++
  UInt64.to_be d.h2 ++
  UInt64.to_be d.h3 ++
  UInt64.to_be d.h4 ++
  UInt64.to_be d.h5 ++
  UInt64.to_be d.h6 ++
  UInt64.to_be d.h7

def init_hash: Digest :=
  { h0 := 0x6a09e667f3bcc908, h1 := 0xbb67ae8584caa73b, h2 := 0x3c6ef372fe94f82b, h3 := 0xa54ff53a5f1d36f1,
    h4 := 0x510e527fade682d1, h5 := 0x9b05688c2b3e6c1f, h6 := 0x1f83d9abfb41bd6b, h7 := 0x5be0cd19137e2179 }

def K : Array UInt64 := #[
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fb44, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
]

def rotr (x : UInt64) (n : Nat) : UInt64 :=
  UInt64.ror x n

def choice (x y z : UInt64) : UInt64 := (x &&& y) ^^^ (~~~x &&& z)
def majority (x y z : UInt64) : UInt64 := (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)
def bigSigma0 (x : UInt64) : UInt64 := rotr x 28 ^^^ rotr x 34 ^^^ rotr x 39
def bigSigma1 (x : UInt64) : UInt64 := rotr x 14 ^^^ rotr x 18 ^^^ rotr x 41
def smallSigma0 (x : UInt64) : UInt64 := rotr x 1 ^^^ rotr x 8 ^^^ (x >>> 7)
def smallSigma1 (x : UInt64) : UInt64 := rotr x 19 ^^^ rotr x 61 ^^^ (x >>> 6)

def prepare (msg : ByteArray): Array UInt64 :=
  let padding :=
    let padding_required :=
      let size := msg.size + 1 + 16
      let rem := size % 128
      if rem == 0 then 0 else 128 - rem
    { data :=  #[0x80] ++ Array.mkArray padding_required 0x00 }
  let length := Nat.to_be64 (msg.size * 8)
  ByteArray.to_be64 (msg ++ padding ++ length)

def to_chunks (msg: Array UInt64): List (Array UInt64) :=
  Id.run do
    let mut out := []
    for chunk in [0:msg.size / 16] do
      let start := chunk * 16
      let stop := start + 16
      out := Array.extract msg start stop :: out
    pure out

def schedule (message: Array UInt64): Array UInt64 :=
  Id.run do
    let mut w: Array UInt64 := Array.mkEmpty 80
    for i in [0:80] do
      if i < 16 then
        w := w.push message[i]!
      else do
        let w15 := w[i-15]!
        let w2 := w[i-2]!
        let s0 := (rotr w15 1) ^^^ (rotr w15 8) ^^^ (w15 >>> 7)
        let s1 := (rotr w2 19) ^^^ (rotr w2 61) ^^^ (w2 >>> 6)
        let w' := w[i-16]! + s0 + w[i-7]! + s1
        w := w.push w'
    pure w

def compress_loop (chunk: Array UInt64) (state: Digest): Digest :=
  Id.run do
    let mut a := state.h0
    let mut b := state.h1
    let mut c := state.h2
    let mut d := state.h3
    let mut e := state.h4
    let mut f := state.h5
    let mut g := state.h6
    let mut h := state.h7
    let w := schedule chunk
    for i in [0:80] do
      let S1 := bigSigma1 e
      let ch := choice e f g
      let temp1 := h + S1 + ch + K[i]! + w[i]!
      let S0 := bigSigma0 a
      let maj := majority a b c
      let temp2 := S0 + maj
      h := g
      g := f
      f := e
      e := d + temp1
      d := c
      c := b
      b := a
      a := temp1 + temp2
    pure (Digest.new a b c d e f g h)

def compress (chunk: Array UInt64) (h: Digest): Digest :=
  if chunk.size != 16 then panic s!"Invalid chunk size: {chunk.size}"
  else
    let j := compress_loop chunk h
    Digest.add h j

def hash (msg: ByteArray): ByteArray :=
  let padded := prepare msg
  let chunks := to_chunks padded
  Digest.toBytes $ List.foldr compress init_hash chunks


end Sha512
end CryptWalker.Hash.Sha2

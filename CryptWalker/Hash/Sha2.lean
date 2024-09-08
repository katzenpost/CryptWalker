/-
 Copyright 2023 RISC Zero, Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-/

import CryptWalker.Util.Hex
import CryptWalker.Util.ByteArray
import CryptWalker.Util.Nat
import CryptWalker.Util.UInt32
import CryptWalker.Util.Serial

namespace CryptWalker.Hash.Sha2

open CryptWalker.Util.ByteArray
open CryptWalker.Util.Nat
open CryptWalker.Util.UInt32
open CryptWalker.Util.Serial

namespace Sha256

structure Digest where
  h0: UInt32
  h1: UInt32
  h2: UInt32
  h3: UInt32
  h4: UInt32
  h5: UInt32
  h6: UInt32
  h7: UInt32
  deriving BEq

def Digest.new (h0 h1 h2 h3 h4 h5 h6 h7: UInt32): Digest
  := { h0, h1, h2, h3, h4, h5, h6, h7 }

instance : Inhabited Digest where
  default := Digest.new 0 0 0 0 0 0 0 0

def Digest.add (d1 d2: Digest): Digest
  := {
    h0 := d1.h0 + d2.h0
    h1 := d1.h1 + d2.h1
    h2 := d1.h2 + d2.h2
    h3 := d1.h3 + d2.h3
    h4 := d1.h4 + d2.h4
    h5 := d1.h5 + d2.h5
    h6 := d1.h6 + d2.h6
    h7 := d1.h7 + d2.h7
  }

def Digest.xor (d1 d2: Digest): Digest
  := {
    h0 := d1.h0 ^^^ d2.h0
    h1 := d1.h1 ^^^ d2.h1
    h2 := d1.h2 ^^^ d2.h2
    h3 := d1.h3 ^^^ d2.h3
    h4 := d1.h4 ^^^ d2.h4
    h5 := d1.h5 ^^^ d2.h5
    h6 := d1.h6 ^^^ d2.h6
    h7 := d1.h7 ^^^ d2.h7
  }

def Digest.ofArray (d: Array UInt32): Digest
  := Digest.new d[0]! d[1]! d[2]! d[3]! d[4]! d[5]! d[6]! d[7]!

def Digest.ofSubarray (d: Subarray UInt32): Digest
  := Digest.new d[0]! d[1]! d[2]! d[3]! d[4]! d[5]! d[6]! d[7]!

def Digest.toArray (d: Digest): Array UInt32
  := #[ d.h0, d.h1, d.h2, d.h3, d.h4, d.h5, d.h6, d.h7 ]

def Digest.toSubarray (d: Digest): Subarray UInt32
  := (Digest.toArray d).toSubarray

def Digest.toBytes (d: Digest): ByteArray
  :=
    UInt32.to_be d.h0 ++
    UInt32.to_be d.h1 ++
    UInt32.to_be d.h2 ++
    UInt32.to_be d.h3 ++
    UInt32.to_be d.h4 ++
    UInt32.to_be d.h5 ++
    UInt32.to_be d.h6 ++
    UInt32.to_be d.h7

def init_hash: Digest
  := {
    h0 := 0x6a09e667,
    h1 := 0xbb67ae85,
    h2 := 0x3c6ef372,
    h3 := 0xa54ff53a,
    h4 := 0x510e527f,
    h5 := 0x9b05688c,
    h6 := 0x1f83d9ab,
    h7 := 0x5be0cd19
  }

def round_constants: Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

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

def prepare (msg: ByteArray): Array UInt32 :=
  let padding :=
    let padding_required :=
      let size := msg.size + 1 + 8
      let rem := size % 64
      if rem == 0 then 0 else 64 - rem
    { data := #[0x80] ++ Array.mkArray padding_required 0x00 }
  let length := Nat.to_be64 (msg.size * 8)
  ByteArray.to_be32 (msg ++ padding ++ length)

def to_chunks (msg: Array UInt32): List (Array UInt32)
  := Id.run do
        let mut out := []
        for chunk in [0:msg.size / 16] do
          let start := chunk * 16
          let stop := start + 16
          out := Array.extract msg start stop :: out
        pure out

def schedule (message: Array UInt32): Array UInt32
  := Id.run do
        let mut w: Array UInt32 := Array.mkEmpty 64
        for i in [0:64] do
          if i < 16
            then w := w.push message[i]!
            else do let w15 := w[i-15]!
                    let w2 := w[i-2]!
                    let s0 := (UInt32.ror w15  7) ^^^ (UInt32.ror w15 18) ^^^ (w15 >>> 3)
                    let s1 := (UInt32.ror w2  17) ^^^ (UInt32.ror w2  19) ^^^ (w2 >>> 10)
                    let w' := w[i-16]! + s0 + w[i-7]! + s1
                    w := w.push w'
        pure w

def compress_loop (chunk: Array UInt32) (state: Digest): Digest
  := Id.run do
        let mut a := state.h0
        let mut b := state.h1
        let mut c := state.h2
        let mut d := state.h3
        let mut e := state.h4
        let mut f := state.h5
        let mut g := state.h6
        let mut h := state.h7
        let w := schedule chunk
        for i in [0:64] do
          let S1 := (UInt32.ror e 6) ^^^ (UInt32.ror e 11) ^^^ (UInt32.ror e 25)
          let ch := (e &&& f) ^^^ ((~~~ e) &&& g)
          let temp1 := h + S1 + ch + round_constants[i]! + w[i]!
          let S0 := (UInt32.ror a 2) ^^^ (UInt32.ror a 13) ^^^ (UInt32.ror a 22)
          let maj := (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)
          let temp2 := S0 + maj
          h := g
          g := f
          f := e
          e := (d + temp1)
          d := c
          c := b
          b := a
          a := (temp1 + temp2)
        pure (Digest.new a b c d e f g h)

def compress (chunk: Array UInt32) (h: Digest): Digest :=
  if chunk.size != 16 then panic s!"Invalid chunk size: {chunk.size}"
  else
    let j := compress_loop chunk h
    Digest.add h j

def hash (msg: ByteArray): ByteArray :=
  let padded := prepare msg
  let chunks := to_chunks padded
  Digest.toBytes $ List.foldr compress init_hash chunks

end Sha256

end CryptWalker.Hash.Sha2

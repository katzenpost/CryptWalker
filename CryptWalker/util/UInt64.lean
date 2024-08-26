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

namespace CryptWalker.util.UInt64

def UInt64.test_bit (bit: Nat) (x: UInt64): Bool :=
  (1 <<< bit).toUInt64 &&& x != 0

/- Endian helpers -/

def UInt64.swap_endian (x: UInt64): UInt64 :=
  let a0 := x &&& 0xff
  let a1 := (x >>> (8*1)) &&& 0xff
  let a2 := (x >>> (8*2)) &&& 0xff
  let a3 := (x >>> (8*3)) &&& 0xff
  let a4 := (x >>> (8*4)) &&& 0xff
  let a5 := (x >>> (8*5)) &&& 0xff
  let a6 := (x >>> (8*6)) &&& 0xff
  let a7 := (x >>> (8*7)) &&& 0xff
  let c0 := a0 <<< (8*7)
  let c1 := a1 <<< (8*6)
  let c2 := a2 <<< (8*5)
  let c3 := a3 <<< (8*4)
  let c4 := a4 <<< (8*3)
  let c5 := a5 <<< (8*2)
  let c6 := a6 <<< (8*1)
  let c7 := a7
  c7 ||| c6 ||| c5 ||| c4 ||| c3 ||| c2 ||| c1 ||| c0

def UInt64.ror (x: UInt64) (n: Nat): UInt64 :=
  let l := x >>> UInt64.ofNat n
  let r := x <<< UInt64.ofNat (64 - n)
  l ||| r

def UInt64.of_be64 (b7 b6 b5 b4 b3 b2 b1 b0: UInt8): UInt64 :=
  let c0 := UInt64.ofNat (b0.val.val)
  let c1 := UInt64.ofNat (b1.val.val) <<< (8*1)
  let c2 := UInt64.ofNat (b2.val.val) <<< (8*2)
  let c3 := UInt64.ofNat (b3.val.val) <<< (8*3)
  let c4 := UInt64.ofNat (b4.val.val) <<< (8*4)
  let c5 := UInt64.ofNat (b5.val.val) <<< (8*5)
  let c6 := UInt64.ofNat (b6.val.val) <<< (8*6)
  let c7 := UInt64.ofNat (b7.val.val) <<< (8*7)
  c7 ||| c6 ||| c5 ||| c4 ||| c3 ||| c2 ||| c1 ||| c0

def UInt64.to_le (x: UInt64): ByteArray :=
  let a0 := UInt8.ofNat <| UInt64.toNat <| x &&& 0xff
  let a1 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*1)) &&& 0xff
  let a2 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*2)) &&& 0xff
  let a3 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*3)) &&& 0xff
  let a4 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*4)) &&& 0xff
  let a5 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*5)) &&& 0xff
  let a6 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*6)) &&& 0xff
  let a7 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*7)) &&& 0xff
  { data := #[ a0, a1, a2, a3, a4, a5, a6, a7 ] }

def UInt64.to_be (x: UInt64): ByteArray :=
  let a0 := UInt8.ofNat <| UInt64.toNat <| x &&& 0xff
  let a1 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*1)) &&& 0xff
  let a2 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*2)) &&& 0xff
  let a3 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*3)) &&& 0xff
  let a4 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*4)) &&& 0xff
  let a5 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*5)) &&& 0xff
  let a6 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*6)) &&& 0xff
  let a7 := UInt8.ofNat <| UInt64.toNat <| (x >>> (8*7)) &&& 0xff
  { data := #[ a7, a6, a5, a4, a3, a2, a1, a0 ] }

end CryptWalker.util.UInt64

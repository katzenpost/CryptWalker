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

namespace CryptWalker.util.Serial

class SerialUInt32 (X: Type) where
  words: Nat
  toUInt32Words: X -> Array UInt32
  fromUInt32Words: Subarray UInt32 -> X

instance : SerialUInt32 UInt32 where
  words := 1
  toUInt32Words x := #[x]
  fromUInt32Words x := x[0]!


class SerialWords (Word : Type) (X : Type) where
  words : Nat
  toWords : X -> Array Word
  fromWords : Subarray Word -> X

instance : SerialWords UInt32 UInt32 where
  words := 1
  toWords x := #[x]
  fromWords x := x[0]!

instance : SerialWords UInt64 UInt64 where
  words := 1
  toWords x := #[x]
  fromWords x := x[0]!


end CryptWalker.util.Serial

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

import CryptWalker.Util.UInt32
import CryptWalker.Util.UInt64

namespace CryptWalker.Util.ByteArray

open CryptWalker.Util.UInt32
open CryptWalker.Util.UInt64

/- Endian helpers -/

partial def ByteArray.to_be32 (x: ByteArray) (i: Nat := 0) (out: Array UInt32 := #[]): Array UInt32 :=
  if i + 4 <= x.size
  then ByteArray.to_be32 x (i + 4) (out.push (UInt32.of_be32 x[i]! x[i+1]! x[i+2]! x[i+3]!))
  else out

partial def ByteArray.to_le32 (x: ByteArray) (i: Nat := 0) (out: Array UInt32 := #[]): Array UInt32 :=
  if i + 4 <= x.size
  then ByteArray.to_le32 x (i + 4) (out.push (UInt32.of_be32 x[i+3]! x[i+2]! x[i+1]! x[i]!))
  else out

partial def ByteArray.of_le32 (x: Subarray UInt32) (i: Nat := 0) (out: ByteArray := ByteArray.mkEmpty (x.size * 4)): ByteArray
  := if h: i < x.size
      then ByteArray.of_le32 x (i + 1) (out ++ UInt32.to_le x[i])
      else out

#eval (ByteArray.of_le32 #[0xff000001, 0xcc000002].toSubarray).data == #[1, 0, 0, 0xff, 2, 0, 0, 0xcc]
#eval ByteArray.to_le32 (ByteArray.of_le32 #[0xff000001, 0xcc000002].toSubarray) == #[0xff000001, 0xcc000002]

partial def ByteArray.of_be32 (x: Subarray UInt32) (i: Nat := 0) (out: ByteArray := ByteArray.mkEmpty (x.size * 4)): ByteArray
  := if h: i < x.size
      then ByteArray.of_be32 x (i + 1) (out ++ UInt32.to_be x[i])
      else out

-- UInt64

partial def ByteArray.to_be64 (x: ByteArray) (i: Nat := 0) (out: Array UInt64 := #[]): Array UInt64 :=
  if i + 8 <= x.size then
    ByteArray.to_be64 x (i + 8) (out.push (UInt64.of_be64 x[i+7]! x[i+6]! x[i+5]! x[i+4]! x[i+3]! x[i+2]! x[i+1]! x[i]!))
  else out

partial def ByteArray.to_le64 (x: ByteArray) (i: Nat := 0) (out: Array UInt64 := #[]): Array UInt64 :=
  if i + 8 <= x.size then
    ByteArray.to_le64 x (i + 8) (out.push (UInt64.of_be64 x[i]! x[i+1]! x[i+2]! x[i+3]! x[i+4]! x[i+5]! x[i+6]! x[i+7]!))
  else out

partial def ByteArray.of_le64 (x: Subarray UInt64) (i: Nat := 0) (out: ByteArray := ByteArray.mkEmpty (x.size * 8)): ByteArray :=
  if h: i < x.size then
    ByteArray.of_le64 x (i + 1) (out ++ UInt64.to_le x[i])
  else out

partial def ByteArray.of_be64 (x: Subarray UInt64) (i: Nat := 0) (out: ByteArray := ByteArray.mkEmpty (x.size * 8)): ByteArray :=
  if h: i < x.size then
    ByteArray.of_be64 x (i + 1) (out ++ UInt64.to_be x[i])
  else out

end CryptWalker.Util.ByteArray

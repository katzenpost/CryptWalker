import Init.Data.UInt
import Init.Data.ByteArray
import Init.System.IO
import Init.Data.String

import CryptWalker.Util.newhex
import CryptWalker.Util.newnat
import CryptWalker.StreamCipher.Chacha20

open CryptWalker.Util.newhex
open CryptWalker.Util.newnat
open CryptWalker.StreamCipher.Chacha20


def testChaCha20Encrypt : IO Unit :=
  let key := [toUInt32 "00010203", toUInt32 "04050607", toUInt32 "08090a0b", toUInt32 "0c0d0e0f",
              toUInt32 "10111213", toUInt32 "14151617", toUInt32 "18191a1b", toUInt32 "1c1d1e1f"]
  let nonce := [toUInt32 "00000000", toUInt32 "0000004a", toUInt32 "00000000"]
  let counter := toUInt32 "1"
  let plaintext := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".toList.map Char.toUInt8
  let ciphertext := chaCha20Encrypt key counter nonce plaintext
  ciphertext.forM (fun byte => printHex byte.toUInt32)


def main : IO Unit := do
  testChaCha20Encrypt

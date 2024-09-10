
import Mathlib.Data.ByteArray

namespace CryptWalker.Util.newnat

def natToBytesAux (n : Nat) (acc : List UInt8) : List UInt8 :=
  if n == 0 then acc else natToBytesAux (n / 256) (UInt8.ofNat (n % 256) :: acc)
termination_by n
decreasing_by
  simp_wf
  simp_all
  omega

def natToBytes (n : Nat) : ByteArray :=
  List.toByteArray (natToBytesAux n [])

end CryptWalker.Util.newnat

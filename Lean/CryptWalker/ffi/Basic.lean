
import Lean

def addTwo (a b : UInt32) : UInt32 := a + b
def addThree (a b c : UInt32) : UInt32 := a + b + c

@[extern "add_from_rust1"]
opaque addFromRust1 : UInt32 → UInt32 → UInt32

@[extern "rust_hello"]
opaque hello : BaseIO Unit

@[extern "create_tuple"]
opaque create_nat_tuple_impl : Nat → Nat → Nat × Nat

def createNatPair (a b : Nat) : Nat × Nat :=
  create_nat_tuple_impl a b

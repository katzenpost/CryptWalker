import Batteries.Classes.SatisfiesM

structure NIKESpec where
  State : Type
  NikePublicKey : Type
  NikePrivateKey : Type
  SharedSecret : Type
  toPublicKey : NikePrivateKey → NikePublicKey
  deriveSecret : NikePrivateKey → NikePublicKey → StateM State SharedSecret
  init : State
  nike_generate : StateM State (Σ' (pk : NikePublicKey), {sk : NikePrivateKey //
    ∀ s sk2,
      let pk2 := toPublicKey sk2;
      (deriveSecret sk pk2 s).1 = (deriveSecret sk2 pk s).1})
  [sharedSecretEq : DecidableEq SharedSecret]

instance : Inhabited NIKESpec := ⟨{
  State := Unit,
  NikePublicKey := Unit,
  NikePrivateKey := Unit,
  SharedSecret := Unit,
  toPublicKey := fun _ => (),
  deriveSecret := fun _ _ => pure (),
  init := (),
  nike_generate := pure ⟨(), (), fun () _ => rfl⟩,
  sharedSecretEq := inferInstance
}⟩

opaque nikeSpec : NIKESpec

instance : Inhabited nikeSpec.State := ⟨nikeSpec.init⟩

abbrev NIKEM := StateM nikeSpec.State

def NikePublicKey : Type := nikeSpec.NikePublicKey
instance : Inhabited NikePublicKey := ⟨(nikeSpec.nike_generate default).1.1⟩

def NikePrivateKey : Type := nikeSpec.NikePrivateKey
instance : Inhabited NikePrivateKey := ⟨(nikeSpec.nike_generate default).1.2.1⟩

def SharedSecret : Type := nikeSpec.SharedSecret
instance : Inhabited SharedSecret :=
  ⟨(nikeSpec.deriveSecret (nikeSpec.nike_generate default).1.2.1 (nikeSpec.nike_generate default).1.1 default).1⟩

def nike_generate : NIKEM (NikePublicKey × NikePrivateKey) := fun s =>
  let (⟨pk, sk, _⟩, s) := nikeSpec.nike_generate s
  ((pk, sk), s)

def toPublicKey : NikePrivateKey → NikePublicKey := nikeSpec.toPublicKey

def deriveSecret : NikePrivateKey → NikePublicKey → NIKEM SharedSecret := nikeSpec.deriveSecret

instance : DecidableEq SharedSecret := nikeSpec.sharedSecretEq

def IsSharedSecret (sk1 : NikePrivateKey) (pk2 : NikePublicKey) (secret : SharedSecret) :=
  ∀ s, (deriveSecret sk1 pk2 s).1 = secret

def NikeKeyPair (pk : NikePublicKey) (sk : NikePrivateKey) :=
  ∀ s sk2,
    let pk2 := toPublicKey sk2;
    (deriveSecret sk pk2 s).1 = (deriveSecret sk2 pk s).1

/-
theorem nike_generate_ok : SatisfiesM (fun (pk, sk) => NikeKeyPair pk sk) generate := by
  sorry
-/

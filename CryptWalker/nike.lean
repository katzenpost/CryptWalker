import Batteries.Classes.SatisfiesM

structure NIKESpec where
  State : Type
  PublicKey : Type
  PrivateKey : Type
  SharedSecret : Type
  toPublicKey : PrivateKey → PublicKey
  deriveSecret : PrivateKey → PublicKey → StateM State SharedSecret
  init : State
  generate : StateM State (Σ' (pk : PublicKey), {sk : PrivateKey //
    ∀ s sk2,
      let pk2 := toPublicKey sk2;
      (deriveSecret sk pk2 s).1 = (deriveSecret sk2 pk s).1})
  [sharedSecretEq : DecidableEq SharedSecret]

instance : Inhabited NIKESpec := ⟨{
  State := Unit,
  PublicKey := Unit,
  PrivateKey := Unit,
  SharedSecret := Unit,
  toPublicKey := fun _ => (),
  deriveSecret := fun _ _ => pure (),
  init := (),
  generate := pure ⟨(), (), fun () _ => rfl⟩,
  sharedSecretEq := inferInstance
}⟩

opaque nikeSpec : NIKESpec

instance : Inhabited nikeSpec.State := ⟨nikeSpec.init⟩

abbrev NIKEM := StateM nikeSpec.State

def PublicKey : Type := nikeSpec.PublicKey
instance : Inhabited PublicKey := ⟨(nikeSpec.generate default).1.1⟩

def PrivateKey : Type := nikeSpec.PrivateKey
instance : Inhabited PrivateKey := ⟨(nikeSpec.generate default).1.2.1⟩

def SharedSecret : Type := nikeSpec.SharedSecret
instance : Inhabited SharedSecret :=
  ⟨(nikeSpec.deriveSecret (nikeSpec.generate default).1.2.1 (nikeSpec.generate default).1.1 default).1⟩

def generate : NIKEM (PublicKey × PrivateKey) := fun s =>
  let (⟨pk, sk, _⟩, s) := nikeSpec.generate s
  ((pk, sk), s)

def toPublicKey : PrivateKey → PublicKey := nikeSpec.toPublicKey

def deriveSecret : PrivateKey → PublicKey → NIKEM SharedSecret := nikeSpec.deriveSecret

instance : DecidableEq SharedSecret := nikeSpec.sharedSecretEq

def IsSharedSecret (sk1 : PrivateKey) (pk2 : PublicKey) (secret : SharedSecret) :=
  ∀ s, (deriveSecret sk1 pk2 s).1 = secret

def KeyPair (pk : PublicKey) (sk : PrivateKey) :=
  ∀ s sk2,
    let pk2 := toPublicKey sk2;
    (deriveSecret sk pk2 s).1 = (deriveSecret sk2 pk s).1

theorem generate_ok : SatisfiesM (fun (pk, sk) => KeyPair pk sk) generate := by
  unfold SatisfiesM
  -- Introduce state s
  intro s
  -- Simplify the goal using generate definition
  simp only [generate, KeyPair]
  -- Destructure the result of nikeSpec.generate
  let ⟨⟨pk, sk, h⟩, s'⟩ := nikeSpec.generate s
  -- Provide the key pair (pk, sk)
  use (pk, sk)
  -- Simplify goal to show KeyPair holds
  simp only
  -- Exact the proof h which is exactly the KeyPair condition
  exact h

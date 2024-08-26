import Batteries.Classes.SatisfiesM

/- KEM spec written initially by Mario Carneiro -/

structure KEMSpec where
  State : Type
  PublicKey : Type
  PrivateKey : Type
  Ciphertext : Type
  Plaintext : Type
  decap : PrivateKey → Ciphertext → StateM State Plaintext
  encap : PublicKey → StateM State (Ciphertext × Plaintext)
  init : State
  generate : StateM State (Σ' (pk : PublicKey), {sk : PrivateKey //
    ∀ s, let (c, k) := (encap pk s).1; ∀ s, (decap sk c s).1 = k})
  [plaintextEq : DecidableEq Plaintext]

instance : Inhabited KEMSpec := ⟨{
  State := Unit
  PublicKey := Unit
  PrivateKey := Unit
  Ciphertext := Unit
  Plaintext := Unit
  decap := fun _ _ => pure ()
  encap := fun _ => pure ((), ())
  init := ()
  generate := pure ⟨(), (), fun () () => rfl⟩
  plaintextEq := inferInstance
}⟩

opaque kemSpec : KEMSpec

instance : Inhabited kemSpec.State := ⟨kemSpec.init⟩

abbrev KEMM := StateM kemSpec.State

def PublicKey : Type := kemSpec.PublicKey
instance : Inhabited PublicKey := ⟨(kemSpec.generate default).1.1⟩

def PrivateKey : Type := kemSpec.PrivateKey
instance : Inhabited PrivateKey := ⟨(kemSpec.generate default).1.2.1⟩

def Ciphertext : Type := kemSpec.Ciphertext
instance : Inhabited Ciphertext :=
  ⟨(kemSpec.encap (kemSpec.generate default).1.1 default).1.1⟩

def Plaintext : Type := kemSpec.Plaintext
instance : Inhabited Plaintext :=
  ⟨(kemSpec.encap (kemSpec.generate default).1.1 default).1.2⟩

def generate : KEMM (PublicKey × PrivateKey) := fun s =>
  let (⟨pk, sk, _⟩, s) := kemSpec.generate s
  ((pk, sk), s)

def encap : PublicKey → KEMM (Ciphertext × Plaintext) := kemSpec.encap

def decap : PrivateKey → Ciphertext → KEMM Plaintext := kemSpec.decap

instance : DecidableEq Plaintext := kemSpec.plaintextEq

def IsEncapsulation (sk : PrivateKey) (c : Ciphertext) (k : Plaintext) :=
  ∀ s, (decap sk c s).1 = k

def KeyPair (pk : PublicKey) (sk : PrivateKey) :=
  ∀ s, let (c, k) := (encap pk s).1; IsEncapsulation sk c k

theorem generate_ok : SatisfiesM (fun (pk, sk) => KeyPair pk sk) generate := by
  simp [generate]; intro s; split; rename_i h1 s1 _; exact h1

theorem encap_ok {pk sk} (h : KeyPair pk sk) :
    SatisfiesM (fun (c, k) => IsEncapsulation sk c k) (encap pk) := by simpa using h

theorem decap_ok {sk c k} (h : IsEncapsulation sk c k) :
    SatisfiesM (fun k' => k' = k) (decap sk c) := by simpa using h

import Std.Tactic.Do

open Std.Do

namespace CryptWalker.KEM.KEM

inductive KEMError where
  | badCiphertext
  | unsafePublicKey
deriving DecidableEq


structure KEM where
  State : Type
  PublicKey : Type
  PrivateKey : Type
  Ciphertext : Type
  Plaintext : Type
  [pubI  : Inhabited PublicKey]
  [privI : Inhabited PrivateKey]
  [ctI   : Inhabited Ciphertext]
  [ptI   : Inhabited Plaintext]
  /-- Inhabitance witness only; never run a scheme against `stateI.default`. -/
  [stateI : Inhabited State]

  publicKeySize  : Nat
  privateKeySize : Nat
  ciphertextSize : Nat
  plaintextSize  : Nat

  encodePublicKey  : PublicKey  → Vector UInt8 publicKeySize
  decodePublicKey  : Vector UInt8 publicKeySize  → Option PublicKey
  encodePrivateKey : PrivateKey → Vector UInt8 privateKeySize
  decodePrivateKey : Vector UInt8 privateKeySize → Option PrivateKey
  encodeCiphertext : Ciphertext → Vector UInt8 ciphertextSize
  decodeCiphertext : Vector UInt8 ciphertextSize → Option Ciphertext
  encodePlaintext  : Plaintext  → Vector UInt8 plaintextSize

  decap : PrivateKey → Ciphertext → EStateM KEMError State Plaintext
  encap : PublicKey → EStateM KEMError State (Ciphertext × Plaintext)

  /-- Pre-encapsulation states that cannot cause a decryption failure. `True` for a perfectly
  correct KEM; a lattice KEM restricts it to states whose sampled noise stays within bounds. -/
  Reliable : State → Prop := fun _ => True

  generate : EStateM KEMError State (Σ' (pk : PublicKey), {sk : PrivateKey //
    ∀ s, Reliable s → ∀ c k s', encap pk s = .ok (c, k) s' → ∀ t, ∃ t', decap sk c t = .ok k t'})

  /-- Deterministic state from a 32-byte seed. -/
  stateFromSeed : Vector UInt8 32 → State

  derivePublicKey : PrivateKey → PublicKey

  /-- Round trip for any private key and its derived public key, from a `Reliable` state. -/
  honestRoundTrip : ∀ sk, ∀ s, Reliable s → ∀ c k s', encap (derivePublicKey sk) s = .ok (c, k) s' →
    ∀ t, ∃ t', decap sk c t = .ok k t'

  /-- Every byte string of the right width decodes to a private key. -/
  decodePrivateKey_total : ∀ b, ∃ sk, decodePrivateKey b = some sk

  decode_encode_pub  : ∀ pk, decodePublicKey  (encodePublicKey  pk) = some pk
  decode_encode_priv : ∀ sk, decodePrivateKey (encodePrivateKey sk) = some sk
  decode_encode_ct   : ∀ c,  decodeCiphertext (encodeCiphertext c)  = some c

  [plaintextEq : DecidableEq Plaintext]


instance : Inhabited KEM := ⟨{
  State := Unit
  PublicKey := Unit
  PrivateKey := Unit
  Ciphertext := Unit
  Plaintext := Unit

  publicKeySize  := 0
  privateKeySize := 0
  ciphertextSize := 0
  plaintextSize  := 0

  encodePublicKey  := fun _ => #v[]
  decodePublicKey  := fun _ => some ()
  encodePrivateKey := fun _ => #v[]
  decodePrivateKey := fun _ => some ()
  encodeCiphertext := fun _ => #v[]
  decodeCiphertext := fun _ => some ()
  encodePlaintext  := fun _ => #v[]

  decap := fun _ _ => pure ()
  encap := fun _ => pure ((), ())
  generate := pure ⟨(), (), fun _ _ _ _ _ _ t => ⟨t, rfl⟩⟩
  stateFromSeed := fun _ => ()
  derivePublicKey := fun _ => ()
  honestRoundTrip := fun _ _ _ _ _ _ _ t => ⟨t, rfl⟩
  decodePrivateKey_total := fun _ => ⟨(), rfl⟩

  decode_encode_pub  := fun _ => rfl
  decode_encode_priv := fun _ => rfl
  decode_encode_ct   := fun _ => rfl

  plaintextEq := inferInstance
}⟩

section Spec

variable (kemSpec : KEM)

instance : Inhabited kemSpec.State := kemSpec.stateI

abbrev KEMM := EStateM KEMError kemSpec.State

abbrev PublicKey : Type := kemSpec.PublicKey
instance : Inhabited (PublicKey kemSpec) := kemSpec.pubI

abbrev PrivateKey : Type := kemSpec.PrivateKey
instance : Inhabited (PrivateKey kemSpec) := kemSpec.privI

abbrev Ciphertext : Type := kemSpec.Ciphertext
instance : Inhabited (Ciphertext kemSpec) := kemSpec.ctI

abbrev Plaintext : Type := kemSpec.Plaintext
instance : Inhabited (Plaintext kemSpec) := kemSpec.ptI

instance : DecidableEq (Plaintext kemSpec) := kemSpec.plaintextEq

def generate : KEMM kemSpec (PublicKey kemSpec × PrivateKey kemSpec) := do
  let ⟨pk, sk, _⟩ ← kemSpec.generate
  pure (pk, sk)

def encap : PublicKey kemSpec → KEMM kemSpec (Ciphertext kemSpec × Plaintext kemSpec) :=
  kemSpec.encap

def decap : PrivateKey kemSpec → Ciphertext kemSpec → KEMM kemSpec (Plaintext kemSpec) :=
  kemSpec.decap

def IsEncapsulation (sk : PrivateKey kemSpec) (c : Ciphertext kemSpec) (k : Plaintext kemSpec) :=
  ∀ t, ∃ t', decap kemSpec sk c t = .ok k t'

def KeyPair (pk : PublicKey kemSpec) (sk : PrivateKey kemSpec) :=
  ∀ s, kemSpec.Reliable s → ∀ c k s', encap kemSpec pk s = .ok (c, k) s' →
    IsEncapsulation kemSpec sk c k

/-- Partial-correctness triple: if `x` returns, its result satisfies `p`. -/
theorem EStateM_triple_ok {ε σ α} {p : α → Prop} {x : EStateM ε σ α}
    (h : ∀ t a t', x t = .ok a t' → p a) :
    ⦃⌜True⌝⦄ x ⦃post⟨fun a => ⌜p a⌝, fun _ => ⌜True⌝⟩⦄ := by
  intro t _
  simp only [WP.wp, PredTrans.apply, EStateM.run]
  cases hx : x t with
  | ok a t'    => exact h t a t' hx
  | error e t' => trivial

/-- Total-correctness triple: `x` always returns a result satisfying `p`. -/
theorem EStateM_triple {ε σ α} {p : α → Prop} {x : EStateM ε σ α}
    (h : ∀ t, ∃ a t', x t = .ok a t' ∧ p a) :
    ⦃⌜True⌝⦄ x ⦃post⟨fun a => ⌜p a⌝, fun _ => ⌜False⌝⟩⦄ := by
  intro t _
  obtain ⟨a, t', ht, hp⟩ := h t
  simp only [WP.wp, PredTrans.apply, EStateM.run, ht]
  exact hp

/-- Whatever `generate` returns is a valid key pair. -/
theorem generate_keyPair {t r t'} (hr : generate kemSpec t = .ok r t') :
    KeyPair kemSpec r.1 r.2 := by
  simp only [generate, bind, EStateM.bind] at hr
  split at hr
  · rename_i a _ _
    simp only [pure, EStateM.pure, EStateM.Result.ok.injEq] at hr
    obtain ⟨rfl, -⟩ := hr
    exact a.2.property
  · exact absurd hr (by simp)

@[spec] theorem generate_ok :
    ⦃⌜True⌝⦄ generate kemSpec
    ⦃post⟨fun (pk, sk) => ⌜KeyPair kemSpec pk sk⌝, fun _ => ⌜True⌝⟩⦄ :=
  EStateM_triple_ok fun _ _ _ hr => generate_keyPair kemSpec hr

/-- Encapsulation from a `Reliable` state to a valid key pair decapsulates correctly. Stated as a
plain proposition because the precondition constrains the starting state. -/
theorem encap_ok {pk sk} (h : KeyPair kemSpec pk sk) (t : kemSpec.State)
    (hrel : kemSpec.Reliable t) :
    ∀ r t', encap kemSpec pk t = .ok r t' → IsEncapsulation kemSpec sk r.1 r.2 :=
  fun r t' hr => h t hrel r.1 r.2 t' hr

@[spec] theorem decap_ok {sk ct k} (h : IsEncapsulation kemSpec sk ct k) :
    ⦃⌜True⌝⦄ decap kemSpec sk ct ⦃post⟨fun k' => ⌜k' = k⌝, fun _ => ⌜False⌝⟩⦄ :=
  EStateM_triple fun t => let ⟨t', ht⟩ := h t; ⟨k, t', ht, rfl⟩

end Spec

end CryptWalker.KEM.KEM

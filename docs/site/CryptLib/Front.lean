import VersoBlog
open Verso Genre Blog

#doc (Page) "Cryptlib" =>

```leanInit demo
```

```lean demo -show
inductive KEMError where
  | badCiphertext
  | unsafePublicKey
```

# Abstract

Cryptlib started off as a Lean model of [hpqc](https://github.com/katzenpost/hpqc/) (hybrid
post-quantum cryptography), a Go, Python and Rust cryptography library used by the
[Katzenpost](https://katzenpost.network/) post-quantum decryption mix network.

Beyond that we have two main goals:

* Cryptlib can be used to write real, high-assurance cryptography applications in Lean.
* Cryptlib can be used to prove security properties of cryptographic primitives and protocols.

For each kind of cryptographic primitive, such as a NIKE (non-interactive key exchange), Cryptlib
defines a Lean structure type that describes the primitive generically. In a language like Rust a
trait is an empty husk that only declares function signatures. Cryptlib uses a structure instead,
where some fields hold functions and others hold data types. So far this is how Rust or Go would
represent a primitive generically. Lean lets us go a step further with dependent types: a field can
also be a proposition. For example, our NIKE structure has a field stating that the group operation
is commutative:

```lean demo
structure NIKE where
  PrivateKey   : Type
  PublicKey    : Type
  SharedSecret : Type
  -- ...
  Safe : PublicKey → Prop
  derivePublicKey : PrivateKey → PublicKey
  groupAction : PrivateKey → {pk : PublicKey // Safe pk} → SharedSecret
  -- ...
  derive_safe : ∀ sk, Safe (derivePublicKey sk)
  -- ...
  commutes : ∀ sk₁ sk₂,
    groupAction sk₁ ⟨derivePublicKey sk₂, derive_safe sk₂⟩
      = groupAction sk₂ ⟨derivePublicKey sk₁, derive_safe sk₁⟩
```

:::htmlDiv (class := "caption")
Abridged from [`Cryptlib/Primitives/NIKE/NIKE.lean`](https://github.com/katzenpost/cryptlib/blob/2165380e906475ac966b72c272c527c93ef2b15b/Cryptlib/Primitives/NIKE/NIKE.lean#L12-L73)
:::

Each category of cryptographic primitive in Cryptlib has a structure type like this one, defining
its functions and data types together with propositions about the primitive. Our generic definition
of a KEM (key encapsulation mechanism) is another example:

```lean demo
structure KEM where
  State      : Type
  PublicKey  : Type
  PrivateKey : Type
  Ciphertext : Type
  Plaintext  : Type
  -- ...
  decap : PrivateKey → Ciphertext → EStateM KEMError State Plaintext
  encap : PublicKey → EStateM KEMError State (Ciphertext × Plaintext)

  /-- Pre-encapsulation states that cannot cause a decryption failure. `True` for a perfectly
  correct KEM; a lattice KEM restricts it to states whose sampled noise stays within bounds. -/
  Reliable : State → Prop := fun _ => True
  -- ...
  derivePublicKey : PrivateKey → PublicKey

  /-- Round trip for any private key and its derived public key, from a `Reliable` state. -/
  honestRoundTrip : ∀ sk, ∀ s, Reliable s → ∀ c k s', encap (derivePublicKey sk) s = .ok (c, k) s' →
    ∀ t, ∃ t', decap sk c t = .ok k t'
```

:::htmlDiv (class := "caption")
Abridged from [`Cryptlib/Primitives/KEM/KEM.lean`](https://github.com/katzenpost/cryptlib/blob/2165380e906475ac966b72c272c527c93ef2b15b/Cryptlib/Primitives/KEM/KEM.lean#L13-L65)
:::

A cryptography library that uses dependent types to add these proof obligations has some obvious
and some less obvious benefits. The obvious one is that every instance of these types meets at
least a basic bar of quality: it satisfies the type's proposition fields. A less obvious advantage
is that when we compose these types, the resulting definitions carry fewer transitive proof
obligations overall.

For example, we define a NIKE-to-KEM adapter, which is a hashed ElGamal construction. In Lean we
could write a theorem saying the adapter produces a lawful KEM whenever it is given a lawful NIKE.
But with dependent types for the NIKE and KEM definitions there is no need to write that theorem at
all, because it is impossible to construct an instance that violates its type's proposition fields.
See our [NIKE-to-KEM adapter](https://github.com/katzenpost/cryptlib/blob/2165380e906475ac966b72c272c527c93ef2b15b/Cryptlib/Primitives/KEM/Adapter.lean#L119-L161).

This is an example of dependent types enforcing a proof implicitly, and they keep doing so
transitively as primitives are composed. In many ways this simplifies the proof obligations of the
composed protocol.

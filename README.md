# Crypt Walker

*A cryptographic library for Lean.*


The hope is that this Lean library will allow you to
write a cryptographic protocol prototype or model.
Then you can write theorems and proofs about your model!


## cryptographic primitives

| NIKE: Non-Interactive Key Exchange |
|:---:|

Classical NIKEs:
* X25519 (constant time Montgomery Ladder)
* work-in-progress: X448
* work-in-progres: X41417

| KEM: Key Encapsulation Method |
|:---:|

Classical NIKEs adapted to KEM via hashed ElGamal construction:
* X25519

| SIGN: Cryptographic Signature Scheme |
|:---:|
* work-in-progress: ed25519

| PRF: Pseuodo Random Function |
|:---:|
* SHA256
* work-in-progress: SHA512

| DATAstructures |
|:---:|
* Binary Merkle Hash Tree polymorphic over the hash function


## developer notes

*building*

```bash
lake build
```

*testing*

```bash
lake env lean --run CryptWalker/Data/test.lean
lake env lean --run CryptWalker/NIKE/test.lean
lake env lean --run CryptWalker/KEM/test.lean
lake env lean --run ./CryptWalker/Hash/test.lean
```

*benchmarks*

```bash
lake env lean --run CryptWalker/NIKE/benchmark.lean
count: 1000 elapsed: 2765066159.000000 ns average 2765066.159000 ns
```

## licensing

AGPLv3


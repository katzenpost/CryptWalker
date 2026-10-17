import VersoBlog
open Verso Genre Blog

#doc (Page) "Getting started" =>

# Build

Cryptlib builds with Lake, using the toolchain pinned in `lean-toolchain`:

```
git clone https://github.com/katzenpost/cryptlib
cd Cryptlib
lake exe cache get   # fetch prebuilt Mathlib
lake build
```

# Use it as a dependency

```
[[require]]
name = "Cryptlib"
git = "https://github.com/katzenpost/cryptlib"
rev = "main"
```

# Test

```
make test   # build everything and run every suite
make help   # list every target, including one per suite
```

The suites read their known-answer vectors from `testdata/` by relative path, so run them from the
repository root.

# Benchmark

```
make bench                                         # every NIKE, KEM and Sphinx benchmark
make bench-kem                                     # one suite
make bench BENCH_ARGS='--match "kem MLKEM768 decap"'
```

---
title: Getting started
weight: 30
description: Build CryptWalker, run its test suites and benchmarks.
---

## Build

CryptWalker builds with Lake, using the toolchain pinned in `lean-toolchain`:

```bash
git clone https://github.com/katzenpost/CryptWalker
cd CryptWalker
lake exe cache get   # fetch prebuilt Mathlib
lake build
```

## Use it as a dependency

```toml
[[require]]
name = "CryptWalker"
git = "https://github.com/katzenpost/CryptWalker"
rev = "main"
```

## Test

```bash
make test   # build everything and run every suite
make help   # list every target, including one per suite
```

The suites read their known-answer vectors from `testdata/` by relative path, so run them from
the repository root.

## Benchmark

```bash
make bench                                         # every NIKE, KEM and Sphinx benchmark
make bench-kem                                     # one suite
make bench BENCH_ARGS='--match "kem MLKEM768 decap"'
```

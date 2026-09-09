# CryptWalker
#
# Lake does the building; this file collects the things one actually wants to run.
# Every target must run from the repository root: the suites load their vectors
# from testdata/ and CryptWalker/testdata/ by relative path.

SHELL := /bin/bash
LAKE  ?= lake
BIN   := .lake/build/bin

# Test executables, as declared in lakefile.toml. Lake names each binary after
# its module with the dots turned into dashes.
TESTS := \
	CryptWalker.Data.test \
	CryptWalker.NIKE.test \
	CryptWalker.KEM.test \
	CryptWalker.KEM.vectors \
	CryptWalker.Hash.test \
	CryptWalker.Hash.hkdf_test \
	CryptWalker.Hash.hkdf_structured_test \
	CryptWalker.Cipher.test \
	CryptWalker.Sign.test \
	CryptWalker.Sign.blinded_test \
	CryptWalker.BACAP.test \
	CryptWalker.Sphinx.Crypto.test \
	CryptWalker.Sphinx.Crypto.aez_test

TEST_BINS := $(foreach t,$(TESTS),$(BIN)/$(subst .,-,$(t)))

# Bare `lake build` builds only defaultTargets, which is the library. The
# executables have to be named or the test targets run whatever binary was left
# in .lake/build/bin by an earlier build.
EXES := $(TESTS) CryptWalker.NIKE.benchmark

.DEFAULT_GOAL := help

.PHONY: all build test bench sorries clean help
.PHONY: test-data test-nike test-kem test-kem-vectors test-hash test-hkdf
.PHONY: test-hkdf-structured test-cipher test-sign test-blinded test-bacap test-sphinx-crypto

all: build ## build everything, library and executables

build: ## build everything, library and executables
	$(LAKE) build CryptWalker $(EXES)

# A suite counts as failed if it exits non-zero or prints anything matching
# "fail". Most suites signal a mismatch by throwing, which exits 1, but
# CryptWalker/Data/test.lean only prints on mismatch and still exits 0. No
# passing suite prints the word, so scanning for it costs nothing and catches
# that case along with any future suite that reports the same way.
test: build ## run every suite and report all failures
	@rc=0; \
	for bin in $(TEST_BINS); do \
	  name=$$(basename $$bin); \
	  printf '\n=== %s ===\n' "$$name"; \
	  out=$$("$$bin" 2>&1); status=$$?; \
	  printf '%s\n' "$$out"; \
	  if [ $$status -ne 0 ] || printf '%s' "$$out" | grep -qi 'fail'; then \
	    rc=1; printf '  ^^ %s FAILED\n' "$$name"; \
	  fi; \
	done; \
	printf '\n'; \
	if [ $$rc -ne 0 ]; then echo "some suites failed"; else echo "all suites passed"; fi; \
	exit $$rc

test-data: build ## Merkle hash tree
	@$(BIN)/CryptWalker-Data-test

test-nike: build ## X25519 NIKE
	@$(BIN)/CryptWalker-NIKE-test

test-kem: build ## KEM round trips
	@$(BIN)/CryptWalker-KEM-test

test-kem-vectors: build ## NIKE-to-KEM adapter vectors from hpqc
	@$(BIN)/CryptWalker-KEM-vectors

test-hash: build ## SHA-512 vectors from hpqc
	@$(BIN)/CryptWalker-Hash-test

test-hkdf: build ## HKDF-BLAKE2b raw function vectors
	@$(BIN)/CryptWalker-Hash-hkdf_test

test-hkdf-structured: build ## HKDF structured instance vectors
	@$(BIN)/CryptWalker-Hash-hkdf_structured_test

test-cipher: build ## AES-256-GCM-SIV vectors from hpqc
	@$(BIN)/CryptWalker-Cipher-test

test-sign: build ## Ed25519 RFC 8032 vectors
	@$(BIN)/CryptWalker-Sign-test

test-blinded: build ## blinded Ed25519 vectors from hpqc
	@$(BIN)/CryptWalker-Sign-blinded_test

test-bacap: build ## BACAP vectors from hpqc
	@$(BIN)/CryptWalker-BACAP-test

test-sphinx-crypto: build ## Sphinx primitive-layer vectors (hash/MAC/stream/KDF) from katzenpost
	@$(BIN)/CryptWalker-Sphinx-Crypto-test

bench: build ## run the NIKE benchmarks
	@$(BIN)/CryptWalker-NIKE-benchmark

sorries: ## list every declaration still standing on sorry
	@$(LAKE) build 2>&1 | grep 'declaration uses' | sort -u || echo "no sorries"

clean: ## remove all build artefacts
	$(LAKE) clean

help: ## list the targets
	@grep -hE '^[a-z-]+:.*##' $(MAKEFILE_LIST) \
	  | sed -E 's/:.*## / /' \
	  | awk '{ printf "  \033[36m%-22s\033[0m %s\n", $$1, substr($$0, index($$0, " ") + 1) }'

# Cryptlib
#
# Lake does the building; this file collects the things one actually wants to run.
# Every target must run from the repository root: the suites load their vectors
# from testdata/ and Cryptlib/testdata/ by relative path.

SHELL := /bin/bash
LAKE  ?= lake
BIN   := .lake/build/bin

# Test executables, as declared in lakefile.toml. Lake names each binary after
# its module with the dots turned into dashes.
TESTS := \
	Cryptlib.Data.test \
	Cryptlib.Primitives.NIKE.test \
	Cryptlib.Primitives.KEM.test \
	Cryptlib.Primitives.KEM.vectors \
	Cryptlib.Primitives.Hash.test \
	Cryptlib.Primitives.Hash.hkdf_test \
	Cryptlib.Primitives.MAC.hmac_hkdf_test \
	Cryptlib.Primitives.Hash.blake2s_test \
	Cryptlib.Primitives.KDF.argon2_test \
	Cryptlib.Primitives.Cipher.aead_vectors_test \
	Cryptlib.Primitives.Hash.hkdf_structured_test \
	Cryptlib.Primitives.Cipher.test \
	Cryptlib.Primitives.Sign.test \
	Cryptlib.Primitives.Sign.blinded_test \
	Cryptlib.Protocols.BACAP.test \
	Cryptlib.Protocols.Sphinx.crypto_test \
	Cryptlib.Primitives.WideBlockCipher.test \
	Cryptlib.Protocols.Sphinx.commands_test \
	Cryptlib.Protocols.Sphinx.geometry_test \
	Cryptlib.Protocols.Sphinx.nike_selftest \
	Cryptlib.Protocols.Sphinx.kem_selftest \
	Cryptlib.Protocols.Sphinx.nike_vectors_test \
	Cryptlib.Protocols.Sphinx.kem_vectors_test \
	Cryptlib.Primitives.KEM.MLKEM.mlkem_test \
	Cryptlib.Primitives.Hash.blake2b_256_test \
	Cryptlib.Primitives.Hash.blake2b_xof_test \
	Cryptlib.Primitives.KEM.mlkem768_x25519_combiner_test \
	Cryptlib.Primitives.KEM.MLKEMHedged.mlkemhedged_test \
	Cryptlib.Primitives.KEM.mlkem_hedged_test \
	Cryptlib.Primitives.MultiRecipientHybrid.multirecipient_hybrid_test \
	Cryptlib.Protocols.Sphinx.kem_hybrid_vectors_test \
	Cryptlib.Protocols.Sphinx.kem_hybrid_blake2bxof_vectors_test \
	Cryptlib.Protocols.BACAP.primitive_vectors_test \
	Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.ack_codec_test \
	Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.wire_vectors_test \
	Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.replay \
	Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.scenarios

TEST_BINS := $(foreach t,$(TESTS),$(BIN)/$(subst .,-,$(t)))

# Bare `lake build` builds only defaultTargets, which is the library. The
# executables have to be named or the test targets run whatever binary was left
# in .lake/build/bin by an earlier build.
EXES := $(TESTS) Cryptlib.Protocols.BACAP.gen_vectors Cryptlib.Bench.benchmark Cryptlib.Protocols.Sphinx.gen_nike_vectors Cryptlib.Protocols.Sphinx.gen_kem_vectors Cryptlib.Primitives.KEM.gen_mlkem768_x25519_combiner_vectors Cryptlib.Primitives.KEM.gen_mlkem_hedged_vectors Cryptlib.Primitives.MultiRecipientHybrid.gen_multirecipient_hybrid_vectors

.DEFAULT_GOAL := help

.PHONY: all build test bench bench-nike bench-kem bench-sphinx sorries clean help
.PHONY: test-data test-nike test-kem test-kem-vectors test-hash test-hkdf test-argon2
.PHONY: test-hkdf-structured test-cipher test-sign test-blinded test-bacap test-sphinx-crypto
.PHONY: gen-sphinx-vectors gen-hybrid-vectors gen-hedged-vectors gen-mrhybrid-vectors test-mrhybrid test-mlkem test-mlkem-kat test-mlkem-hedged test-hybrid-sphinx
.PHONY: verify-vectors gen-acks-vectors gen-groupchat-wire-vectors check-bacap-vectors axioms tla veil
.PHONY: api-docs website website-pages website-serve mathlib-cache

all: build ## build everything, library and executables

# Prebuilt Mathlib. `lake clean` deletes it along with every other package's
# build directory, and rebuilding it from source takes hours.
mathlib-cache: ## download prebuilt Mathlib (fast when already present)
	$(LAKE) exe cache get

build: mathlib-cache ## build everything, library and executables
	$(LAKE) build --log-level=warning Cryptlib $(EXES)

# A suite counts as failed if it exits non-zero or prints anything matching
# "fail". Most suites signal a mismatch by throwing, which exits 1, but
# Cryptlib/Data/test.lean only prints on mismatch and still exits 0. No
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
	@$(BIN)/Cryptlib-Data-test

test-nike: build ## X25519 NIKE
	@$(BIN)/Cryptlib-Primitives-NIKE-test

test-kem: build ## KEM round trips
	@$(BIN)/Cryptlib-Primitives-KEM-test

test-kem-vectors: build ## NIKE-to-KEM adapter vectors from hpqc
	@$(BIN)/Cryptlib-Primitives-KEM-vectors

test-hash: build ## SHA-512 vectors from hpqc
	@$(BIN)/Cryptlib-Primitives-Hash-test

test-hkdf: build ## HKDF-BLAKE2b raw function vectors
	@$(BIN)/Cryptlib-Primitives-Hash-hkdf_test

test-argon2: build ## Argon2d/i/id vectors from RFC 9106 and x/crypto/argon2
	@$(BIN)/Cryptlib-Primitives-KDF-argon2_test

test-hkdf-structured: build ## HKDF structured instance vectors
	@$(BIN)/Cryptlib-Primitives-Hash-hkdf_structured_test

test-cipher: build ## AES-256-GCM-SIV vectors from hpqc
	@$(BIN)/Cryptlib-Primitives-Cipher-test

test-sign: build ## Ed25519 RFC 8032 vectors
	@$(BIN)/Cryptlib-Primitives-Sign-test

test-blinded: build ## blinded Ed25519 vectors from hpqc
	@$(BIN)/Cryptlib-Primitives-Sign-blinded_test

test-bacap: build ## BACAP vectors from hpqc
	@$(BIN)/Cryptlib-Protocols-BACAP-test

test-sphinx-crypto: build ## Sphinx primitive-layer vectors (hash/MAC/stream/KDF) from katzenpost
	@$(BIN)/Cryptlib-Protocols-Sphinx-crypto_test

gen-sphinx-vectors: build ## build Sphinx packets with the Lean port, for cross-checking against katzenpost's Unwrap
	@$(BIN)/Cryptlib-Protocols-Sphinx-gen_nike_vectors
	@$(BIN)/Cryptlib-Protocols-Sphinx-gen_kem_vectors

gen-hybrid-vectors: build ## build X25519+ML-KEM-768 combiner vectors, for cross-checking against hpqc
	@$(BIN)/Cryptlib-Primitives-KEM-gen_mlkem768_x25519_combiner_vectors

gen-hedged-vectors: build ## build hedged ML-KEM-512/768/1024 vectors, for cross-checking against hpqc
	@$(BIN)/Cryptlib-Primitives-KEM-gen_mlkem_hedged_vectors

gen-mrhybrid-vectors: build ## build multi-recipient hybrid vectors, for cross-checking against hpqc
	@$(BIN)/Cryptlib-Primitives-MultiRecipientHybrid-gen_multirecipient_hybrid_vectors

# Override with `make verify-vectors HPQC_DIR=... KATZENPOST_DIR=...` if the sibling repos aren't
# checked out at ../hpqc, ../katzenpost.
HPQC_DIR ?= ../hpqc
KATZENPOST_DIR ?= ../katzenpost
KATZENQT_DIR ?= ../katzenqt

gen-acks-vectors: ## regenerate testdata/acks_vectors.json from katzenqt's Python Acks codec
	@python3 -I scripts/gen_acks_vectors.py "$(KATZENQT_DIR)" > testdata/acks_vectors.json
	@sha256sum testdata/acks_vectors.json > testdata/acks_vectors.json.sha256

# katzenqt's models need its dependencies, so this runs with katzenqt's own Python.
KATZENQT_PYTHON ?= $(KATZENQT_DIR)/.venv/bin/python

gen-groupchat-wire-vectors: ## regenerate testdata/groupchat_wire_vectors.json from katzenqt's message codec
	@$(KATZENQT_PYTHON) -I scripts/gen_groupchat_wire_vectors.py "$(KATZENQT_DIR)" > testdata/groupchat_wire_vectors.json
	@sha256sum testdata/groupchat_wire_vectors.json > testdata/groupchat_wire_vectors.json.sha256

check-bacap-vectors: build ## generate hpqc's BACAP vectors with the Lean implementation and compare
	@$(BIN)/Cryptlib-Protocols-BACAP-gen_vectors --check
	@$(BIN)/Cryptlib-Protocols-BACAP-test

verify-vectors: ## sha256sum-compare vendored testdata/ files against their hpqc/katzenpost/katzenqt source copies
	@./scripts/verify-vectors.sh "$(HPQC_DIR)" "$(KATZENPOST_DIR)" "$(KATZENQT_DIR)"

axioms: build ## fail if a group chat theorem rests on sorry, native_decide or a declared axiom
	@./scripts/check-axioms.sh

tla: ## model-check every GroupChat/tla protocol and impl config against its EXPECT line (needs java and tla2tools.jar)
	@./Cryptlib/Protocols/GroupComm/GroupChatKatzenqt1/tla/check.sh

veil: ## prove and model-check the GroupChat/veil Backfill model (its own Lake project, needs npm)
	@cd Cryptlib/Protocols/GroupComm/GroupChatKatzenqt1/veil && $(LAKE) build

test-mlkem: build ## ML-KEM-768: round-trip self-test + NIST ACVP known-answer vectors
	@$(BIN)/Cryptlib-Protocols-Sphinx-kem_selftest
	@$(BIN)/Cryptlib-Primitives-KEM-MLKEM-mlkem_test

test-mlkem-kat: build ## ML-KEM-768: NIST ACVP known-answer vectors only
	@$(BIN)/Cryptlib-Primitives-KEM-MLKEM-mlkem_test

test-mlkem-hedged: build ## hedged ML-KEM-512/768/1024: NIST ACVP vectors + hpqc cross-check vectors
	@$(BIN)/Cryptlib-Primitives-KEM-MLKEMHedged-mlkemhedged_test
	@$(BIN)/Cryptlib-Primitives-KEM-mlkem_hedged_test

test-mrhybrid: build ## multi-recipient hybrid: hpqc cross-check vectors
	@$(BIN)/Cryptlib-Primitives-MultiRecipientHybrid-multirecipient_hybrid_test

test-hybrid-sphinx: build ## KEM-Sphinx round-trip self-test for the X25519+ML-KEM-768 hybrid only
	@$(BIN)/Cryptlib-Protocols-Sphinx-kem_selftest MLKEM768X25519

# Extra LeanBench flags, e.g. `make bench BENCH_ARGS='--match "unwrap MLKEM768" --samples 5'`.
BENCH_ARGS ?=

# Quiet: otherwise Lake replays LeanBench's missing-docstring warnings and VCVio's native-backend
# notices on every run.
BENCH := $(LAKE) -q --log-level=error exe Cryptlib.Bench.benchmark

bench: ## run every benchmark (NIKE, KEM, Sphinx); pass LeanBench flags via BENCH_ARGS
	@$(BENCH) $(BENCH_ARGS)

bench-nike: ## benchmark every registered NIKE
	@$(BENCH) --suite nike $(BENCH_ARGS)

bench-kem: ## benchmark every registered KEM (generate/encap/decap)
	@$(BENCH) --suite kem $(BENCH_ARGS)

bench-sphinx: ## benchmark Sphinx packet creation and unwrap for every scheme
	@$(BENCH) --suite sphinx $(BENCH_ARGS)

sorries: ## list every declaration still standing on sorry
	@$(LAKE) build 2>&1 | grep 'declaration uses' | sort -u || echo "no sorries"

# The website: Verso pages from docs/site plus the doc-gen4 API reference.
# gen-api.py documents Cryptlib's modules and Lean's core libraries;
# prune-api.py keeps only our pages and links core to its hosted docs.
API_DOCS := docs/_api
SITE_OUT := docs/public
SERVE_PORT ?= 8000

# doc-gen4 jobs run at once; each loads Lean plus the imported part of Mathlib.
DOCS_JOBS ?= $(shell awk '/MemTotal/ { j = int($$2 / 3000000); print (j < 1) ? 1 : j }' /proc/meminfo 2>/dev/null || echo 2)

api-docs: mathlib-cache ## generate the API reference with doc-gen4 into docs/_api (DOCS_JOBS caps parallelism)
	python3 -I docs/scripts/gen-api.py . $(DOCS_JOBS)
	rm -rf $(API_DOCS)
	cp -r docs/docbuild/.lake/apidocs/doc $(API_DOCS)
	python3 -I docs/scripts/prune-api.py $(API_DOCS)

website-pages: ## render the Verso pages into docs/public, keeping any API docs already there
	cd docs/site && $(LAKE) exe cryptlib --output ../public

website: api-docs website-pages ## build the whole website, API reference included, into docs/public
	rm -rf $(SITE_OUT)/api
	cp -r $(API_DOCS) $(SITE_OUT)/api

website-serve: website-pages ## serve docs/public on 127.0.0.1:$(SERVE_PORT) (run make website once for /api/)
	python3 -m http.server --bind 127.0.0.1 -d $(SITE_OUT) $(SERVE_PORT)

clean: ## remove all build artefacts
	$(LAKE) clean

help: ## list the targets
	@grep -hE '^[a-z-]+:.*##' $(MAKEFILE_LIST) \
	  | sed -E 's/:.*## / /' \
	  | awk '{ printf "  \033[36m%-22s\033[0m %s\n", $$1, substr($$0, index($$0, " ") + 1) }'

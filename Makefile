CARGO ?= cargo
BINARY_NAME = symfritz
RUST_BINARY = target/debug/symfritz

.PHONY: all
all: build test

.PHONY: build
build:
	$(CARGO) build -p symfritz-cli --bin symfritz --locked
	cp $(RUST_BINARY) $(BINARY_NAME)

.PHONY: build-version
build-version:
	SYMFRITZ_VERSION=$(VERSION) $(CARGO) build -p symfritz-cli --bin symfritz --locked
	cp $(RUST_BINARY) $(BINARY_NAME)

.PHONY: test
test: rust-test

.PHONY: test-verbose
test-verbose:
	$(CARGO) test --workspace --all-features --locked -- --nocapture

.PHONY: rust-build
rust-build:
	$(CARGO) build --workspace --locked

.PHONY: rust-test
rust-test:
	$(CARGO) test --workspace --all-features --locked

.PHONY: rust-lint
rust-lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets --all-features --locked -- -D warnings

.PHONY: rust-readonly
rust-readonly:
	$(CARGO) test -p symfritz-cli --test cli_contract --locked
	$(CARGO) test -p symfritz-cli --locked
	$(CARGO) clippy -p symfritz-cli --all-targets --locked -- -D warnings

.PHONY: rust-diagnostic
rust-diagnostic:
	$(CARGO) test -p symfritz-cli --test cli_contract --locked
	$(CARGO) clippy -p symfritz-cli --all-targets --locked -- -D warnings

.PHONY: rust-mutating
rust-mutating:
	$(CARGO) test -p symfritz-cli --locked
	$(CARGO) clippy -p symfritz-cli --all-targets --locked -- -D warnings

.PHONY: rust-check
rust-check: rust-lint rust-test

.PHONY: rust-parser-properties
rust-parser-properties:
	$(CARGO) test -p symfritz-core --test property_parsers --locked
	$(CARGO) test -p symfritz-tr064 --test property_parsers --locked
	$(CARGO) test -p symfritz-mcp --test property_framing --locked

.PHONY: cli-contract
cli-contract: rust-build
	python3 scripts/cli-differential.py --binary ./$(RUST_BINARY)

.PHONY: release-manifest-test
release-manifest-test:
	python3 scripts/test_release_manifest.py

.PHONY: release-snapshot
release-snapshot:
	python3 scripts/release_snapshot.py --version "$${VERSION:-0.0.0-dev}" --out dist/snapshot

.PHONY: lint
lint: rust-lint

.PHONY: clean
clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/

.PHONY: install
install:
	$(CARGO) install --path crates/symfritz-cli --locked

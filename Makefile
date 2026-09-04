GO ?= go
CARGO ?= cargo
PYTHON ?= python3
BINARY_NAME = symfritz
RUST_BINARY = target/debug/symfritz-rust
# version is a package-level var in `main`, so inject into main.version
# (matches .goreleaser.yml). Injecting into the full import path silently no-ops.
VERSION_PKG = main

.PHONY: all
all: build test

.PHONY: build
build:
	CGO_ENABLED=0 $(GO) build -ldflags "-s -w -X main.version=dev" -o $(BINARY_NAME) ./cmd/symfritz

.PHONY: build-version
build-version:
	CGO_ENABLED=0 $(GO) build -ldflags "-s -w -X $(VERSION_PKG).version=$(VERSION)" -o $(BINARY_NAME) ./cmd/symfritz

.PHONY: test
test:
	CGO_ENABLED=0 $(GO) test ./...

.PHONY: test-verbose
test-verbose:
	CGO_ENABLED=0 $(GO) test -v ./...

.PHONY: test-race
test-race:
	$(GO) test -race ./...

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

.PHONY: rust-check
rust-check: rust-lint rust-test

.PHONY: port-fixtures
port-fixtures: build
	$(PYTHON) scripts/capture-port-fixtures.py --oracle ./$(BINARY_NAME)

.PHONY: port-parity-version
port-parity-version: build rust-build
	$(PYTHON) scripts/port-parity.py --reference ./$(BINARY_NAME) --candidate ./$(RUST_BINARY)

.PHONY: lint
lint:
	$(GO) fmt ./...
	CGO_ENABLED=0 $(GO) vet ./...

.PHONY: docs
docs:
	CGO_ENABLED=0 $(GO) run ./cmd/gen-docs

.PHONY: clean
clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/

.PHONY: install
install:
	CGO_ENABLED=0 $(GO) install -ldflags "-s -w -X $(VERSION_PKG).version=dev" ./cmd/symfritz

GO ?= go
CARGO ?= cargo
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

.PHONY: port-aha-fixtures
port-aha-fixtures:
	SYMFRITZ_UPDATE_PORT_FIXTURES=1 $(GO) test ./internal/fritz -run '^TestPortAHAFixture$$' -count=1

.PHONY: port-capabilities-core-fixtures
port-capabilities-core-fixtures:
	SYMFRITZ_UPDATE_PORT_FIXTURES=1 $(GO) test ./internal/fritz -run '^TestPortCapabilitiesCoreFixture$$' -count=1

.PHONY: port-remaining-fixtures
port-remaining-fixtures:
	SYMFRITZ_UPDATE_PORT_FIXTURES=1 $(GO) test ./internal/fritz -run '^TestPortRemainingCapabilitiesFixture$$' -count=1

.PHONY: port-cli-fixtures
port-cli-fixtures: build
	$(GO) run ./cmd/capture-cli-fixtures -oracle ./$(BINARY_NAME)

.PHONY: port-cli-parity
port-cli-parity: build rust-build
	python3 scripts/cli-differential.py --go ./$(BINARY_NAME) --rust ./$(RUST_BINARY)

.PHONY: port-fixtures
port-fixtures: build port-cli-fixtures
	$(GO) run ./cmd/capture-port-fixtures -oracle ./$(BINARY_NAME)
	SYMFRITZ_UPDATE_PORT_FIXTURES=1 $(GO) test ./internal/fritz ./internal/config ./internal/secret ./cmd/symfritz -run '^TestPort(Auth|TR064|Config|ConfigInit|Secret|Transport|SessionData|CapabilitiesCore|RemainingCapabilities)Fixture$$' -count=1
	$(MAKE) port-aha-fixtures

.PHONY: port-parity-version
port-parity-version: build rust-build
	$(GO) run ./cmd/port-parity -reference ./$(BINARY_NAME) -candidate ./$(RUST_BINARY)

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

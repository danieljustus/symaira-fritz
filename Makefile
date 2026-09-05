GO ?= go
CARGO ?= cargo
BINARY_NAME = symfritz
RUST_BINARY = target/debug/symfritz
GO_BINARY = target/debug/symfritz-go

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

.PHONY: build-go
build-go:
	mkdir -p $(dir $(GO_BINARY))
	CGO_ENABLED=0 $(GO) build -ldflags "-s -w -X main.version=dev" -o $(GO_BINARY) ./cmd/symfritz

.PHONY: test
test: rust-test go-test

.PHONY: go-test
go-test:
	CGO_ENABLED=0 $(GO) test ./...

.PHONY: test-verbose
test-verbose: rust-test go-test-verbose

.PHONY: go-test-verbose
go-test-verbose:
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

.PHONY: rust-parser-properties
rust-parser-properties:
	$(CARGO) test -p symfritz-core --test property_parsers --locked
	$(CARGO) test -p symfritz-tr064 --test property_parsers --locked
	$(CARGO) test -p symfritz-mcp --test property_framing --locked

.PHONY: release-manifest-test
release-manifest-test:
	python3 scripts/test_release_manifest.py

.PHONY: release-snapshot
release-snapshot:
	python3 scripts/release_snapshot.py --version "$${VERSION:-0.0.0-dev}" --out dist/snapshot

.PHONY: benchmark-release
benchmark-release: release-snapshot
	python3 scripts/benchmark_release.py --go dist/snapshot/.build/symfritz-go --rust target/release/symfritz --output dist/snapshot/value-gate.json

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
port-cli-fixtures: build-go
	$(GO) run ./cmd/capture-cli-fixtures -oracle ./$(GO_BINARY)

.PHONY: port-cli-parity
port-cli-parity: build-go rust-build
	python3 scripts/cli-differential.py --go ./$(GO_BINARY) --rust ./$(RUST_BINARY)

.PHONY: port-fixtures
port-fixtures: build-go port-cli-fixtures
	$(GO) run ./cmd/capture-port-fixtures -oracle ./$(GO_BINARY)
	SYMFRITZ_UPDATE_PORT_FIXTURES=1 $(GO) test ./internal/fritz ./internal/config ./internal/secret ./cmd/symfritz -run '^TestPort(Auth|TR064|Config|ConfigInit|Secret|Transport|SessionData|CapabilitiesCore|RemainingCapabilities)Fixture$$' -count=1
	$(MAKE) port-aha-fixtures

.PHONY: port-parity-version
port-parity-version: build-go rust-build
	$(GO) run ./cmd/port-parity -reference ./$(GO_BINARY) -candidate ./$(RUST_BINARY)

.PHONY: mcp-fixtures
mcp-fixtures:
	$(GO) run ./cmd/capture-mcp-fixtures -output testdata/mcp/protocol-fixtures.json

.PHONY: mcp-parity
mcp-parity: mcp-fixtures
	$(GO) build -o target/debug/mcp-go-fixture ./cmd/capture-mcp-fixtures
	$(CARGO) build -p symfritz-mcp --bin mcp-fixture-server --locked
	python3 scripts/mcp-differential.py --go target/debug/mcp-go-fixture --rust target/debug/mcp-fixture-server

.PHONY: lint
lint: rust-lint go-lint

.PHONY: go-lint
go-lint:
	$(GO) fmt ./...
	CGO_ENABLED=0 $(GO) vet ./...

.PHONY: docs
docs:
	CGO_ENABLED=0 $(GO) run ./cmd/gen-docs

.PHONY: clean
clean:
	rm -f $(BINARY_NAME)
	rm -f $(GO_BINARY)
	rm -rf dist/

.PHONY: install
install:
	$(CARGO) install --path crates/symfritz-cli --locked

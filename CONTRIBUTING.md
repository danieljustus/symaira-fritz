# Contributing to Symaira Fritz

Thank you for your interest in contributing to Symaira Fritz! This document provides guidelines and information for contributors.

## Development Setup

### Prerequisites

- Rust 1.98.0 via rustup (production implementation)
- Git
- Python 3 and Make for the verification scripts
- Go 1.26.6 for the historical CLI differential only; building and running the
  production Rust binary does not require Go

### Trusted oracle setup

Before running `make cli-contract`, export absolute paths to trusted Git and
the pinned Go executable. With an installed Go launcher that supports toolchain
selection, run from the repository root on macOS/Linux:

```bash
export SYMAIRA_TRUSTED_GIT="$(command -v git)"
export SYMAIRA_TRUSTED_GO="$(GOTOOLCHAIN=go1.26.6 go env GOROOT)/bin/go"
"$SYMAIRA_TRUSTED_GO" version  # must report go1.26.6
```

The Go command downloads Go 1.26.6 if necessary. Select the direct `GOROOT/bin/go`
binary, not a newer Go launcher: the differential runner intentionally ignores
caller `GO*` overrides and forces `GOTOOLCHAIN=local`. Exporting `GOTOOLCHAIN`
alone therefore does not select the oracle toolchain.

On Windows (PowerShell):

```powershell
$env:SYMAIRA_TRUSTED_GIT = (Get-Command git -CommandType Application).Source
$env:GOTOOLCHAIN = 'go1.26.6'
$env:SYMAIRA_TRUSTED_GO = Join-Path (go env GOROOT) 'bin/go.exe'
& $env:SYMAIRA_TRUSTED_GO version  # must report go1.26.6
```

Use these variables in the same shell as the checks below. A shallow clone may
also need `git fetch --unshallow origin` to include the immutable historical
oracle commit. Verification rebuilds that oracle in isolated temporary storage;
it never uses a prebuilt replacement or connects to a physical router.

### Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/symaira-fritz.git
   cd symaira-fritz
   ```
3. Create a branch for your changes:
   ```bash
   git checkout -b my-feature
   ```
4. Complete the [trusted oracle setup](#trusted-oracle-setup), then make your
   changes and ensure they pass all checks:
   ```bash
   make build
   make lint
   make test
   make cli-contract
   make release-manifest-test
   ```

## Code Style

- Follow Rust conventions (`rustfmt`, Clippy with warnings denied)
- Keep functions focused and small
- Write meaningful commit messages
- Add tests for new functionality


## Pull Request Process

1. Update documentation if your change affects user-facing behavior
2. Add tests for new functionality
3. Ensure all CI checks pass
4. Submit your PR with a clear description of the changes
5. Link the related issue in the PR body

## Reporting Issues

- Use the GitHub issue templates for bug reports and feature requests
- Include reproduction steps for bugs
- Describe the expected vs actual behavior

## Security

If you discover a security vulnerability, please report it privately via [GitHub's private vulnerability reporting](https://github.com/danieljustus/symaira-fritz/security/advisories/new). Do not open a public issue for security vulnerabilities.

## License

By contributing to Symaira Fritz, you agree that your contributions will be licensed under the Apache-2.0 License.

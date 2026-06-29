# Contributing to Symaira Fritz

Thank you for your interest in contributing to Symaira Fritz! This document provides guidelines and information for contributors.

## Development Setup

### Prerequisites

- Go 1.26.4 or later
- Git

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
4. Make your changes and ensure they pass all checks:
   ```bash
   CGO_ENABLED=0 go vet ./...
   CGO_ENABLED=0 go build ./...
   CGO_ENABLED=0 go test -race ./...
   ```

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep functions focused and small
- Write meaningful commit messages
- Add tests for new functionality
- Ensure `CGO_ENABLED=0` builds succeed (cross-platform requirement)

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

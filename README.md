# Symaira Fritz

> **Accepted product direction — implementation pending:** Fritz remains an independent FRITZ!Box tool. The standalone symvault credential service remains optional and usable without Brain. The accepted ecosystem consolidation does not change Fritz protocols, secret resolution or installation. See [PB-2026-09-09](docs/product-boundaries.md).

[![CI](https://github.com/danieljustus/symaira-fritz/actions/workflows/ci.yml/badge.svg)](https://github.com/danieljustus/symaira-fritz/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/danieljustus/symaira-fritz)](https://github.com/danieljustus/symaira-fritz/releases/latest)
[![License](https://img.shields.io/github/license/danieljustus/symaira-fritz)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.98-orange.svg)](rust-toolchain.toml)

![Symaira Fritz](docs/assets/social-preview.png)

> A CLI to **administer, analyse, and control an AVM FRITZ!Box** — part of the
> Symaira ecosystem. Binary name: `symfritz`.

**Status:** Active development — see the [latest releases](https://github.com/danieljustus/symaira-fritz/releases).

## Demo

![symfritz terminal demo](docs/assets/symfritz-demo.svg)

Editable router/radio mark and ready-to-publish social, release, and README
graphics: [public asset kit](assets/branding/public-kit/README.md). The router
signet and existing CLI/repository identifiers remain unchanged.

## Why symfritz

- **Single binary, no dependencies** — works on macOS, Linux, and Windows
- **Speaks documented interfaces only** (TR-064, AHA-HTTP) — no reverse-engineering required
- **End-to-end diagnosis in one command** — `symfritz diagnose <host>` checks box entry, activity, LAN/WLAN, DNS, and TCP ports
- **Secure credential handling** — resolves from env, symvault, or macOS Keychain; never stores plaintext by default
- **MCP server for AI agents** — exposes all capabilities as a stdio MCP server

It speaks the FRITZ!Box's documented interfaces, no reverse-engineering required:

| Interface | Used for | Endpoint |
|-----------|----------|----------|
| **TR-064** (SOAP) | Administration: status, WAN/IP, WLAN, host list, mesh, reboot | `:49443` (TLS default) / `:49000` |
| **AHA-HTTP** | DECT smart-home actors (switches, thermostats) | `/webservices/homeautoswitch.lua` |
| **Session login** | Auth for AHA and best-effort web-UI scraping | `/login_sid.lua` |

> Inspired by [`fritzconnection`](https://github.com/kbr/fritzconnection) (Python,
> the best TR-064 reference) and [`fritzctl`](https://github.com/bpicode/fritzctl)
> (Go, the architectural blueprint).

## Capabilities

- **Session auth** — modern PBKDF2 (FRITZ!OS 7.24+) *and* legacy MD5 challenge-response, with automatic re-login on session expiry.
- **TR-064** — generic action calls with HTTP digest auth, plus `tr64desc.xml` service discovery (`symfritz services`).
- **Hosts** — first-class host table: `list`, `active`, `get` by name/MAC/IP.
- **Detect** — find FRITZ!Box on local network when `fritz.box` resolves to a public IP.
- **Diagnose** — end-to-end host reachability (box entry → active → LAN/WLAN → DNS → TCP ports).
- **Doctor** — validate the local config, credential resolution, TR-064 discovery, session login, and optional AHA access.
- **Mesh** — topology of nodes, repeaters, and links.
- **WLAN** — radios, associated clients, guest-network status/toggle.
- **Wake-on-LAN** — by host name/IP or explicit MAC.
- **AHA-HTTP** — DECT device listing, switch on/off, and thermostat temperature control (`symfritz home`).
- **Credentials** — `auth login/test/store`, resolved from env → symvault → macOS Keychain → config.
- **Traffic** — current WAN traffic rates (downstream/upstream by category); use `symfritz traffic --watch` for live monitoring.
- **DSL** — line statistics: noise margin, attenuation, max bit rate.
- **Phone** — call list with type filtering, dial, and hangup.
- **Log** — system event log with category filtering (sys/net/fon/wlan/usb).
- **`status`**, **`reboot`**, an **MCP server** (stdio) exposing the above, config + env loading.
- Global `--output text|json|yaml` for structured output; `--json` remains the shorthand on the root and existing subcommands.

Still planned: per-radio band labelling.

## Install

```bash
make build           # → ./symfritz
# or
cargo install --path crates/symfritz-cli --locked
# or via Homebrew
brew install danieljustus/tap/symfritz
```

## Configure

```bash
symfritz config init                       # writes ~/.config/symfritz/config.toml
# edit host/user in the file, then store the password securely:
symfritz auth login                        # reads SYMFRITZ_PASSWORD or prompts, verifies, stores it
symfritz auth test                         # confirm it resolves and works
```

`config init` is intentionally a subcommand rather than a top-level `init`: symfritz
has one local configuration file and no other initialization state.

### Where the password comes from

symfritz resolves the password at runtime, in this order (first hit wins):

1. **`SYMFRITZ_PASSWORD`** environment variable — ad-hoc / CI.
2. **symvault** — set `password_ref = "fritz.password"` in the config; symfritz
   shells out to `symvault get` so nothing is stored on disk.
3. **macOS Keychain** — set `keychain = true`; service `symfritz`, account = host.
4. **`password`** plaintext in the config — least secure, convenience only.

`auth login` reads `SYMFRITZ_PASSWORD` when set (otherwise prompts), verifies
the password, and stores it in the Keychain (default on macOS) or symvault
(`--symvault fritz.password`). symvault
and the Keychain are reached through their CLIs, so symfritz has **no build
dependency** on either and works fine when they are absent.

```bash
symfritz auth login --symvault fritz.password   # store in symvault instead of Keychain
symfritz auth store --keychain                  # store without verifying (reads SYMFRITZ_PASSWORD or prompts)
symfritz auth test                              # show source + verify web login and TR-064 access
```

> **Tip:** use a dedicated FRITZ!Box user with only the permissions you need
> rather than the admin account. TR-064 must be enabled on the box
> (Home Network → Network → Network Settings → "Allow access for applications").

### Debug logging

For troubleshooting or attaching detailed diagnostics to a bug report, enable debug logging by setting the `SYMFRITZ_LOG_LEVEL=debug` environment variable:

```bash
SYMFRITZ_LOG_LEVEL=debug symfritz doctor
```

This emits request-level logs (method, redacted URL, and status code) for TR-064, session login, and service discovery requests while keeping credentials, passwords, and session IDs redacted.

### TLS & Certificate Pinning

TLS is enabled by default (`use_tls = true`), connecting to port 49443 (TR-064)
and port 443 (web login). On first connection, symfritz records the box's
certificate public key pin (TOFU) in `~/.config/symfritz/pins.json` and verifies
it on subsequent calls.

- If TLS endpoints do not answer (e.g. TR-064 TLS is disabled on the box), symfritz
  automatically falls back to plain HTTP and emits a warning naming `use_tls`.
- Set `use_tls = false` in `~/.config/symfritz/config.toml` to disable TLS entirely.
- Set `insecure_tls = true` to skip certificate verification without pinning.
- Use `symfritz auth trust --reset <host>` to reset a recorded certificate pin.

## Usage

For the complete list of commands, subcommands, and flags, see the [CLI Command Reference](docs/cli.md).

### Common commands

```bash
symfritz status                             # model, firmware, connection, external IP
symfritz detect                             # find FRITZ!Box on local network
symfritz diagnose macmini                   # end-to-end host reachability check
symfritz diagnose router                    # detect and diagnose local router
symfritz doctor                             # verify the local setup and box access
symfritz hosts list                         # all known network devices
symfritz wlan radios                        # WLAN SSIDs, channels, state
symfritz traffic                            # current WAN traffic rates
symfritz traffic --watch --interval 5s       # live WAN traffic monitoring
symfritz dsl                                # DSL line statistics
symfritz home list                          # DECT smart-home actors
symfritz home temp <ain> <celsius|on|off>   # set target temperature for thermostat
symfritz calls                              # recent call list
symfritz status --output json                # machine-readable status
symfritz reboot --yes                       # reboot the FRITZ!Box
symfritz mcp                                # start MCP stdio server for AI agents
```

### Read-only DNS-path diagnosis

```bash
SYMFRITZ_HOST=192.168.188.1 symfritz dns homeassistant.fritz.box --expected-ip 192.168.188.20 --json
# Compare with a separately known router DNS endpoint when necessary:
SYMFRITZ_HOST=192.168.188.1 symfritz dns fritz.box --router-dns-ip 192.168.188.1 --json
```

The addresses above are examples, not discovered device addresses. The command
requires a literal local IPv4 or IPv6 router connection address in the config or
`SYMFRITZ_HOST`, so broken OS DNS cannot block transport initialization.
`--router-dns-ip` selects a DNS comparison endpoint, not the TR-064 connection
address; configured router hostnames are rejected before transport creation.
The command
checks only the selected absolute name (A and AAAA), never the full host inventory
or guessed suffixes. `--expected-ip` compares answer identity and requests one
typed host-table entry; a private answer or active table flag does not prove IP
connectivity. `.local` is reported as mDNS/unsupported without unicast queries.

The report separates router DHCP DNS configuration, TR-064 `NewDomainName`,
unobserved DHCP option 15, and client resolver/search evidence. macOS captures
`scutil --dns` within two seconds and 64 KiB; Linux reads a bounded
`/etc/resolv.conf` snapshot. Other platforms, scoped IPv6 resolvers, OS/NSS and
VPN split-resolver selection stay unknown rather than being guessed. Direct UDP
queries are capped at 500 ms each and five seconds total, separately from bounded
TR-064 requests (at most two seconds per request). Ctrl-C stops between calls.
Text mode prints the same explicit JSON fields; YAML remains available.

An external resolver such as AdGuard may need conditional forwarding of the
verified local zone to router-local DNS. Optional DHCP suffix restoration affects
bare-name search separately. This command changes neither setting, does not enable
FRITZ!OS DNS filtering, and does not claim FRITZ!OS 8.50 compatibility or a new
firmware regression. DNS-filter state is explicitly unknown.

### Typical Mac Mini check

```bash
symfritz diagnose macmini
# Diagnose macmini  →  192.168.188.65
#   ✓ FRITZ!Box knows host       macmini
#   ✓ Host active
#   ✓ IP address                 192.168.188.65
#   ✓ Link medium                LAN
#   ✓ DNS resolves               192.168.188.65
#   ✓ TCP 22 (SSH)               open
#   ✗ TCP 5900 (VNC/Screen Sharing)  closed or filtered
#   ✓ TCP 8001 (Paperless)       open
```

### Raw TR-064 service names

Shortcuts: `deviceinfo`, `wanip`, `wanppp`, `wancommon`, `hosts`, `wlan1`. Any
other name is resolved through `tr64desc.xml` discovery, so `call` reaches every
action the box advertises.

## MCP server

`symfritz mcp` starts a stdio MCP server that exposes the FRITZ!Box capabilities
to AI agents such as Hermes.

### Registering in Hermes

Add a server block to your Hermes configuration. The example below assumes the
Homebrew-installed binary at `/opt/homebrew/bin/symfritz`; adjust the path to
your installation:

```yaml
mcp_servers:
  symfritz:
    command: /opt/homebrew/bin/symfritz
    args:
      - mcp
    env:
      SYMFRITZ_HOST: "192.168.188.1"
    enabled: true
```

> **Note:** `fritz.box` can resolve to a public IP address on some networks, which
> causes the MCP server to fail to reach the box. Use an explicit local IP or a
> DNS name you control, and set it via `SYMFRITZ_HOST` or `host` in the config.

### Smoke test

After registering, verify the server starts and exposes the expected tools:

```bash
$ SYMFRITZ_HOST=192.168.188.1 symfritz mcp
initialize: OK
serverInfo.name: symfritz
serverInfo.version: <version>
tools/list: 9 tools
```

The expected tools are `status`, `host_list`, `host_get`, `diagnose`, `mesh`,
`wlan_clients`, `wake_on_lan`, `home_list`, and `home_switch`.

## Ecosystem

Symaira Fritz is part of the [Symaira ecosystem](https://symaira.com). It can
use [symvault](https://github.com/danieljustus/symaira-vault) as an optional
credential store and exposes its capabilities to [Hermes Agent](https://hermes-agent.nousresearch.com/)
through MCP.

## Architecture

```
crates/symfritz-cli/    clap CLI and output adapters
crates/symfritz-core/   config, credentials, auth primitives, TLS pins
crates/symfritz-tr064/  SOAP/digest transport, discovery, typed capabilities
crates/symfritz-aha/    session-authenticated AHA and web endpoints
crates/symfritz-mcp/    MCP stdio server and protocol framing
```

The Rust crates are the complete production implementation. Language-neutral
fixtures under `testdata/port/` preserve the contracts frozen during the port.

## Caveats

- TR-064 + AHA cover the stable ~80%. For remaining data such as some stats,
  logs, and guest-WLAN details, the best-effort `symfritz scrape` command uses
  the web-UI `data.lua` endpoint. That interface is FRITZ!OS-version-dependent
  and may break on firmware updates; prefer TR-064 or AHA whenever possible.

## Upgrade and rollback

Current releases contain only the Rust `symfritz` binary. Keep the existing
`~/.config/symfritz/config.toml` and `~/.config/symfritz/pins.json` when
upgrading; their formats did not change during the Rust migration.

Verify an upgrade with:

```bash
symfritz version --json
```

For an implementation-level rollback, use the immutable v0.7.0 release archive,
which still contains `symfritz-go`. Keep the same config and pin files; do not
delete or reset them as part of rollback. See
[`docs/rust-port/release-cutover.md`](docs/rust-port/release-cutover.md) for the
release, signing, SBOM, and migration evidence.

## Development

Rust has been the sole source implementation since the completed v0.7
migration. The parity evidence and immutable rollback point are documented in
[`docs/rust-port/`](docs/rust-port/).

Build:

```bash
make build           # → ./symfritz
```

Test (complete the [trusted oracle setup](CONTRIBUTING.md#trusted-oracle-setup)
before running the CLI contract suite; its Go 1.26.6 dependency is verification-only):

```bash
make test            # complete Rust workspace
make rust-test
make cli-contract    # strict local v0.7.0-Go↔Rust fake-box CLI suite
```

Lint:

```bash
make lint            # rustfmt + Clippy
make rust-lint
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution guide.

## License

Apache-2.0. See [LICENSE](LICENSE).

### Firmware status, refresh and installation

```sh
symfritz firmware status --json
symfritz firmware check --json
# After creating/verifying a configuration backup, with stable power and local wired access:
symfritz firmware install --yes --verify --json
```

`status` reads the box's cached availability; `check` explicitly invokes
`X_AVM-DE_CheckUpdate`. These commands expose separate available, unavailable,
unknown, checking, failed and unsupported states, plus model/serial, current and
offered versions, build type, auto-update mode and last result where supported.
The existing `symfritz status` and `update_available()` contracts are unchanged.
Actions and endpoints come from the router's TR-064 description and SCPD.
Field semantics follow the [FRITZ! UserInterface specification](https://fritz.support/resources/TR-064_User_Interface.pdf).

Installation requires `--yes` before configuration, credentials or network access.
Back up and verify the configuration first. Expect internet, WLAN and telephony
loss; keep wired local access and stable power, and never unplug during an update.
Only the box-selected, unambiguously newer Release offer is accepted. Missing
identity/version/channel, conflicting metadata, unknown/no-update states,
unrecognised versions, model-prefix changes and downgrades fail closed. There
are no image URL, manual-image, Lab or downgrade options. No image is downloaded
or selected by symfritz.

A successful install response reports **accepted**, never installed. `--verify`
performs bounded TR-064 DeviceInfo readback, requiring the original model and
serial and the offered version. Reports distinguish `accepted`, `rebooting`
(in observation history, meaning unreachable after acceptance),
`verified_installed`, `timeout`, `unknown` and `rejected`. A disconnect or invalid
response during dispatch means **unknown**, and installation is never retried
automatically. Verification cannot establish what happened after cancellation or
its deadline; reconnect and inspect the original device before further action.
CLI incomplete/rejected outcomes retain their single result document and exit
nonzero. MCP returns the same explicit outcome data.

The default polling budget is 30 observations, two seconds apart, with a
120-second deadline for starting calls. Public options cap polling at 60 and
elapsed time at 600 seconds. An in-flight synchronous SOAP call can outlive that
deadline by its bounded transport timeout (including at most one Digest
challenge exchange). Firmware CLI/MCP transports cap each HTTP request at 15
seconds and disable HTTP fallback; cooperative cancellation is checked before
each dispatch and between polls. Library users construct
`Client<FirmwareTransport<T>, C>` using the same cancellation source for the
adapter and workflow, a bounded inner transport, and no automatic fallback.
The adapter only forwards requests, checks cancellation and validates SOAP
responses; authentication and HTTP remain with the existing client/transport.

MCP appends `firmware_status`, `firmware_check` and `firmware_install` after the
original nine tools. Refresh is annotated as a mutation. Installation is
annotated destructive, non-idempotent and open-world; it requires explicit user
consent after the backup/connectivity preflight and `{"confirm":true}` (optionally
`"verify":true`). Tool annotations do not grant consent.

**Manual acceptance gate — unperformed:** automated tests use mock responses;
no real router installation was performed for this feature. A human must
explicitly authorize a model-specific installation, verify the backup and
connectivity plan, then check the original device's identity/version and local
reachability after reboot. The earlier FRITZ!Box 4060 / 261.08.25 check is not
installation evidence or proof of FRITZ!OS 8.50 compatibility.

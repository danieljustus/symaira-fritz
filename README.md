# symaira-fritz

A CLI to **administer, analyse, and control an AVM FRITZ!Box** — part of the
Symaira ecosystem. Binary name: `symfritz`.

It speaks the FRITZ!Box's documented interfaces, no reverse-engineering required:

| Interface | Used for | Endpoint |
|-----------|----------|----------|
| **TR-064** (SOAP) | Administration: status, WAN/IP, WLAN, host list, mesh, reboot | `:49000` / `:49443` |
| **AHA-HTTP** | DECT smart-home actors (switches, thermostats) | `/webservices/homeautoswitch.lua` |
| **Session login** | Auth for AHA and (later) web-UI scraping | `/login_sid.lua` |

> Inspired by [`fritzconnection`](https://github.com/kbr/fritzconnection) (Python,
> the best TR-064 reference) and [`fritzctl`](https://github.com/bpicode/fritzctl)
> (Go, the architectural blueprint).

## Status

Early scaffold. What works today:

- **Session auth** — modern PBKDF2 (FRITZ!OS 7.24+) *and* legacy MD5 challenge-response.
- **TR-064** — generic action calls with automatic HTTP digest auth (`symfritz call`).
- **AHA-HTTP** — DECT device listing and switch on/off (`symfritz home`).
- **`status`**, **`reboot`**, **MCP server** (stdio), config + env loading.

See the `TODO`s in the source for the planned surface (tr64desc.xml service
discovery, WLAN/guest-WLAN control, mesh topology, host list, thermostat control,
web-UI `data.lua` scraping for stats not exposed via TR-064).

## Install

```bash
make build           # → ./symfritz
# or
go install github.com/danieljustus/symaira-fritz/cmd/symfritz@latest
```

## Configure

```bash
symfritz config init                       # writes ~/.config/symfritz/config.toml
export SYMFRITZ_PASSWORD='your-box-password'
# optionally: export SYMFRITZ_HOST=192.168.178.1  SYMFRITZ_USER=admin
```

> **Security:** prefer the `SYMFRITZ_PASSWORD` env var (or symvault) over putting
> the password in `config.toml`. A FRITZ!Box user with only the needed permissions
> is recommended over the admin account.

## Usage

```bash
symfritz status                            # model, firmware, connection, external IP
symfritz status --json

symfritz home list                         # DECT actors: AIN, name, state
symfritz home switch <AIN> on              # toggle a smart plug

symfritz call deviceinfo GetInfo           # raw TR-064 (power user)
symfritz call wanip GetExternalIPAddress
symfritz call hosts GetGenericHostEntry NewIndex=0

symfritz reboot --yes

symfritz mcp                               # MCP stdio server for AI agents
```

### Raw TR-064 service shortcuts

`deviceinfo`, `wanip`, `wancommon`, `hosts`, `wlan1`. More are added as
higher-level commands land; until then `call` is the escape hatch for any action.

## Architecture

```
cmd/symfritz/        Cobra CLI
internal/config/     TOML + env config (corekit configkit)
internal/fritz/      Core library:
  client.go            Client, options, endpoints
  session.go           login_sid.lua auth (PBKDF2 + MD5)
  tr064.go             SOAP action calls
  digest.go            HTTP digest auth
  aha.go               AHA-HTTP smart-home
  status.go            high-level overview
internal/mcp/        MCP stdio server (corekit mcpserver)
```

The `internal/fritz` package is deliberately self-contained so other Symaira
tools could embed it later.

## Caveats

- TR-064 + AHA cover the stable ~80%. The remaining bits (some stats, certain
  logs, guest-WLAN details) are only available via **web-UI `data.lua` scraping**,
  which is FRITZ!OS-version-dependent and may break on firmware updates. That
  layer is intentionally not built yet and will be clearly marked "best effort".

## License

Apache-2.0. See [LICENSE](LICENSE).

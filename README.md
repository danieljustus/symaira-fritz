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

What works today:

- **Session auth** — modern PBKDF2 (FRITZ!OS 7.24+) *and* legacy MD5 challenge-response, with automatic re-login on session expiry.
- **TR-064** — generic action calls with HTTP digest auth, plus `tr64desc.xml` service discovery (`symfritz services`).
- **Hosts** — first-class host table: `list`, `active`, `get` by name/MAC/IP.
- **Diagnose** — end-to-end host reachability (box entry → active → LAN/WLAN → DNS → TCP ports).
- **Mesh** — topology of nodes, repeaters, and links.
- **WLAN** — radios, associated clients, guest-network status/toggle.
- **Wake-on-LAN** — by host name/IP or explicit MAC.
- **AHA-HTTP** — DECT device listing and switch on/off (`symfritz home`).
- **`status`**, **`reboot`**, an **MCP server** (stdio) exposing the above, config + env loading.
- `--json` on the query/diagnose commands for scripting.

Still planned: thermostat (HKR) control, per-radio band labelling, and the
web-UI `data.lua` scraping layer for stats TR-064 doesn't expose (firmware-fragile,
will be marked best-effort).

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

# Hosts
symfritz hosts list                        # all known devices
symfritz hosts active                      # only currently-active devices
symfritz hosts get macmini                 # by name…
symfritz hosts get --mac f0:18:98:f3:64:b5 # …or MAC…
symfritz hosts get --ip 192.168.188.65     # …or IP

# End-to-end diagnosis (the headline use case)
symfritz diagnose macmini                  # box entry → active → LAN/WLAN → DNS → ports
symfritz diagnose macmini --port 22 --port 5900 --port 8001
symfritz doctor macmini --json             # alias, machine-readable

# Network shape
symfritz mesh                              # mesh nodes + links
symfritz wlan radios                       # SSID / band / channel / state
symfritz wlan clients                      # associated devices + signal/speed
symfritz wlan guest status|on|off

# Wake the Mac Mini
symfritz wol macmini                       # resolves MAC via host table
symfritz wol --mac f0:18:98:f3:64:b5

# DECT smart home
symfritz home list
symfritz home switch <AIN> on

# Power-user / introspection
symfritz services                          # discover all TR-064 services (tr64desc.xml)
symfritz call deviceinfo GetInfo           # raw TR-064 action
symfritz call WLANConfiguration:2 GetInfo  # any discovered service by name

symfritz reboot --yes
symfritz mcp                               # MCP stdio server for AI agents
```

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

Shortcuts: `deviceinfo`, `wanip`, `wancommon`, `hosts`, `wlan1`. Any other name
is resolved through `tr64desc.xml` discovery, so `call` reaches every action the
box advertises.

## Architecture

```
cmd/symfritz/        Cobra CLI
internal/config/     TOML + env config (corekit configkit)
internal/fritz/      Core library:
  client.go            Client, options, endpoints
  session.go           login_sid.lua auth (PBKDF2 + MD5, auto re-login)
  tr064.go             SOAP action calls
  digest.go            HTTP digest auth
  discover.go          tr64desc.xml service discovery
  hosts.go             host table, lookup, Wake-on-LAN
  diagnose.go          end-to-end reachability checks
  wlan.go              radios, clients, guest network
  mesh.go              mesh topology
  aha.go               AHA-HTTP smart-home
  status.go            high-level overview
internal/mcp/        MCP stdio server: status, host_list, host_get, diagnose,
                     mesh, wlan_clients, wake_on_lan, home_list, home_switch
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

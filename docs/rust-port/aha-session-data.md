# Rust SID and `data.lua` boundary

`crates/symfritz-aha` owns the session-id lifecycle, typed AHA/Homeauto
models, and the raw web-UI scraper boundary. AHA-HTTP is the stable smart-home
surface; `data.lua` remains best-effort and version-fragile.

## Side-effect boundary

`Client<T, C>` is generic over `Transport` and `Clock`. The crate does not
resolve credentials, read a credential store, or open sockets itself. A
production adapter supplies a transport; tests use a recording transport and
a deterministic clock.

`Transport::send` receives a complete request, including its method, URL,
headers, body, and response limit. A transport must retain no more than the
requested limit; excess response bytes are silently truncated. The `data.lua`
limit is **5 MiB** (`5 << 20`), the AHA response limit is **1 MiB**, and the
`login_sid.lua` XML limit is 64 KiB.
The shared concrete TR-064 transport ceiling is **5 MiB** so it can carry the
`data.lua` request without truncating it.

## SID lifecycle

1. A fresh, non-sentinel cached SID is returned without a request.
2. Missing or whitespace-only passwords fail before the transport is called.
3. `/login_sid.lua?version=2` is fetched and a ready SID is cached.
4. Otherwise the challenge is passed to `symfritz-core::auth`, which supports
   both UTF-16LE MD5 and two-round PBKDF2-HMAC-SHA256 challenges.
5. The username and response are sent in the second login request. Invalid SID
   and positive `BlockTime` are reported separately.
6. Cached SIDs expire after the configurable TTL (15 minutes by default) and
   can be explicitly invalidated.
7. An AHA HTTP 403 clears the SID, logs in once, and retries once. A second 403
   is returned as `AhaForbiddenAfterRelogin`; there is no retry loop.
8. `data.lua` does **not** retry or invalidate the SID on HTTP 403, matching Go
   `ScrapeDataLUA`; it returns `DataLuaHttpStatus(403)`.

## AHA/Homeauto contract

`home` sends `GET /webservices/homeautoswitch.lua` with `sid`, `switchcmd`,
and caller parameters encoded with Go `url.Values.Encode` ordering. It trims
successful response text, bounds the body at 1 MiB, and performs exactly one
SID invalidation/re-login retry for HTTP 403. `devices`, `groups`,
`device_list`, `switch_on`, `switch_off`, and `set_hkr_temp` preserve the Go
XML field mapping, group-member splitting, and 253/254 thermostat values.
TR-064 `homeauto_devices` enumerates `GetGenericDeviceInfos` from index zero
until the first error, and `homeauto_switch` uses `SetSwitch` with `ON`/`OFF`.

## `data.lua` contract

`data_lua(page, params)` sends a POST to `/data.lua` with the exact
`application/x-www-form-urlencoded` body equivalent to Go's `url.Values.Encode`:
keys are sorted, spaces use `+`, and repeated values are preserved. The body
contains `page`, `sid`, and caller parameters. A successful response must be
valid JSON; its original bytes (including surrounding whitespace) are returned
as text. HTTP status errors, HTML login pages, and other non-JSON bodies retain
Go's exact scrape error strings. Login parsing errors remain explicit when the
bounded prefix is malformed.

This endpoint is best-effort and version-fragile. Prefer TR-064 or AHA APIs
when a stable capability exists, and do not infer a typed schema from this raw
response.

# Rust SID and `data.lua` boundary

`crates/symfritz-aha` owns the session-id lifecycle and the raw web-UI
scraper foundation. It intentionally does not contain typed AHA/Homeauto
models; those belong to a later vertical slice.

## Side-effect boundary

`Client<T, C>` is generic over `Transport` and `Clock`. The crate does not
resolve credentials, read a credential store, or open sockets itself. A
production adapter supplies a transport; tests use a recording transport and
a deterministic clock.

`Transport::send` receives a complete request, including its method, URL,
headers, body, and response limit. A transport must honor the requested limit
or return an error. The `data.lua` limit is **5 MiB** (`5 << 20`), while the
`login_sid.lua` XML limit is 64 KiB.

The existing TR-064 concrete transport currently has a 4 MiB global ceiling.
It must be made configurable or raised to at least 5 MiB before this client is
connected to that adapter; silently routing `data.lua` through the 4 MiB cap
would break the Go contract. Keeping this crate transport-generic avoids that
loss in this slice.

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
7. A `data.lua` HTTP 403 clears the SID, logs in once, and retries once. A
   second 403 is returned as `ForbiddenAfterRelogin`; there is no retry loop.

## `data.lua` contract

`data_lua(page, params)` sends a POST to `/data.lua` with the exact
`application/x-www-form-urlencoded` body equivalent to Go's `url.Values.Encode`:
keys are sorted, spaces use `+`, and repeated values are preserved. The body
contains `page`, `sid`, and caller parameters. A successful response must be
valid JSON; its original bytes (including surrounding whitespace) are returned
as text. HTTP status errors, HTML login pages, other non-JSON bodies, malformed
login XML, and over-limit bodies are explicit errors.

This endpoint is best-effort and version-fragile. Prefer TR-064 or AHA APIs
when a stable capability exists, and do not infer a typed schema from this raw
response.

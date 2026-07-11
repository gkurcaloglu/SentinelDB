# Wasm plugin API

SentinelDB runs its firewall decision logic and its PII masking logic
inside a single sandboxed WebAssembly module rather than as native Go
code. This document describes that module's runtime, its wire contract
(`internal/wasmproto`), and how to rebuild it.

## Current Wasm runtime

- **Runtime**: [wazero](https://github.com/tetratelabs/wazero) v1.x, a
  pure-Go WebAssembly runtime — no cgo, no C toolchain required to run
  the host process.
- **Guest ABI**: [WASI Preview 1](https://github.com/WebAssembly/WASI)
  `command` model (`wasi_snapshot_preview1`). The plugin is a normal Go
  `main()` program compiled with `GOOS=wasip1 GOARCH=wasm`; it reads a
  single request from stdin, writes a single response to stdout, and
  exits.
- **Host object**: `internal/wasm.Runtime` — compiles the `.wasm` file
  once at startup (`NewRuntime`) and re-instantiates a fresh module
  instance from that same `CompiledModule` for every call
  (`Runtime.call`). WASI command modules are defined to run `main()`
  exactly once per instance, so a compiled module cannot be "called
  again" on an existing instance — each request gets a fresh, isolated
  instance instead.
- **Per-call timeout**: 2 seconds (`defaultTimeout`), enforced via
  `wazero.RuntimeConfig.WithCloseOnContextDone(true)` plus a
  `context.WithTimeout` on each call. A plugin that hangs or loops does
  not block the gateway indefinitely.

## One-module design

There is exactly **one** compiled plugin
(`plugins/firewall/v2.wasm`, loaded from `wasm.plugin_path` in
`config.yaml`) and exactly one `internal/wasm.Runtime` loading it. Both
the firewall decision (`evaluate_query`) and the masking transformation
(`mask_value`) are operations dispatched *within* that same module via a
shared, versioned request/response envelope — not two separate plugins
or two separate runtimes. `wasm.Policy` and `wasm.Masker` are both thin
adapters over the same `*wasm.Runtime`.

## Protocol version

`internal/wasmproto.ProtocolVersion = 1`. Every request (`Envelope`) and
response (`Result`) carries a `version` field. The host
(`wasm.Runtime.call` → `validateEnvelopeMeta`) rejects any response whose
`version` doesn't exactly match, or whose `op` doesn't match the
operation that was requested — a version or op mismatch is treated as a
plugin protocol error and fails closed exactly like a runtime error.

## Transport

Requests and responses are single JSON objects, one per call, exchanged
over the plugin's stdin/stdout:

- **Request**: the host serializes an `Envelope` to JSON and writes it
  as the entire stdin of a fresh module instance.
- **Response**: the plugin writes exactly one JSON `Result` object to
  stdout (via `json.NewEncoder(out).Encode(resp)`, which appends a
  single trailing `\n`) and exits.
- **Strict decoding**: the host decodes the response with
  `json.Decoder.DisallowUnknownFields()` and then verifies that nothing
  but whitespace remains after the first JSON value
  (`decodeStrictResult`). Extra fields, a second JSON value, or trailing
  garbage all cause the call to fail.
- **Output limits**: stdout is capped at 8 KiB and stderr at 4 KiB
  (`maxStdoutBytes`/`maxStderrBytes`), enforced *while the plugin writes*
  via a bounded buffer (`boundedBuffer`) rather than collected unbounded
  and truncated afterward. Exceeding either limit fails the call.
- Plugin stderr/stdout content is never included in host error messages
  or logs — only operation name, byte counts, and timeout/cancellation
  state are (see [threat-model.md](threat-model.md#sensitive-logging-policy)).

## `evaluate_query` operation

Evaluates a single frontend `Query` message's SQL text against a
host-supplied blocked-phrase list. Matching itself is plain
case/whitespace-insensitive substring matching (`internal/sqlmatch`),
not real SQL parsing — see
[threat-model.md](threat-model.md#known-bypass-limitations).

### Request

```json
{
  "version": 1,
  "op": "evaluate_query",
  "query": "SELECT * FROM users; DROP TABLE users;",
  "blocked_phrases": ["DROP TABLE", "DROP DATABASE", "DELETE FROM", "TRUNCATE"]
}
```

### Response — allowed

```json
{"version": 1, "op": "evaluate_query", "verdict": "ALLOW"}
```

### Response — blocked

```json
{
  "version": 1,
  "op": "evaluate_query",
  "verdict": "BLOCK",
  "reason": "SentinelDB policy (wasm): query engellendi (yasaklı ifade: \"DROP TABLE\")"
}
```

### Validation rules (host side, `validateEvaluateResponse`)

- `verdict` must be **exactly** `"ALLOW"` or `"BLOCK"` — anything else
  (missing, empty, misspelled, wrong case) is a protocol error and fails
  closed to `Block`. This is intentionally strict: an earlier
  implementation treated "anything that isn't literally `BLOCK`" as
  allow, which meant a malformed or unexpected plugin response could
  silently disable the firewall.

## `mask_value` operation

Masks a single cell value from a `DataRow`, for a single configured
column, according to a masking `kind`. V1 supports exactly one kind:
`email` (`wasmproto.KindEmail`).

### Request

```json
{
  "version": 1,
  "op": "mask_value",
  "column": "email",
  "kind": "email",
  "value": "john@example.com"
}
```

### Response — value changed

```json
{"version": 1, "op": "mask_value", "value": "jo****@example.com", "changed": true}
```

### Response — value unchanged (not email-shaped, or already masked)

```json
{"version": 1, "op": "mask_value", "value": "not-an-email", "changed": false}
```

### Masking rule (`plugins/firewall/mask.go`, `kind: "email"`)

- If the value doesn't look like an email (`looksLikeEmail`: exactly one
  `@`, non-empty local/domain parts, no whitespace in either, and a `.`
  in the domain that isn't the first or last character), it is returned
  unchanged with `changed: false`.
- Otherwise: the domain (including `@`) is preserved as-is. At most the
  first **two Unicode code points** (runes, not bytes — so multi-byte
  UTF-8 local parts aren't corrupted) of the local part are preserved,
  followed by a fixed `****` mask that does not reveal the original
  length. Examples: `john@example.com` → `jo****@example.com`;
  `jo@example.com` (2-char local part) → `jo****@example.com`;
  `x@example.com` (1-char local part) → `x****@example.com`.
- If the computed masked value is identical to the input (e.g. the input
  was already masked, like `jo****@example.com`), the response reports
  `changed: false`.

### Validation rules (host side, `validateMaskResponse`)

Both `value` and `changed` are required, presence-aware fields (see
`wireResult`'s pointer types in `internal/wasm/runtime.go`) — a response
that omits either field is rejected, distinct from an explicit
`value: ""`/`changed: false`. In addition:

- `value` must be valid UTF-8.
- `value` must be at most 64 KiB (`maxMaskedValueSize`) — generous for
  an email address, but bounds a malicious/buggy plugin trying to return
  an oversized value.
- `changed: true` requires `value != <the original input value>`.
- `changed: false` requires `value == <the original input value>`.

Any violation of the above is treated as a plugin contract violation and
fails the call — the caller (`masking.Transformer`) then fails the
connection closed rather than guess which value (masked or unmasked) is
"more correct" to forward.

## Timeout / output limits summary

| Limit | Value | Enforced by |
|---|---|---|
| Per-call wall-clock timeout | 2 seconds | `wazero.RuntimeConfig.WithCloseOnContextDone` + `context.WithTimeout` |
| stdout cap | 8 KiB | `boundedBuffer`, checked in `Runtime.call` |
| stderr cap | 4 KiB | `boundedBuffer`, checked in `Runtime.call` |
| `mask_value` response `value` size | 64 KiB | `validateMaskResponse` |

## Fail-closed behavior

Any of the following causes the *caller* (`wasm.Policy.Evaluate` for
`evaluate_query`, `masking.Transformer.handleDataRow` for `mask_value`)
to treat the call as failed and fail closed — block the query, or close
the connection with a `FATAL`/`ERROR` `ErrorResponse` — rather than
guess a safe default and continue:

- Module instantiation error (includes timeout/cancellation).
- stdout or stderr byte limit exceeded.
- Response is not valid, single-value, schema-exact JSON
  (`decodeStrictResult`).
- `version`/`op` mismatch, or a non-empty `error` field
  (`validateEnvelopeMeta`).
- Operation-specific validation failure (see above).

`wasm.Policy.Evaluate` specifically fails closed to **`Block`** — an
unevaluable query is refused, not allowed. `masking.Transformer` fails
closed by **closing the connection** — a cell that can't be safely
masked is never forwarded either as-is or partially masked.

## How to rebuild the plugin

The plugin source lives in `plugins/firewall/` (`main.go`, `mask.go`)
and compiles to the binary checked into git at
`plugins/firewall/v2.wasm`. After changing anything under
`plugins/firewall/`, rebuild it:

```powershell
pwsh scripts/build-wasm-plugins.ps1
```

Equivalently, by hand:

```powershell
$env:GOOS = "wasip1"
$env:GOARCH = "wasm"
go build -o plugins/firewall/v2.wasm ./plugins/firewall
```

Commit the rebuilt `plugins/firewall/v2.wasm` alongside your source
change — the gateway loads whatever binary is on disk at
`wasm.plugin_path`, so a stale binary silently makes source changes
inert until rebuilt.

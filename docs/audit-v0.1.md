# SentinelDB v0.1 final audit

**Date:** 2026-07-11
**Branch:** `audit/v0.1-final` (based on `main` / `v0.1.0` at `ae532e9324db25c28a1424ab154db31bd434c40a`)
**Scope:** Full repository — compile/API consistency, runtime safety, PostgreSQL
protocol handling, security posture, memory/performance correctness, HTTP/
metrics/dashboard behavior, documentation accuracy, and repository hygiene.
**Method:** Manual full-repository code reading (all `internal/`, `cmd/`,
`plugins/`, `dashboard/src/`, `scripts/`, `docs/`, and root project files),
targeted reproduction of suspected gaps, and live verification of the Docker
Compose stack. No findings in this report are speculative — each was either
reproduced with a failing test/probe before being fixed, or confirmed safe by
reading the actual code path.

This is a **hardening and truth-audit pass**, not a feature sprint. No new
product capabilities (Extended Query Protocol, TLS, COPY, AST-based SQL
parsing, new policy features, Kubernetes, authentication/RBAC) were added,
per the audit brief.

---

## 1. Confirmed issues fixed

### 1.1 `config.Load` silently accepted unknown YAML fields — **Medium**

**File:** `internal/config/config.go`

`Load` used `yaml.Unmarshal(data, &cfg)`, which (unlike a `yaml.Decoder` with
`KnownFields(true)`) silently ignores any YAML key that doesn't map to a
struct field. Reproduced with a probe test before fixing: a `config.yaml`
containing `unknown_top_level_field: 123` loaded without error. This means a
typo in `config.yaml` (e.g. `blocked_phrase:` instead of `blocked_phrases:`,
or a misplaced/misspelled key under `masking:`) would silently produce an
empty/default value instead of failing loudly — exactly the kind of "operator
believes a rule/mask is active but it isn't" gap the audit brief calls out
under config-vs-struct consistency.

**Fix:** `Load` now uses `yaml.NewDecoder` with `dec.KnownFields(true)`, so
any unrecognized field (top-level or nested) is rejected with a clear error.
An empty file (0 bytes) is still accepted as a valid zero-value `Config`,
preserving prior behavior for that edge case (guarded explicitly, since a
strict decoder's `Decode` returns `io.EOF` for empty input).

**Tests added:** `TestLoad_UnknownTopLevelFieldIsRejected`,
`TestLoad_UnknownNestedFieldIsRejected`, `TestLoad_EmptyFileIsValid`. All
pre-existing `internal/config` tests still pass, and the shipped
`config.yaml` was verified to still load successfully.

### 1.2 Metrics/API HTTP servers had no timeouts — **Medium**

**File:** `cmd/gateway/main.go`

Both `http.Server` instances (`/metrics` on `SENTINELDB_METRICS_ADDR`,
`/api/status` on `SENTINELDB_API_ADDR`) were constructed with only `Addr` and
`Handler` set — no `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, or
`IdleTimeout`. Go's `net/http` documents this as unsafe: a client that opens a
connection and sends headers slowly (or never finishes) can hold a server
goroutine/connection open indefinitely (the classic "Slowloris" resource-
exhaustion shape), which the audit brief explicitly asks to check for under
"HTTP servers have reasonable timeouts."

**Fix:** both servers now set `ReadHeaderTimeout: 5s`, `ReadTimeout: 10s`,
`WriteTimeout: 10s`, `IdleTimeout: 60s` — generous for these endpoints (a
small, fixed-shape JSON/Prometheus-text response) but bounded. This does not
change documented behavior; the demo stack's healthchecks (`wget` against
`/api/status` every 10s with a 3s timeout) and the dashboard's 5s
per-request timeout are both comfortably inside these bounds, verified live
(see §5).

### 1.3 Stale documentation comments referencing a removed component — **Low**

**File:** `internal/protocol/decoder.go`

`Decoder`'s package doc and the `phasePassthrough` comment both described the
decoder as being "fed by `SniffReader`" and said that in the passthrough
phase "`SniffReader` continues to flow bytes through unchanged (observer-only,
genuine raw forwarding)." Neither is accurate for the current architecture:
`SniffReader` (`internal/protocol/sniffer.go`) is dead code with zero call
sites in `cmd/`, `internal/firewall`, or `internal/masking` — confirmed by
repository-wide grep. The actual current callers, `firewall.Gate.Run` and
`masking.Transformer.Run`, read bytes themselves and call `dec.Write`
directly; neither wraps the underlying connection in a passthrough-style
reader, and once `phasePassthrough` is reached, both callers immediately
observe a non-nil error and close the connection (no bytes are "flowed
through" by anything at the `Decoder` level or below).

**Fix:** updated both comments to describe the current, correct callers
(`Gate.Run`/`Transformer.Run`) and behavior (`Write` returns immediately,
forwarding nothing). This is a documentation-only change — no `Decoder`
behavior was modified.

**Note on `sniffer.go` itself:** it remains in the tree, untested and
unreferenced by production code. Removing it was attempted during this audit
and blocked by the environment's safety controls, since it is a pre-existing
tracked file whose deletion wasn't explicitly requested. It is flagged as a
**V1 limitation intentionally not fixed** below (§3) pending an explicit
decision from the maintainer.

### 1.4 No `.gitattributes` — Windows checkouts break the documented `gofmt -l .` check — **Low**

**Files:** `.gitattributes` (new)

All tracked `.go` files are committed with LF-only line endings (verified via
`git show HEAD:<path>`), and CI's Linux `gofmt -l .` step (`.github/workflows/ci.yml`)
correctly passes against them. However, the repository has no `.gitattributes`,
and Git for Windows' commonly-recommended default (`core.autocrlf=true`)
converts every text file to CRLF on checkout. Reproduced live in this audit
environment: a fresh checkout on this Windows machine left ~35 of the ~40
tracked `.go` files with CRLF line endings, and `gofmt -l .` — the exact
command both `README.md` and `CONTRIBUTING.md` instruct contributors to run
locally — flagged nearly the entire repository as "not gofmt-formatted" as a
pure line-ending artifact, not a real formatting issue.

**Fix:** added `.gitattributes` with `* text=auto eol=lf`, so any future clone
(Windows or otherwise) checks out text files with LF, matching what's
actually committed and what `gofmt` expects. No tracked file's committed
*content* changed — this repository's blobs were already LF-only; only the
checkout normalization rule was added. The local working tree was
renormalized as part of this fix and reverified clean (`gofmt -l .` → no
output, `git status` → clean).

### 1.5 Small bounded fuzz coverage added for untrusted-input parsers — **Informational (hardening, not a bug fix)**

**Files:** `internal/protocol/datarow_test.go`, `internal/protocol/rowdescription_test.go`,
`internal/protocol/decoder_test.go`

No `func Fuzz*` targets existed anywhere in the repository (confirmed via
grep). The three parsers that operate directly on untrusted wire bytes
(`ParseDataRow`, `ParseRowDescription`, `Decoder.Write`) already had strong,
explicit table-driven "never panics" tests, but no genuine fuzzer had ever
exercised them. Per the audit brief's "add a small, bounded set... when they
prove/protect a concrete invariant," three `Fuzz*` functions were added,
seeded from the existing test corpus, each asserting only the invariant
already documented in `docs/postgresql-protocol.md`: **no parser panics on
malformed/truncated/oversized input.**

Run locally, bounded to 8 seconds each (not a long-running campaign):

| Target | Executions | Crashes found |
|---|---:|---:|
| `FuzzParseDataRow` | ~335,000 | 0 |
| `FuzzParseRowDescription` | ~107,000 | 0 |
| `FuzzDecoderWrite` (both client and server decoders, fragmented writes) | ~2,425,000 | 0 |

No crashes were found — this **confirms** the existing defensive parsing is
correct, it does not reveal a new bug. The fuzz targets are committed as a
permanent regression guard (they run as ordinary, fast seed-corpus-only tests
under plain `go test`, adding <1s to the suite; no `testdata/fuzz` corpus
directory was generated or committed).

---

## 2. Confirmed safe behaviors

Verified directly by reading the implementation (not assumed from
documentation) — no changes needed:

- **Firewall Gate callback signatures** (`internal/firewall/gate.go`) are
  internally consistent with all three call sites (`cmd/gateway/main.go`,
  and both native/Wasm `Policy` implementations in `internal/firewall/policy.go`
  and `internal/wasm/policy.go`).
- **`metrics.Snapshot` fields vs. `/api/status` usage** (`internal/metrics/metrics.go`,
  `internal/api/status.go`) — every `Snapshot` field is consumed exactly
  once, with no field name/type mismatch; both `/metrics` and `/api/status`
  read from the same `prometheus.Registry`, so they cannot drift.
- **Wasm protocol types vs. plugin usage** (`internal/wasmproto/protocol.go`
  vs. `internal/wasm/runtime.go` and `plugins/firewall/main.go`) — both host
  and guest import the same dependency-free package; field presence
  (`Value`/`Changed` as non-`omitempty`) is deliberately asymmetric between
  `wasmproto.Result` (guest-side, always-present) and `wireResult`
  (host-side, pointer/presence-aware for strict validation) and this
  asymmetry is intentional and documented, not a bug.
- **`wasm.Runtime.Evaluate`/`Mask` vs. `masking.Masker`/`firewall.Policy`
  interfaces** — adapters (`wasm.Policy`, `wasm.Masker`) correctly narrow the
  wider `Runtime` API to the exact interface each consumer expects.
- **`masking.Transformer` wiring** — `RowDescription` state
  (`t.fields`/`t.maskColIdx`) is correctly cleared on `CommandComplete`,
  `ErrorResponse`, and `ReadyForQuery` (`clearResultSet`), preventing stale
  column-index reuse across result sets (verified by
  `TestTransformer_MultipleResultSets_ClearsStateBetweenSets`).
- **`config.yaml` vs. `Config` structs** — every YAML key in the shipped
  `config.yaml` maps to a real struct field; conversely, every struct field
  has a corresponding, documented YAML key. (The one gap — unknown fields
  not being rejected — is fixed in §1.1.)
- **Transaction-state handling** (`internal/protocol/txstate.go`) — a single
  shared `*TxState`, updated only from real server `ReadyForQuery` messages
  and read by `firewall.Gate` when synthesizing a blocked-query response,
  is atomic (`atomic.Int32`-backed) and race-free (verified by
  `TestTxState_ConcurrentAccessIsSafe` and confirmed no data race by
  inspection of all call sites — see §5 for why `-race` itself couldn't run
  locally).
- **`SerializedWriter` usage** — every write path back to the client
  (`firewall.Gate`'s synthetic responses, `masking.Transformer`'s forwarded/
  masked bytes) goes through the *same* single `*protocol.SerializedWriter`
  per connection (constructed once in `handleConn`), so two goroutines can
  never interleave partial PostgreSQL messages on the wire. Verified by
  `TestSerializedWriter_NoInterleaving` (20 goroutines × 50 writes, asserted
  byte-run-length invariant) and by reading `cmd/gateway/main.go`'s
  `handleConn` to confirm no second writer to `client` exists anywhere.
- **Docker environment overrides** — the four `SENTINELDB_*` environment
  variables read in `cmd/gateway/main.go` exactly match the four values set
  in `docker-compose.yml`'s `sentineldb` service, and both `README.md` and
  `docs/operations.md` document the same four with matching defaults.
- **Fail-closed boundaries** (protocol parse failure, unsupported Extended
  Query message, SSLRequest/GSSENCRequest, binary-format masked column,
  COPY, Wasm timeout/invalid-response, oversized Wasm output) — every one of
  these paths was read end-to-end and confirmed to (a) write a real
  PostgreSQL `ErrorResponse` before closing, (b) never silently forward
  unvalidated/unmasked bytes, and (c) never leave the connection half-open
  waiting on a blocked peer. Confirmed by both code inspection and the
  corresponding existing tests (`TestGate_MalformedMessage_...`,
  `TestTransformer_BinaryFormatColumnFailsClosed`,
  `TestTransformer_CopyProtocolFailsClosed`, `TestRuntime_TimeoutFailsClosed`,
  `TestRuntime_OversizedOutputFailsClosed`, etc.) all passing.
- **Connection/goroutine lifecycle** — every `go func()` in the repository
  (7 in `cmd/gateway/main.go`) is accounted for: the metrics/API server
  goroutines are joined via `httpWG.Wait()` during shutdown, the two
  per-connection `gate.Run`/`transformer.Run` goroutines are joined via a
  per-connection `sync.WaitGroup`, and the top-level accept loop is joined
  via the top-level `wg.Wait()` after `listener.Accept()` unblocks with an
  error post-`ctx.Done()`. No orphaned goroutines were found. Shutdown
  correctly force-closes all tracked client/upstream `net.Conn`s
  (`activeConns.closeAll()`) before waiting, unblocking any in-flight
  blocked `Read`s so `Run()` calls return promptly — this was specifically
  checked for deadlock risk and found correct.
- **Wasm invocation cancellation/leaks** — `wazero.RuntimeConfig.WithCloseOnContextDone(true)`
  plus a per-call `context.WithTimeout` bounds every plugin call; every
  `InstantiateModule` result has its `mod.Close(context.Background())`
  deferred unconditionally (even on instantiation error, guarded by
  `if mod != nil`), so no Wasm module instance can leak. Verified by
  `TestRuntime_TimeoutFailsClosed` and by reading `Runtime.call` directly.
- **Bounded buffers** — `internal/wasm/bounded_buffer.go`'s `boundedBuffer`
  caps stdout/stderr *while the plugin writes* (never collects unbounded
  then truncates), and `internal/protocol`'s `maxMessageLength`/`maxCellValueSize`
  (1 MiB) and `internal/wasm`'s `maxMaskedValueSize` (64 KiB) bound every
  other untrusted-size input. No unbounded-allocation path was found for any
  attacker-controlled length field.
- **No double-counting of metrics** — `sentineldb_masking_errors_total` is
  incremented in exactly one place (`OnError`, never in `OnMaskAttempt`'s
  error branch), confirmed by both code reading and the dedicated
  `TestTransformer_HookPattern_*` test group, which exists specifically to
  prove this invariant.
- **Dashboard polling** (`dashboard/src/App.jsx`, `dashboard/src/api.js`) —
  polling is sequential (`setTimeout`-chained after each request resolves,
  not `setInterval`), so requests cannot overlap; `activeRef` guards against
  a late response updating state after unmount; `fetchStatus` uses an
  `AbortController` with a 5s timeout, shorter than the 3s poll interval
  would allow to stack up. Verified live: the dashboard container reported
  `healthy` and served the live counters correctly (§5).
- **CORS scope** — `/api/status` is the only exposed endpoint, is read-only
  (rejects non-`GET`), and contains no data beyond what's already visible in
  `config.yaml` (rule list, aggregate counters) — the permissive
  `Access-Control-Allow-Origin: *` matches the documented local-demo
  threat model (`docs/threat-model.md`) and does not expose anything a
  same-network attacker couldn't already see via `/metrics` or the config
  file.
- **Metric name consistency** — `sentineldb_connections_total`,
  `sentineldb_blocked_queries_total`, `sentineldb_masked_cells_total`,
  `sentineldb_masking_errors_total`, `sentineldb_masking_plugin_duration_seconds`
  match verbatim across `internal/metrics/metrics.go`, `README.md`,
  `docs/architecture.md`, and the actual live `/metrics` output/Prometheus
  target (verified in §5) — no drift found.
- **Grafana/Prometheus provisioning** — `deploy/prometheus/prometheus.yml`'s
  scrape target (`sentineldb:9090`) and `deploy/grafana/provisioning`'s
  datasource/dashboard reference only the real, currently-emitted metric
  names above; verified live that the Grafana "SentinelDB Overview"
  dashboard and Prometheus datasource are both auto-provisioned and that the
  `sentineldb` scrape target reports `health: "up"` (§5).
- **Demo credentials** — `docker-compose.yml`'s Postgres
  (`sentineldb_demo`/`demo_only_change_me`) and Grafana
  (`admin`/`admin_demo_only`) credentials are clearly named/labeled as
  demo-only in the compose file itself, `README.md`, `docs/operations.md`,
  and `SECURITY.md`; no other secret, token, or private key was found
  anywhere in tracked files (see §6 for the search method).
- **All Docker host ports bound to `127.0.0.1`** — reconfirmed directly from
  `docker compose config`'s resolved output (§5): all five services'
  published ports use `host_ip: 127.0.0.1`, none bind `0.0.0.0` or an
  unqualified port.
- **Wasm plugin reproducibility** — `plugins/firewall/v2.wasm` was rebuilt
  from the exact committed source using the documented command
  (`GOOS=wasip1 GOARCH=wasm go build -o ... ./plugins/firewall`), the
  rebuilt binary was swapped in for the committed one, and the *entire*
  `internal/wasm` test suite (including the plugin-output-leak and
  oversized-output tests) was re-run against it and passed unchanged. The
  original committed binary was restored afterward with no diff. Go
  binaries are not byte-for-bit reproducible by default (embedded build
  ID/timestamp), which is why the SHA-256 hashes differ, but this is not a
  claim the documentation makes anywhere — "reproducibly buildable" means
  "rebuildable into a working, behaviorally-identical module from committed
  source," which was proven functionally.
- **Documentation truth-check** — `README.md`, `CHANGELOG.md`, `SECURITY.md`,
  `CONTRIBUTING.md`, and all seven `docs/*.md` files were each compared
  line-by-line against the actual implementation they describe. No
  overstated, outdated, or missing-limitation claim was found. All required
  prominent limitations (experimental V0, not production-ready, Simple
  Query only, Extended Query rejected, plaintext dev mode, no COPY, UTF-8
  assumption, keyword firewall is not a SQL security boundary, alias-based
  masking limitation) are present, accurate, and appropriately prominent —
  in particular `docs/threat-model.md`'s "Known bypass limitations" section
  already explicitly documents the alias/rename masking-bypass limitation.
  No fixes were needed in this area.

---

## 3. Known V1 limitations intentionally not fixed

These are documented, deliberate V1 scope boundaries. Per the audit brief,
they were **verified as accurately and visibly documented**, not "fixed":

- Extended Query Protocol is rejected, not supported (`docs/postgresql-protocol.md`,
  `README.md`).
- No TLS termination; SSLRequest/GSSENCRequest are always rejected, traffic
  is always plaintext (`docs/threat-model.md`'s "Plaintext development
  limitation").
- No COPY protocol support; COPY responses fail closed.
- UTF-8 is assumed for masked cell values; other encodings are not
  validated.
- Blocked-phrase matching is plain substring matching
  (`internal/sqlmatch`), not real SQL parsing — explicitly documented as
  bypassable and not a SQL security boundary.
- Masking matches exact `RowDescription` column names only; a renamed or
  aliased column (`SELECT email AS e`) defeats the match — explicitly
  documented in `docs/threat-model.md`'s "Known bypass limitations."
- `internal/protocol/sniffer.go` (`SniffReader`) is dead, untested code left
  over from a prior (pre-`Gate`/`Transformer`) architecture. It is
  functionally inert (zero call sites) and does not affect runtime
  behavior, but its removal was not carried out in this pass (see §1.3) —
  flagged for an explicit maintainer decision rather than unilateral
  deletion of a tracked file outside the audit's proven-inconsistency scope.
- No connection-rate limiting, per-client quotas, or query-complexity
  limiting — documented in `docs/threat-model.md`'s "Denial-of-service
  risks" as an accepted V1 gap.

---

## 4. V2 recommendations

Not implemented (out of scope for this audit), but worth recording for a
future version:

- Extended Query Protocol support with correct Parse/Bind/Execute and
  post-error `Sync`-resync semantics.
- TLS termination between client and gateway.
- A real SQL-aware statement classifier to replace/augment substring
  matching for the firewall policy.
- Schema-aware or pattern-based masking that survives column aliasing/
  renaming (would require tracking source-table/column provenance beyond
  what `RowDescription` alone provides).
- Wasm module-instance pooling: `docs/benchmarks.md` already identifies
  per-call WASI instantiation (~3.3ms, ~43,700 allocations per call) as the
  dominant cost by three orders of magnitude over native parsing; pooling
  compiled instances would be the highest-leverage performance work.
- Connection-level rate limiting / per-client quotas.
- Formal removal (or an explicit decision to keep and re-wire) of the dead
  `SniffReader` type in `internal/protocol/sniffer.go`.

---

## 5. Commands and evidence used

All run from the repository root on the audit machine (Windows 11 Pro,
`go1.26.5 windows/amd64`, Docker 29.6.1 / Compose v5.2.0, Node v22.20.0,
npm 10.9.3) unless noted otherwise.

| Command | Result |
|---|---|
| `git status` / `git fetch origin --tags` / `git rev-parse main origin/main v0.1.0^{commit}` | Clean tree (aside from an untracked, non-repository scratch file `sentineldb_all_code.txt`, left as-is); local `main` == `origin/main` == `v0.1.0` (annotated tag), all at `ae532e9`. |
| `go mod verify` | `all modules verified` |
| `go build ./...` | Clean |
| `go vet ./...` | Clean |
| `gofmt -l .` | Clean (after `.gitattributes` fix — see §1.4; **before** the fix, listed ~35 files as a CRLF-checkout artifact, not a real content issue) |
| `go test ./...` | All packages pass |
| `go test -fuzz=FuzzParseDataRow -fuzztime 8s`, same for `FuzzParseRowDescription`, `FuzzDecoderWrite` | 0 crashes across ~2.86M total executions |
| `go test -race ./...` | **Could not run locally** — exact error: `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1`. This machine has `CGO_ENABLED=0` and no `gcc`/`cc` on `PATH`. Per the audit brief, no compiler was installed to force this; `.github/workflows/ci.yml`'s `go-race` job (runs on `ubuntu-latest`, which ships a C toolchain) is the source of truth for race detection and was reviewed (present, unmodified, runs `go test -race ./...` with a 15-minute timeout). |
| `docker compose config` | Valid; all five services' published ports confirmed `host_ip: 127.0.0.1` |
| `docker compose build` | Both images (`sentineldb`, `dashboard`) built successfully |
| `docker compose up -d` / `docker compose ps` | All five services reached `healthy`/`running` |
| `.\scripts\e2e-demo.ps1` (Windows PowerShell 5.1, no `-Cleanup`) | **Passed** — direct PostgreSQL query returned `john@example.com`; SentinelDB gateway query returned `jo****@example.com` |
| `curl http://127.0.0.1:9091/api/v1/targets` | `sentineldb` target `health: "up"` |
| `curl http://127.0.0.1:8080/api/status` | Valid JSON matching the documented `Status` schema |
| `curl -I http://127.0.0.1:5173/` | `200 OK` (dashboard reachable) |
| `curl -u admin:admin_demo_only http://127.0.0.1:3000/api/datasources` and `/api/search` | Prometheus datasource and "SentinelDB Overview" dashboard both provisioned |
| `docker compose logs sentineldb \| grep -iE "password\|john@example\|demo_only_change_me\|SELECT"` | No matches beyond `PasswordMessage (uzunluk=N)` length-only log lines — no query text, cell values, or credentials found in logs |
| `docker compose down` | Clean teardown |
| `npm ci` / `npm run build` (in `dashboard/`) | Both clean |
| `npm audit` (in `dashboard/`) | `found 0 vulnerabilities` |
| Rebuild `plugins/firewall/v2.wasm` from source, swap in, re-run `go test ./internal/wasm/...`, restore original | Rebuilt binary passed the full `internal/wasm` suite; original restored, `git status` clean afterward |
| Repository-wide search for tracked `*.exe`/`node_modules`/`dist`/`.env`/binaries, `TODO`/`FIXME` markers | None found |

---

## 6. Remaining uncertainty

- **`-race` was not run locally** for the reason stated above (§5); CI's
  Linux `go-race` job is the authoritative source and was reviewed (present,
  correctly configured) but its live pass/fail result for this exact commit
  was not re-observed as part of this local audit session.
- **`sentineldb_all_code.txt`** — an untracked ~225 KB file at the
  repository root (a full source dump, evidently created by the
  repository's owner for some external purpose, e.g. pasting into another
  tool). It is not part of git history, is already excluded from any commit
  by virtue of being untracked, and was left untouched. It does not affect
  the correctness of anything audited here, but is worth the maintainer's
  attention if it isn't intentional — see also `.gitignore`, which does not
  currently exclude this filename pattern.
- **`internal/protocol/sniffer.go`** — confirmed dead/unreferenced (§1.3,
  §3), but not removed pending an explicit maintainer decision (file
  deletion of a pre-existing tracked file was outside what this audit
  session could do unilaterally).
- **Benchmark numbers in `docs/benchmarks.md`** were not independently
  re-run/re-verified as part of this audit (the document itself already
  carries appropriate single-machine/single-run caveats); only the
  benchmark *fixtures* were reviewed for representativeness (§5's build/test
  runs incidentally re-compiled these packages but did not re-execute
  `-bench`).
- No fuzzing beyond the three new bounded 8-second local runs (§1.5) was
  performed; a longer/CI-integrated fuzz corpus was explicitly out of scope
  per the audit brief ("do not launch long-running fuzz campaigns").

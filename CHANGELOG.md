# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project does not yet follow strict Semantic Versioning guarantees —
see [V1 limitations](README.md#v1-limitations-be-aware-of-these-before-using-this-anywhere-real)
for what "0.x" means here.

## [Unreleased]

Release-readiness housekeeping for the v0.1.0 tag: license, changelog,
contributor/security docs, technical documentation (`docs/`), Go
benchmarks, GitHub Actions CI, and repository templates. No product
behavior changed.

## [0.1.1] - 2026-07-11

Patch release covering the final V0.1 internal audit
(`docs/audit-v0.1.md`). This release **adds no product capabilities** and
does **not** change the documented V1 protocol support
(`docs/postgresql-protocol.md`) — it is hardening and repository-hygiene
only.

### Fixed

- **Config parsing now strictly rejects unknown YAML fields.**
  `config.Load` (`internal/config/config.go`) previously used a lenient
  YAML unmarshal that silently ignored unrecognized keys (e.g. a typo in
  `config.yaml`); it now uses a strict decoder that fails loudly on any
  unknown top-level or nested field.
- **HTTP servers now have read/write/header/idle timeouts.** The metrics
  (`/metrics`) and status API (`/api/status`) `http.Server` instances in
  `cmd/gateway/main.go` previously had no timeouts configured, leaving them
  exposed to slow-client resource exhaustion; both now set
  `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, and `IdleTimeout`.
- **Repository-wide LF line-ending normalization.** Added `.gitattributes`
  so Go source and other text files always check out with `LF` line
  endings, regardless of the checking-out machine's Git configuration —
  previously, a common Windows Git default could check files out as
  `CRLF`, causing the documented `gofmt -l .` verification step to report
  false positives.

### Added

- **Bounded fuzz coverage for the PostgreSQL wire-protocol parsers.** Added
  small, bounded `go test -fuzz` targets for `ParseDataRow`,
  `ParseRowDescription`, and `Decoder.Write`, seeded from the existing test
  corpus, to guard the "never panics on untrusted input" invariant.
- **Final V0.1 internal audit report** (`docs/audit-v0.1.md`): a
  full-repository compile/API-consistency, runtime-safety, protocol,
  security, memory/performance, HTTP/dashboard, and documentation-accuracy
  audit, including confirmed-safe findings, intentionally-unfixed V1
  limitations, and V2 recommendations.

## [0.1.0] - 2026-07-11

Initial released version of SentinelDB: a PostgreSQL wire-protocol gateway
that enforces a query firewall and masks PII in query results, using
sandboxed WebAssembly for the decision/masking logic.

### Added

- **PostgreSQL TCP gateway**: a transparent proxy clients connect to
  instead of PostgreSQL directly, forwarding allowed traffic unchanged.
- **Simple Query Protocol support**: parses and inspects the single `'Q'`
  frontend message; the Extended Query Protocol (Parse/Bind/Describe/
  Execute/Close/Flush/Sync) is explicitly rejected rather than silently
  passed through.
- **Wasm query policy execution**: firewall decisions (`evaluate_query`)
  run inside a sandboxed WebAssembly module (`plugins/firewall`, run via
  [wazero](https://github.com/tetratelabs/wazero)) rather than as native
  Go code, evaluated against a configurable blocked-phrase list
  (`config.yaml`).
- **RowDescription and DataRow parsing**: a dedicated wire-protocol
  decoder (`internal/protocol`) parses backend `RowDescription`/`DataRow`
  messages so that individual result columns can be inspected and
  rewritten.
- **Response-side email masking**: columns configured in
  `masking.columns` (currently `email`) are masked in-flight via the same
  Wasm module's `mask_value` operation, matched by exact,
  case-insensitive column name — no regex or schema discovery.
- **Prometheus metrics**: `sentineldb_connections_total`,
  `sentineldb_blocked_queries_total`, `sentineldb_masked_cells_total`,
  `sentineldb_masking_errors_total`, and
  `sentineldb_masking_plugin_duration_seconds`, exposed on `/metrics`.
  A read-only JSON status API (`/api/status`) is also included.
- **React dashboard**: a small Vite-built dashboard that polls
  `/api/status` and displays live connection/blocking/masking counters
  and the active firewall rule list.
- **Grafana dashboard**: a provisioned "SentinelDB Overview" dashboard
  and Prometheus datasource (`deploy/grafana`), wired to the Prometheus
  instance in the Compose stack automatically.
- **Docker Compose demo stack**: `postgres`, `sentineldb`, `prometheus`,
  `grafana`, and `dashboard` services (`docker-compose.yml`), with all
  published host ports bound to `127.0.0.1`, plus a scripted end-to-end
  masking demo (`scripts/e2e-demo.ps1`).
- **Fail-closed behavior for unsupported protocol paths**: any parse
  error, unsupported protocol path (Extended Query, COPY, binary-format
  columns), or Wasm plugin failure closes the connection with an
  explanatory PostgreSQL `ErrorResponse` instead of forwarding
  unvalidated or unmasked data.

### Known limitations

- **Extended Query Protocol rejected.** Clients/drivers that default to
  it (e.g. `pgx`, `psycopg`'s prepared-statement mode) must be configured
  to use simple-protocol execution, or they receive a `FATAL` error.
- **Plaintext development mode.** `SSLRequest`/`GSSENCRequest` are
  rejected so the gateway can always inspect traffic; there is no TLS
  termination. Do not expose this to an untrusted network.
- **No COPY protocol support.** Connections attempting `COPY` fail
  closed.
- **UTF-8 is assumed.** Masking logic operates on `[]rune`; other client
  encodings are not validated or supported.
- **Experimental and not production-ready.** This is a V1 MVP: no
  third-party security audit, no load testing, no high-availability
  story. See [SECURITY.md](SECURITY.md) and
  [docs/threat-model.md](docs/threat-model.md).

[Unreleased]: https://github.com/gkurcaloglu/SentinelDB/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/gkurcaloglu/SentinelDB/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/gkurcaloglu/SentinelDB/releases/tag/v0.1.0

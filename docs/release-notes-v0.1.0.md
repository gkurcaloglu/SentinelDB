# SentinelDB v0.1.0 release notes

**Status: experimental (V0/V1 MVP).** This is the first tagged version of
SentinelDB. It is a working prototype suitable for local experimentation,
demos, and further development — not a production security control. See
[SECURITY.md](../SECURITY.md) and [docs/threat-model.md](threat-model.md)
before considering it for anything beyond that.

## What SentinelDB v0.1.0 is

A PostgreSQL wire-protocol gateway that sits between a client and a real
PostgreSQL server. Clients connect to SentinelDB instead of PostgreSQL
directly; SentinelDB forwards allowed traffic unchanged and:

- evaluates each Simple Query Protocol statement against a configurable
  blocked-phrase firewall policy, executed inside a sandboxed WebAssembly
  module, and
- masks configured result columns (currently `email`) in the rows
  returned to the client, also via the same Wasm module.

## Capabilities in this release

- **PostgreSQL TCP gateway** — transparent proxy, `SENTINELDB_LISTEN_ADDR`
  / `SENTINELDB_TARGET_ADDR` configurable via environment variables.
- **Simple Query Protocol support** — the single `'Q'` frontend message is
  parsed and inspected.
- **Wasm query policy execution** — `evaluate_query` runs inside
  `plugins/firewall/v2.wasm` via [wazero](https://github.com/tetratelabs/wazero),
  evaluated against `config.yaml`'s `firewall.blocked_phrases`.
- **RowDescription and DataRow parsing** — `internal/protocol` decodes
  backend result-set framing so individual cells can be inspected.
- **Response-side email masking** — columns listed in `masking.columns`
  are rewritten in-flight via the Wasm module's `mask_value` operation
  (exact, case-insensitive column-name match; no regex, no schema
  discovery).
- **Prometheus metrics** — `sentineldb_connections_total`,
  `sentineldb_blocked_queries_total`, `sentineldb_masked_cells_total`,
  `sentineldb_masking_errors_total`,
  `sentineldb_masking_plugin_duration_seconds` on `/metrics`; a read-only
  JSON status API on `/api/status`.
- **React dashboard** — polls `/api/status` and shows live counters and
  the active firewall rule list.
- **Grafana dashboard** — a provisioned "SentinelDB Overview" dashboard
  and Prometheus datasource, no manual setup required.
- **Docker Compose demo stack** — `postgres`, `sentineldb`, `prometheus`,
  `grafana`, `dashboard`, all published host ports bound to `127.0.0.1`,
  plus a scripted end-to-end masking demo
  ([scripts/e2e-demo.ps1](../scripts/e2e-demo.ps1)).
- **Fail-closed behavior** for every unsupported or unparseable protocol
  path: the connection is closed with an explanatory PostgreSQL
  `ErrorResponse` rather than forwarding unvalidated or unmasked data.

## Known limitations in this release

- **Extended Query Protocol is rejected**, not supported. Parse/Bind/
  Describe/Execute/Close/Flush/Sync all receive a `FATAL` error. Clients
  or drivers that default to prepared statements (e.g. `pgx`, `psycopg`
  in prepared mode) must be configured to use simple-protocol execution.
- **Plaintext development mode.** `SSLRequest`/`GSSENCRequest` are
  rejected with `'N'` so the gateway can always inspect plaintext
  traffic. There is no TLS termination in this release — do not expose
  SentinelDB to an untrusted network without adding your own TLS layer
  in front of it.
- **No COPY protocol support.** Connections attempting `COPY` fail
  closed; COPY data streams are not parsed or masked.
- **UTF-8 is assumed.** Masking operates on `[]rune`; other client
  encodings are not validated or supported.
- **Experimental — not production-ready.** No third-party security
  audit, no load testing, no high-availability story. Masking is a
  literal exact-column-name rule, not data discovery or classification.
  No claim of GDPR/KVKK/PCI or any other regulatory compliance.

## Upgrade notes

This is the first release; there is no prior version to upgrade from.

## Where to go next

- [README.md](../README.md) — quick start, configuration, metrics
- [docs/architecture.md](architecture.md) — system design and data flow
- [docs/postgresql-protocol.md](postgresql-protocol.md) — exact protocol
  support
- [docs/plugin-api.md](plugin-api.md) — Wasm plugin contract
- [docs/threat-model.md](threat-model.md) — assets, trust boundaries,
  known bypasses
- [docs/operations.md](operations.md) — running and operating the demo
  stack
- [CHANGELOG.md](../CHANGELOG.md) — full change list

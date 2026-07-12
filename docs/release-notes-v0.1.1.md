# SentinelDB v0.1.1 release notes

**Status: experimental (V0/V1 MVP) — unchanged from v0.1.0.** This remains a
working prototype suitable for local experimentation, demos, and further
development — **not** a production security control. See
[SECURITY.md](../SECURITY.md) and [docs/threat-model.md](threat-model.md)
before considering it for anything beyond that.

## Purpose of this patch

v0.1.1 is a hardening and repository-hygiene patch produced from the final
V0.1 internal audit (see [docs/audit-v0.1.md](audit-v0.1.md) for the full
report). **It adds no product capabilities and does not change the
documented V1 protocol support** — the
[Supported / unsupported protocol table](../README.md#supported--unsupported-protocol)
and [docs/postgresql-protocol.md](postgresql-protocol.md) still describe
this release exactly. Nothing here changes what SentinelDB does; it changes
how strictly and safely it does it.

## Fixed issues

- **Config parsing now strictly rejects unknown YAML fields.**
  `config.Load` previously used a lenient YAML unmarshal that silently
  ignored unrecognized keys — a typo or misplaced key in `config.yaml`
  (e.g. under `firewall:` or `masking:`) could silently produce a
  different effective configuration than intended, with no error. It now
  uses a strict decoder that fails loudly (config load error) on any
  unknown top-level or nested field. An empty `config.yaml` file remains
  valid, unchanged from prior behavior.
- **HTTP servers now have read/write/header/idle timeouts.** The metrics
  (`/metrics`) and status API (`/api/status`) servers previously had no
  timeouts configured, which could allow a slow or stalled client
  connection to hold a server goroutine open indefinitely. Both servers
  now set `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, and
  `IdleTimeout` to generous but bounded values; this is not observable in
  normal use (the demo stack's healthchecks and the dashboard's own 5s
  request timeout are well within the new bounds).
- **Repository-wide LF line-ending normalization.** Added a
  `.gitattributes` file so tracked text files (Go source included) always
  check out with `LF` line endings on any machine. Previously, a common
  Windows Git default (`core.autocrlf=true`) could check the repository
  out with `CRLF` line endings, which caused the documented `gofmt -l .`
  verification command in [README.md](../README.md) and
  [CONTRIBUTING.md](../CONTRIBUTING.md) to falsely report nearly every Go
  file as unformatted. No committed file content changed — this only
  affects how future clones are checked out.

## Added

- **Bounded fuzz coverage for the PostgreSQL wire-protocol parsers.** Added
  `go test -fuzz` targets for `ParseDataRow`, `ParseRowDescription`, and
  `Decoder.Write`, seeded from the existing correctness-test corpus, to
  guard the "never panics on untrusted/malformed input" invariant that
  [docs/postgresql-protocol.md](postgresql-protocol.md) already documents.
  These run as ordinary fast tests under plain `go test ./...`; no
  long-running fuzz campaign was performed or is required to reproduce
  this work.
- **Final V0.1 internal audit report**
  ([docs/audit-v0.1.md](audit-v0.1.md)): a full-repository review covering
  compile/API consistency, runtime safety (panics, races, leaks,
  deadlocks, shutdown paths), PostgreSQL protocol handling, security
  posture, memory/performance correctness, HTTP/metrics/dashboard
  behavior, and documentation accuracy — with confirmed-safe findings,
  intentionally-unfixed V1 limitations, and V2 recommendations, each
  backed by a reproducible command or code citation.

## Verification performed

- `gofmt -l .`, `go mod verify`, `go build ./...`, `go vet ./...`,
  `go test ./...` — all clean.
- `go test -fuzz` runs (8 seconds each, ~2.86M total executions across the
  three new targets) — zero crashes found.
- `docker compose config`, `docker compose build`, `docker compose up -d`
  — full five-service stack reaches `healthy`.
- `scripts/e2e-demo.ps1` (Windows PowerShell 5.1) — end-to-end masking
  demo passes: direct PostgreSQL query returns `john@example.com`; the
  SentinelDB gateway query returns `jo****@example.com`.
- Prometheus target health, Grafana datasource/dashboard provisioning, and
  dashboard reachability — all verified live.
- Gateway container logs scanned for query text, cell values, and
  credentials — none found, consistent with the documented sensitive
  logging policy.
- `npm ci`, `npm run build`, `npm audit` (in `dashboard/`) — all clean,
  zero vulnerabilities.
- Full diff scanned for secrets and generated/junk files before this
  release was prepared — none found.

See [docs/audit-v0.1.md](audit-v0.1.md) for the complete command list,
evidence, and remaining uncertainty notes.

## Unchanged V1 limitations

Everything documented as a V1 limitation in the
[v0.1.0 release notes](release-notes-v0.1.0.md) still applies, unchanged:

- **Extended Query Protocol is rejected**, not supported. Parse/Bind/
  Describe/Execute/Close/Flush/Sync all receive a `FATAL` error.
- **Plaintext development mode.** `SSLRequest`/`GSSENCRequest` are
  rejected with `'N'`; there is no TLS termination in this release.
- **No COPY protocol support.** Connections attempting `COPY` fail
  closed.
- **UTF-8 is assumed.** Masking operates on `[]rune`; other client
  encodings are not validated or supported.
- **Keyword-based firewall is not a SQL security boundary.**
  Blocked-phrase matching is plain substring matching
  (`internal/sqlmatch`), not real SQL parsing, and is documented as
  bypassable by a motivated client.
- **Masking matches exact column names only.** A renamed or aliased
  column (`SELECT email AS e`) defeats the match; see
  [docs/threat-model.md](threat-model.md#known-bypass-limitations).
- **Experimental — not production-ready.** No third-party security audit,
  no load testing, no high-availability story. No claim of GDPR/KVKK/PCI
  or any other regulatory compliance.

## Upgrade instructions

This is a source-only patch release; no config, schema, or data migration
is required.

```powershell
# Fetch the new source/tag
git fetch origin --tags
git checkout v0.1.1

# Rebuild and restart the Docker Compose demo stack
docker compose up -d --build
```

If you run the gateway outside Docker, rebuild the Go binary as usual:

```powershell
go build ./cmd/gateway
```

The Wasm plugin (`plugins/firewall/v2.wasm`) is unchanged in this release;
no rebuild of it is required, but
[scripts/build-wasm-plugins.ps1](../scripts/build-wasm-plugins.ps1) remains
the documented way to rebuild it if you ever modify `plugins/firewall/`
source.

## Status

SentinelDB v0.1.1 **remains experimental and not production-ready**, exactly
as v0.1.0 was. This patch improves internal robustness and repository
hygiene; it does not change the project's security posture, scope, or
suitability for production use. See [SECURITY.md](../SECURITY.md) and
[docs/threat-model.md](threat-model.md) before using it for anything beyond
local experimentation and demos.

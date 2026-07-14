# Contributing to SentinelDB

Thanks for your interest in SentinelDB. This is an experimental V0/V1
project (see [README.md](README.md#v1-limitations-be-aware-of-these-before-using-this-anywhere-real)
and [SECURITY.md](SECURITY.md)) — contributions are welcome, but please
keep changes scoped and in line with what the project actually is today.

## Required tools

- **Go** — version matching [go.mod](go.mod) (currently `1.26.x`).
  `go build`/`go vet`/`go test` are used throughout; no other Go tooling
  is required.
- **Node.js** — a version compatible with `dashboard/package.json`
  (Vite 8, React 19) for the dashboard. Use whatever LTS Node you have;
  CI pins an exact version (see `.github/workflows/`).
- **Docker Desktop** (or Docker Engine + Compose v2) — for the demo
  stack and end-to-end verification.
- **PowerShell** — the helper scripts (`scripts/*.ps1`) are PowerShell.
  They are written to run under both PowerShell 7+ (`pwsh`) and Windows
  PowerShell 5.1 (`powershell`); do not add PS7-only syntax
  (ternary/null-coalescing operators, `&&`/`||` chaining, etc.) without
  checking both.

## Local setup

```powershell
git clone https://github.com/gkurcaloglu/SentinelDB.git
cd SentinelDB
go build ./...
```

The gateway itself needs a real PostgreSQL instance to proxy to
(`SENTINELDB_TARGET_ADDR`, default `localhost:5433`); the easiest way to
get one plus the full observability stack is the Docker Compose demo
below.

## Go testing

```powershell
gofmt -l .
go build ./...
go vet ./...
go test ./...
```

`go test -race ./...` requires a cgo-capable C toolchain; if you don't
have one installed locally, rely on the CI race job (`.github/workflows/`)
instead of trying to force it locally.

## Dashboard testing/build

```powershell
cd dashboard
npm ci
npm run build
npm run lint    # oxlint
```

`npm run dev` starts a local Vite dev server against
`VITE_API_BASE_URL` (defaults to `http://localhost:8080`) if you want to
iterate on the UI against a gateway you're already running.

## Rebuilding the Wasm plugin

The firewall/masking logic in `plugins/firewall` compiles to the
`plugins/firewall/v2.wasm` binary, which is checked into git and loaded
by the gateway at startup. After changing anything under
`plugins/firewall/`, rebuild it and commit the updated binary:

```powershell
pwsh scripts/build-wasm-plugins.ps1
```

Do not hand-edit `plugins/firewall/v2.wasm`; it must always be the
output of this build step from the corresponding source.

## Docker Compose demo

```powershell
docker compose up -d --build
docker compose ps          # wait for postgres/sentineldb to be healthy

# PowerShell 7+
pwsh scripts/e2e-demo.ps1 -Cleanup
# Windows PowerShell 5.1
powershell -ExecutionPolicy Bypass -File .\scripts\e2e-demo.ps1 -Cleanup
```

See [docs/operations.md](docs/operations.md) for port bindings, health
checks, and troubleshooting.

## pgx driver-compatibility testing

If you changed anything under `internal/gateway`, `internal/firewall`,
`internal/protocol`, or `integration/pgxcompat` itself, run the real
driver-compatibility suite against a real PostgreSQL server before
opening a PR:

```powershell
pwsh scripts/driver-compat.ps1                     # PostgreSQL 16
pwsh scripts/driver-compat.ps1 -PostgresVersion 18  # PostgreSQL 18
```

This starts a dedicated Docker Compose stack
([deploy/driver-compat](deploy/driver-compat), entirely separate from the
demo stack above) and runs `integration/pgxcompat` — a real,
unmodified, stable `github.com/jackc/pgx/v5` driver against it. That
package is its own nested Go module (its own `go.mod`/`go.sum`) so pgx
never becomes a dependency of the root module or the production gateway
binary; `go build ./...`/`go test ./...` from the repository root never
need it. See
[docs/postgresql-protocol.md](docs/postgresql-protocol.md#pgx-v5-driver-compatibility)
for what the suite covers.

## Branch and commit expectations

- Branch off `main`; do not commit directly to `main`.
- Keep commits scoped to one logical change; write commit messages that
  explain *why*, not just what changed.
- Run the Go and dashboard checks above (and the Docker/E2E flow if you
  touched anything under `docker-compose.yml`, `Dockerfile`,
  `dashboard/`, or `scripts/`) before opening a pull request.
- Rebuild `plugins/firewall/v2.wasm` in the same commit if you changed
  `plugins/firewall/` source.

## Scope discipline

This repository intentionally does **not** yet include: Extended Query
Protocol support, TLS termination, COPY protocol support, AI-based
classification, RBAC, Kubernetes manifests, or a SaaS/multi-tenant
control plane. These are tracked in the [README roadmap](README.md#roadmap).
Please open an issue to discuss scope **before** sending a large PR that
adds one of these — small, focused PRs that fit the current V1 design
are much easier to review and merge than large speculative ones.

If you're fixing a bug or hardening existing behavior, avoid bundling in
unrelated refactors, dependency upgrades, or new abstractions — see the
existing code style (fail-closed on any ambiguity, no silent fallback
behavior, comments explain *why* not *what*) and match it.

## How to submit a pull request

1. Fork the repository and create a branch off `main`.
2. Make your change, keeping it scoped per the guidance above.
3. Run the relevant checks locally (Go tests/vet/build, dashboard build,
   Docker/E2E if applicable).
4. Open a pull request against `main` describing what changed and why.
   Reference any related issue.
5. CI (GitHub Actions) will run the Go quality/race jobs, the dashboard
   build, and the Docker/E2E jobs automatically — make sure they pass.
6. Be responsive to review feedback; small, incremental follow-up
   commits are preferred over force-pushed rewrites once a review is
   underway.

For security-sensitive reports, do **not** open a public issue or PR —
see [SECURITY.md](SECURITY.md).

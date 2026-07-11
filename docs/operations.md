# Operations

How to start, stop, inspect, configure, and troubleshoot the SentinelDB
demo stack. This describes the Docker Compose deployment
(`docker-compose.yml`) that ships with the repository; see
[architecture.md](architecture.md) for how the gateway itself is built
and [threat-model.md](threat-model.md) for why every host port below is
bound to `127.0.0.1` only.

## Docker startup

```powershell
docker compose up -d --build
```

This builds (if needed) and starts five services: `postgres`,
`sentineldb`, `prometheus`, `grafana`, `dashboard`.

Rebuild only the gateway image after a code change:

```powershell
docker compose build sentineldb
docker compose up -d sentineldb
```

## Docker shutdown

```powershell
docker compose down
```

Stops and removes the containers and the default network, but **does
not** remove the `pgdata` named volume — demo data persists across
`down`/`up` cycles. See
[data-volume cleanup warning](#data-volume-cleanup-warning) below if you
actually want to reset it.

## Health checks

```powershell
docker compose ps
```

`postgres` and `sentineldb` both have Docker healthchecks and should
report `healthy` within about 10 seconds of a clean start:

- `postgres`: `pg_isready -U $POSTGRES_USER -d $POSTGRES_DB` every 5s.
- `sentineldb`: `wget -q -O- http://127.0.0.1:8080/api/status` every
  10s (`start_period: 5s`).

`prometheus`, `grafana`, and `dashboard` have no explicit Docker
healthcheck in this stack; use the [troubleshooting](#troubleshooting)
checks below to verify them directly.

## Service ports

All published host ports are bound explicitly to `127.0.0.1` (loopback
only) — reachable from the machine running Docker, not from other hosts
on the network:

| Service | Container port | Host port | Purpose |
|---|---|---|---|
| `postgres` | 5432 | `127.0.0.1:5433` | Direct access to the real database (demo/verification only) |
| `sentineldb` | 5432 | `127.0.0.1:5432` | PostgreSQL gateway (Simple Query Protocol) |
| `sentineldb` | 8080 | `127.0.0.1:8080` | Read-only status API (`/api/status`) |
| `sentineldb` | 9090 | `127.0.0.1:9090` | Prometheus metrics (`/metrics`) |
| `prometheus` | 9090 | `127.0.0.1:9091` | Prometheus UI |
| `grafana` | 3000 | `127.0.0.1:3000` | Grafana UI |
| `dashboard` | 8080 | `127.0.0.1:5173` | React monitoring dashboard |

Container-to-container traffic (`sentineldb` → `postgres`,
`prometheus`/`grafana` → `sentineldb`) is unaffected by the loopback
binding and continues to use Docker service names on the internal
`sentineldb-net` bridge network.

## Configuration

The gateway reads `config.yaml` once at startup (see
[architecture.md's configuration flow](architecture.md#configuration-flow)
for the full picture). In Compose, `config.yaml` and
`plugins/firewall/v2.wasm` are bind-mounted read-only into the
`sentineldb` container, so you can iterate on the blocked-phrase list or
masked-column list without rebuilding the image — just restart the
service to pick up the change:

```powershell
docker compose restart sentineldb
```

Network addresses are environment-variable driven (Compose values shown
alongside the local/non-Docker defaults):

| Env var | Default | Compose value |
|---|---|---|
| `SENTINELDB_LISTEN_ADDR` | `localhost:5432` | `0.0.0.0:5432` |
| `SENTINELDB_TARGET_ADDR` | `localhost:5433` | `postgres:5432` |
| `SENTINELDB_METRICS_ADDR` | `:9090` | `:9090` |
| `SENTINELDB_API_ADDR` | `:8080` | `:8080` |

## Prometheus / Grafana access

- **Prometheus UI**: http://127.0.0.1:9091 — check **Status > Targets**;
  the `sentineldb` job should show `health: up` (scraping
  `sentineldb:9090/metrics` on the internal Docker network).
- **Grafana**: http://127.0.0.1:3000 (`admin` / `admin_demo_only`,
  demo-only credential). The **Prometheus** datasource and
  **SentinelDB Overview** dashboard are provisioned automatically from
  `deploy/grafana/provisioning` and `deploy/grafana/dashboards` — no
  manual setup needed.

## Log handling

```powershell
docker compose logs sentineldb
docker compose logs -f sentineldb   # follow
```

By default the gateway does not log SQL query text or `DataRow`/cell
values — see
[threat-model.md's sensitive logging policy](threat-model.md#sensitive-logging-policy).
Do not set `logging.log_full_queries: true` in any environment where
these logs are retained or shared, since that setting logs full SQL
text (which may embed PII, e.g. in a `WHERE` clause).

## Direct versus gateway connection examples

From the host machine (ports are published on `127.0.0.1`):

```powershell
# Direct to the real database, bypassing SentinelDB entirely
psql -h 127.0.0.1 -p 5433 -U sentineldb_demo -d sentineldb_demo -c "SELECT email FROM some_table;"

# Through the SentinelDB gateway — configured columns come back masked
psql -h 127.0.0.1 -p 5432 -U sentineldb_demo -d sentineldb_demo -c "SELECT email FROM some_table;"
```

From inside the Compose network (used by
[scripts/e2e-demo.ps1](../scripts/e2e-demo.ps1), useful when
`host.docker.internal` isn't reliable for a loopback-only published
port):

```powershell
docker compose exec -T postgres psql -U sentineldb_demo -d sentineldb_demo -c "SELECT email FROM some_table;"
docker compose exec -T -e PGPASSWORD=demo_only_change_me postgres `
  psql -h postgres -p 5432 -U sentineldb_demo -d sentineldb_demo -c "SELECT email FROM some_table;"
docker compose exec -T -e PGPASSWORD=demo_only_change_me postgres `
  psql -h sentineldb -p 5432 -U sentineldb_demo -d sentineldb_demo -c "SELECT email FROM some_table;"
```

All credentials shown above (`sentineldb_demo` / `demo_only_change_me`;
Grafana `admin` / `admin_demo_only`) are demo-only, defined in
`docker-compose.yml`. Do not reuse them anywhere real.

## Troubleshooting

| Symptom | Likely cause / check |
|---|---|
| `sentineldb` never reports healthy | Check `docker compose logs sentineldb` — likely `postgres` isn't healthy yet (`sentineldb` has `depends_on: postgres: condition: service_healthy`), or `plugins/firewall/v2.wasm` failed to load. |
| Client gets `FATAL`/connection closed immediately | Client is likely using the Extended Query Protocol (prepared statements) — see [postgresql-protocol.md](postgresql-protocol.md#rejected-frontend-messages-extended-query-protocol). Force simple-protocol execution. |
| `psql` hangs or fails to connect on `127.0.0.1:5432`/`5433` | Confirm the container is actually `healthy` (`docker compose ps`), and that nothing else on the host is bound to that port. |
| Prometheus target `sentineldb` shows `down` | Confirm `sentineldb` container is running and `deploy/prometheus/prometheus.yml`'s scrape target (`sentineldb:9090`) matches the service name in `docker-compose.yml`. |
| Grafana shows no data | Confirm the Prometheus datasource is provisioned (**Connections > Data sources**) and that the Prometheus target above is `up`. |
| Dashboard shows "API'ye ulaşılamadı" (API unreachable) | Confirm `sentineldb`'s `127.0.0.1:8080/api/status` responds directly; the dashboard's `VITE_API_BASE_URL` is baked in at build time (`http://localhost:8080` by default) — see `docker-compose.yml`'s `dashboard.build.args`. |
| `host.docker.internal` doesn't reach a published port | Expected in some Docker environments once ports are bound to `127.0.0.1` only — see [scripts/e2e-demo.ps1](../scripts/e2e-demo.ps1)'s comments; use `docker compose exec` to reach services by their Compose service name instead. |
| `go test -race ./...` fails locally with a cgo/toolchain error | `-race` requires a cgo-capable C toolchain. If unavailable locally (`CGO_ENABLED=0` or no C compiler), rely on the CI race job instead — see [CONTRIBUTING.md](../CONTRIBUTING.md#go-testing). |

## Data-volume cleanup warning

`docker compose down` (without `-v`) **preserves** the `pgdata` named
volume — the demo Postgres data persists across restarts. This is
intentional for iterative local use.

To fully reset the demo database (⚠️ **destructive** — deletes all data
in the demo Postgres instance, including anything you've added):

```powershell
docker compose down -v
```

Only run this if you intend to discard the volume. There is no
confirmation prompt.

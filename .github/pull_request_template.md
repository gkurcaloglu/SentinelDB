## What changed and why

<!-- Summarize the change and the motivation. Link any related issue. -->

## Scope check

- [ ] This PR stays within SentinelDB's current V1 scope (see
      [CONTRIBUTING.md — Scope discipline](../CONTRIBUTING.md#scope-discipline)).
      It does not add Extended Query Protocol support, TLS termination,
      COPY support, AI classification, RBAC, Kubernetes, or a SaaS
      control plane unless this PR was specifically agreed (in an issue)
      to do so.
- [ ] If `plugins/firewall/` source changed, `plugins/firewall/v2.wasm`
      was rebuilt (`pwsh scripts/build-wasm-plugins.ps1`) and committed
      alongside it.

## Testing

<!-- What did you run locally? Check what applies. -->

- [ ] `go build ./...` / `go vet ./...` / `go test ./...`
- [ ] `gofmt -l .` reports nothing
- [ ] `npm run build` in `dashboard/` (if the dashboard changed)
- [ ] Docker Compose demo / `scripts/e2e-demo.ps1` (if `docker-compose.yml`,
      `Dockerfile`, or the demo scripts changed)

## Security-sensitive?

<!-- If this touches firewall policy, masking, logging, or protocol
handling, briefly note the security implication. For an actual
vulnerability report, do not open a PR — see SECURITY.md. -->

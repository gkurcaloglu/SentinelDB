module github.com/gkurcaloglu/sentineldb/integration/pgxcompat

go 1.26.5

// jackc/pgx/v5 is deliberately isolated in this nested module (its own
// go.mod/go.sum, separate from the repository root module) rather than
// added to the root go.mod: the production gateway binary (cmd/gateway)
// must never import it, and this keeps `go build ./...`/`go vet ./...`/
// `go test ./...` run from the repository root from ever needing to
// resolve or compile pgx at all - only `go test ./...` run from inside
// this directory (or scripts/driver-compat.ps1) does.
require github.com/jackc/pgx/v5 v5.10.0

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	golang.org/x/text v0.29.0 // indirect
)

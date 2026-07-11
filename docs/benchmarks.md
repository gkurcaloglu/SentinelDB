# Benchmarks

> **These are local microbenchmarks of isolated hot-path functions, run on
> one developer machine. They are not a production throughput/SLA
> measurement.** They do not include network I/O, TCP connection setup,
> real PostgreSQL round-trips, or concurrent-connection behavior — see
> [Scope and caveats](#scope-and-caveats) below before drawing any
> capacity conclusions from these numbers.

## What is benchmarked

Six `testing.B` benchmarks across three packages, run via
[scripts/benchmark.ps1](../scripts/benchmark.ps1) (`go test -bench -benchmem`,
no external benchmark tooling):

| Benchmark | Package | What it measures |
|---|---|---|
| `BenchmarkParseRowDescription` | `internal/protocol` | Parsing a 3-column `RowDescription` ('T') message body. |
| `BenchmarkParseDataRow` | `internal/protocol` | Parsing a 3-cell `DataRow` ('D') message body. |
| `BenchmarkDataRowBuild` | `internal/protocol` | Re-serializing an already-parsed `DataRow` back to wire bytes — the rebuild cost paid whenever a row's masked column actually changed. |
| `BenchmarkTransformerMaskEmailColumn` | `internal/masking` | The full `masking.Transformer` orchestration for one configured `email` column (parse `RowDescription` + `DataRow`, invoke a fake in-process masker, rebuild the row) — isolates `internal/masking`'s own cost from Wasm call overhead. |
| `BenchmarkRuntimeMaskValue` | `internal/wasm` | One `mask_value` call through the **real**, `GOOS=wasip1`-compiled `plugins/firewall/v2.wasm` plugin (module instantiate + call + strict response validation). |
| `BenchmarkPolicyEvaluateSafeQuery` | `internal/wasm` | `firewall.Policy.Evaluate` (the interface `firewall.Gate` calls per query) for a query that matches none of the shipped `config.yaml` blocked phrases, backed by the real compiled Wasm plugin's `evaluate_query`. |

## How to reproduce

```powershell
# PowerShell 7+
pwsh scripts/benchmark.ps1

# Windows PowerShell 5.1
powershell -ExecutionPolicy Bypass -File .\scripts\benchmark.ps1

# Optional: write raw `go test` output to a file, adjust benchtime, or run a subset
powershell -ExecutionPolicy Bypass -File .\scripts\benchmark.ps1 -OutFile results.txt -BenchTime 2s -Run 'BenchmarkParseDataRow'
```

Equivalent by hand:

```powershell
go test -run '^$' -bench . -benchmem -benchtime 2s ./internal/protocol/... ./internal/masking/... ./internal/wasm/...
```

## Results

- **Date**: 2026-07-11
- **OS**: Windows 11 Pro, 64-bit (build 10.0.26200)
- **Architecture**: `windows/amd64`
- **Go version**: `go1.26.5`
- **CPU**: 12th Gen Intel(R) Core(TM) i7-12700H
- **Exact command**: `go test -run '^$' -bench . -benchmem -benchtime 2s ./internal/protocol/... ./internal/masking/... ./internal/wasm/...` (via `scripts/benchmark.ps1 -BenchTime 2s`)

Raw output:

```
goos: windows
goarch: amd64
pkg: github.com/gkurcaloglu/sentineldb/internal/protocol
cpu: 12th Gen Intel(R) Core(TM) i7-12700H
BenchmarkParseRowDescription-20    	25452200	        97.89 ns/op	     168 B/op	       5 allocs/op
BenchmarkParseDataRow-20           	25868674	        87.15 ns/op	     160 B/op	       5 allocs/op
BenchmarkDataRowBuild-20           	46748450	        53.33 ns/op	     128 B/op	       2 allocs/op
PASS
ok  	github.com/gkurcaloglu/sentineldb/internal/protocol	8.319s
goos: windows
goarch: amd64
pkg: github.com/gkurcaloglu/sentineldb/internal/masking
cpu: 12th Gen Intel(R) Core(TM) i7-12700H
BenchmarkTransformerMaskEmailColumn-20    	  546909	      4509 ns/op	   33930 B/op	      23 allocs/op
PASS
ok  	github.com/gkurcaloglu/sentineldb/internal/masking	4.643s
goos: windows
goarch: amd64
pkg: github.com/gkurcaloglu/sentineldb/internal/wasm
cpu: 12th Gen Intel(R) Core(TM) i7-12700H
BenchmarkRuntimeMaskValue-20           	     730	   3279747 ns/op	 7778632 B/op	   43754 allocs/op
BenchmarkPolicyEvaluateSafeQuery-20    	     706	   3305189 ns/op	 7778821 B/op	   43756 allocs/op
PASS
ok  	github.com/gkurcaloglu/sentineldb/internal/wasm	13.632s
```

### Summary

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `BenchmarkParseRowDescription` | 97.89 | 168 | 5 |
| `BenchmarkParseDataRow` | 87.15 | 160 | 5 |
| `BenchmarkDataRowBuild` | 53.33 | 128 | 2 |
| `BenchmarkTransformerMaskEmailColumn` | 4,509 | 33,930 | 23 |
| `BenchmarkRuntimeMaskValue` | 3,279,747 | 7,778,632 | 43,754 |
| `BenchmarkPolicyEvaluateSafeQuery` | 3,305,189 | 7,778,821 | 43,756 |

## Interpretation

- Raw wire-protocol parsing/rebuilding (`internal/protocol`) is sub-100ns
  and allocates only a handful of small objects per call — not a
  meaningful bottleneck relative to the Wasm calls below.
- `internal/masking`'s own orchestration (with a fake, non-Wasm masker)
  adds roughly a further ~4.5µs per masked cell — this isolates the cost
  of `Transformer`'s parse/dispatch/rebuild logic from actual Wasm
  invocation.
- **The dominant cost by three orders of magnitude is the Wasm plugin
  call itself**: both `mask_value` and `evaluate_query` cost roughly
  3.3ms and ~43,700 allocations per call on this machine. This is the
  per-call cost of instantiating a fresh WASI module instance from the
  compiled module (required because WASI `command`-model instances run
  `main()` exactly once — see
  [plugin-api.md](plugin-api.md#current-wasm-runtime)), not the cost of
  the email-masking or phrase-matching logic itself, which is trivial by
  comparison. Any change that reduces per-call Wasm instantiation
  overhead (e.g. instance pooling) would be the highest-leverage
  performance work identified by these numbers — see the
  [README roadmap](../README.md#roadmap) for what is and isn't planned.

## Scope and caveats

- These benchmarks exercise **isolated functions/paths in-process**, not
  the full `cmd/gateway` TCP proxy loop, real PostgreSQL round-trips, or
  concurrent-connection contention. They deliberately exclude network
  startup per the benchmark scope for this release.
- Numbers were collected on **one developer machine**, once, with
  `-benchtime 2s`. They are not averaged across multiple machines,
  multiple runs, or statistically analyzed (e.g. with `benchstat`).
- `BenchmarkRuntimeMaskValue` and `BenchmarkPolicyEvaluateSafeQuery`
  reflect this machine's wazero/WASI module instantiation cost; expect
  meaningfully different absolute numbers on different hardware or OSes,
  though the *relative* dominance of Wasm call overhead over native
  Go/parsing cost is expected to hold generally.
- **Do not treat any number on this page as a capacity planning input,
  an SLA, or a claim about production throughput.** See
  [SECURITY.md](../SECURITY.md) and
  [threat-model.md](threat-model.md#v1-is-not-a-production-security-boundary)
  for the project's broader "experimental, not production-ready" status.

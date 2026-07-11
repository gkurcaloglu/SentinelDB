package wasm

import (
	"context"
	"testing"

	"github.com/gkurcaloglu/sentineldb/internal/firewall"
	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// defaultBenchBlockedPhrases mirrors the shipped config.yaml's
// firewall.blocked_phrases so the benchmarked evaluate_query call does the
// same amount of matching work a real deployment would.
var defaultBenchBlockedPhrases = []string{"DROP TABLE", "DROP DATABASE", "DELETE FROM", "TRUNCATE"}

// BenchmarkRuntimeMaskValue measures a single mask_value invocation through
// the real, GOOS=wasip1-compiled firewall plugin (not a fake) — i.e. the
// actual per-call Wasm instantiate/call/validate overhead described in
// docs/plugin-api.md, for one email value.
func BenchmarkRuntimeMaskValue(b *testing.B) {
	ctx := context.Background()
	wasmPath := buildTestPlugin(b)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		b.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rt.Mask(ctx, "email", "email", "john.smith@example.com"); err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

// BenchmarkPolicyEvaluateSafeQuery measures firewall.Policy.Evaluate (the
// same interface firewall.Gate calls on the hot path) for a query that does
// NOT match any blocked phrase — the common case for legitimate traffic —
// backed by the real compiled Wasm plugin's evaluate_query operation.
func BenchmarkPolicyEvaluateSafeQuery(b *testing.B) {
	ctx := context.Background()
	wasmPath := buildTestPlugin(b)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		b.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	policy := NewPolicy(rt, defaultBenchBlockedPhrases, nil)
	msg := protocol.Message{
		Type:  protocol.MsgQuery,
		Query: "SELECT id, name, email FROM users WHERE id = 42;",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verdict, _ := policy.Evaluate(msg)
		if verdict != firewall.Allow {
			b.Fatalf("expected Allow for a safe query, got %v", verdict)
		}
	}
}

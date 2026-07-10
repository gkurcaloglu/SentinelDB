package wasm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gkurcaloglu/sentineldb/internal/wasmproto"
)

// buildTestPlugin, plugins/firewall kaynağını GOOS=wasip1 GOARCH=wasm ile
// gerçek bir .wasm ikili dosyasına derler. internal/wasm testlerinin sahte
// bir şey değil, gerçek bir Go-derlenmiş Wasm eklentisine karşı çalışmasını
// sağlar.
func buildTestPlugin(t *testing.T) string {
	t.Helper()

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("repo kok dizini bulunamadi: %v", err)
	}
	out := filepath.Join(t.TempDir(), "firewall_test.wasm")

	cmd := exec.Command("go", "build", "-o", out, "./plugins/firewall")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wasm plugin derlenemedi: %v\n%s", err, output)
	}
	return out
}

func TestRuntime_EvaluateAllowsSafeQuery(t *testing.T) {
	ctx := context.Background()
	wasmPath := buildTestPlugin(t)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		t.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	verdict, reason, err := rt.Evaluate(ctx, "SELECT 1;", []string{"DROP TABLE", "DELETE FROM"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != wasmproto.VerdictAllow {
		t.Fatalf("expected ALLOW, got %s (reason=%q)", verdict, reason)
	}
}

func TestRuntime_EvaluateBlocksDangerousQuery(t *testing.T) {
	ctx := context.Background()
	wasmPath := buildTestPlugin(t)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		t.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	verdict, reason, err := rt.Evaluate(ctx, "DROP TABLE users;", []string{"DROP TABLE", "DELETE FROM"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != wasmproto.VerdictBlock {
		t.Fatalf("expected BLOCK, got %s", verdict)
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason for a blocked query")
	}
}

// TestRuntime_EvaluateMultipleCallsOnSameCompiledModule, ayni Runtime'in
// (dolayisiyla ayni derlenmis CompiledModule'un) art arda birden fazla
// Evaluate cagrisinda güvenle yeniden kullanilabildigini dogrular. Her
// cagri WASI acisindan taze bir instance calistirir.
func TestRuntime_EvaluateMultipleCallsOnSameCompiledModule(t *testing.T) {
	ctx := context.Background()
	wasmPath := buildTestPlugin(t)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		t.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	queries := []struct {
		query string
		want  string
	}{
		{"SELECT 1;", wasmproto.VerdictAllow},
		{"DROP TABLE users;", wasmproto.VerdictBlock},
		{"SELECT 2;", wasmproto.VerdictAllow},
		{"DELETE FROM users;", wasmproto.VerdictBlock},
	}

	for i, tc := range queries {
		verdict, _, err := rt.Evaluate(ctx, tc.query, []string{"DROP TABLE", "DELETE FROM"})
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if verdict != tc.want {
			t.Errorf("call %d (%q): got %s, want %s", i, tc.query, verdict, tc.want)
		}
	}
}

func TestRuntime_NewRuntimeErrorsOnMissingFile(t *testing.T) {
	ctx := context.Background()
	_, err := NewRuntime(ctx, filepath.Join(t.TempDir(), "does-not-exist.wasm"))
	if err == nil {
		t.Fatal("expected an error for a missing wasm file")
	}
}

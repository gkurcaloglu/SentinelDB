package wasm

import (
	"context"
	"testing"
)

func TestRuntime_Mask_MasksEmail(t *testing.T) {
	ctx := context.Background()
	wasmPath := buildTestPlugin(t)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		t.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	res, err := rt.Mask(ctx, "email", "email", "john@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed=true, got %+v", res)
	}
	if res.Value != "jo****@example.com" {
		t.Fatalf("expected 'jo****@example.com', got %q", res.Value)
	}
}

func TestRuntime_Mask_NonEmailUnchanged(t *testing.T) {
	ctx := context.Background()
	wasmPath := buildTestPlugin(t)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		t.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	res, err := rt.Mask(ctx, "email", "email", "not-an-email")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Changed {
		t.Fatalf("expected Changed=false for a non-email value, got %+v", res)
	}
	if res.Value != "not-an-email" {
		t.Fatalf("expected the original value unchanged, got %q", res.Value)
	}
}

func TestRuntime_Mask_UnknownKindFailsClosed(t *testing.T) {
	ctx := context.Background()
	wasmPath := buildTestPlugin(t)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		t.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	if _, err := rt.Mask(ctx, "phone", "phone_number", "555-1234"); err == nil {
		t.Fatal("expected an error for an unknown masking kind")
	}
}

func TestMasker_AdaptsRuntimeToInterface(t *testing.T) {
	ctx := context.Background()
	wasmPath := buildTestPlugin(t)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		t.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	masker := NewMasker(rt)
	value, changed, _, err := masker.Mask(ctx, "email", "email", "john@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed || value != "jo****@example.com" {
		t.Fatalf("expected masked value, got value=%q changed=%v", value, changed)
	}
}

// TestRuntime_SameCompiledModuleServesBothOperations, gorev D'nin "tek
// yuklu Wasm modulu" gereksinimini dogrular: ayni Runtime (dolayisiyla
// ayni derlenmis CompiledModule), art arda hem evaluate_query hem
// mask_value cagrilarini dogru sekilde karsilayabilir.
func TestRuntime_SameCompiledModuleServesBothOperations(t *testing.T) {
	ctx := context.Background()
	wasmPath := buildTestPlugin(t)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		t.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	verdict, _, err := rt.Evaluate(ctx, "DROP TABLE users;", []string{"DROP TABLE"})
	if err != nil {
		t.Fatalf("unexpected evaluate error: %v", err)
	}
	if verdict != "BLOCK" {
		t.Fatalf("expected BLOCK, got %q", verdict)
	}

	res, err := rt.Mask(ctx, "email", "email", "john@example.com")
	if err != nil {
		t.Fatalf("unexpected mask error: %v", err)
	}
	if res.Value != "jo****@example.com" {
		t.Fatalf("expected masked value, got %q", res.Value)
	}

	verdict, _, err = rt.Evaluate(ctx, "SELECT 1;", []string{"DROP TABLE"})
	if err != nil {
		t.Fatalf("unexpected evaluate error: %v", err)
	}
	if verdict != "ALLOW" {
		t.Fatalf("expected ALLOW, got %q", verdict)
	}
}

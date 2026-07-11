package wasm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/wasmproto"
)

// buildTestPlugin, plugins/firewall kaynağını GOOS=wasip1 GOARCH=wasm ile
// gerçek bir .wasm ikili dosyasına derler. internal/wasm testlerinin sahte
// bir şey değil, gerçek bir Go-derlenmiş Wasm eklentisine karşı çalışmasını
// sağlar. testing.TB kabul eder ki hem *testing.T (testler) hem *testing.B
// (bkz. bench_test.go) aynı derleme mantığını paylaşabilsin.
func buildTestPlugin(t testing.TB) string {
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

// TestRuntime_TimeoutFailsClosed, gorev I'nin "plugin timeout ... fail
// closed" gereksinimini dogrular: eklenti cagrisina tanınan sure
// (rt.timeout) pratikte imkansiz derecede kisa tutuldugunda, cagri hata
// ile doner (sonsuza kadar bloke olmaz), boylece cagiran taraf (ör.
// wasm.Policy/wasm.Masker) fail-closed davranabilir.
func TestRuntime_TimeoutFailsClosed(t *testing.T) {
	ctx := context.Background()
	wasmPath := buildTestPlugin(t)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		t.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	rt.timeout = 1 * time.Nanosecond // hicbir calistirmayi bitiremeyecek kadar kisa

	if _, _, err := rt.Evaluate(ctx, "SELECT 1;", nil); err == nil {
		t.Fatal("expected an error when the plugin call times out")
	}
	if _, err := rt.Mask(ctx, "email", "email", "john@example.com"); err == nil {
		t.Fatal("expected an error when the plugin call times out")
	}
}

// TestValidateEnvelopeMeta_MalformedResponsesFailClosed, gorev I'nin
// "malformed plugin response fails closed" gereksinimini
// validateEnvelopeMeta uzerinde dogrudan (sahte bir eklenti derlemeye
// gerek kalmadan) dogrular: eklenti sozlesmesine uymayan hicbir yanit
// sessizce basarili sayilmaz.
func TestValidateEnvelopeMeta_MalformedResponsesFailClosed(t *testing.T) {
	cases := []struct {
		name string
		resp wireResult
	}{
		{"error alani dolu", wireResult{Version: wasmproto.ProtocolVersion, Op: wasmproto.OpEvaluateQuery, Error: "bir seyler ters gitti"}},
		{"versiyon uyusmuyor", wireResult{Version: 999, Op: wasmproto.OpEvaluateQuery, Verdict: "ALLOW"}},
		{"op uyusmuyor", wireResult{Version: wasmproto.ProtocolVersion, Op: wasmproto.OpMaskValue, Verdict: "ALLOW"}},
		{"bos zarf", wireResult{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateEnvelopeMeta(tc.resp, wasmproto.OpEvaluateQuery); err == nil {
				t.Fatalf("expected validateEnvelopeMeta to reject %+v", tc.resp)
			}
		})
	}
}

func TestValidateEnvelopeMeta_ValidResponseAccepted(t *testing.T) {
	resp := wireResult{Version: wasmproto.ProtocolVersion, Op: wasmproto.OpEvaluateQuery, Verdict: "ALLOW"}
	if err := validateEnvelopeMeta(resp, wasmproto.OpEvaluateQuery); err != nil {
		t.Fatalf("unexpected error for a valid response: %v", err)
	}
}

// --- gorev C: sikilastirilmis JSON dogrulama testleri ---

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

func TestDecodeStrictResult_RejectsUnknownField(t *testing.T) {
	data := []byte(`{"version":1,"op":"evaluate_query","verdict":"ALLOW","totally_unknown_field":"x"}`)
	if _, err := decodeStrictResult(data); err == nil {
		t.Fatal("expected an error for an unknown JSON field")
	}
}

func TestDecodeStrictResult_AllowsTrailingNewlineFromJSONEncoder(t *testing.T) {
	// json.Encoder.Encode her zaman tek bir '\n' ekler; bu reddedilmemeli.
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(wasmproto.Result{Version: 1, Op: "evaluate_query", Verdict: "ALLOW"}); err != nil {
		t.Fatalf("unexpected encode error: %v", err)
	}
	if _, err := decodeStrictResult(buf.Bytes()); err != nil {
		t.Fatalf("expected the normal json.Encoder trailing newline to be accepted, got: %v", err)
	}
}

func TestDecodeStrictResult_RejectsTrailingJSONValue(t *testing.T) {
	data := []byte(`{"version":1,"op":"evaluate_query","verdict":"ALLOW"}{"extra":"object"}`)
	if _, err := decodeStrictResult(data); err == nil {
		t.Fatal("expected an error for a second trailing JSON value")
	}
}

func TestDecodeStrictResult_RejectsTrailingGarbage(t *testing.T) {
	data := []byte(`{"version":1,"op":"evaluate_query","verdict":"ALLOW"}garbage`)
	if _, err := decodeStrictResult(data); err == nil {
		t.Fatal("expected an error for trailing non-whitespace garbage")
	}
}

func TestValidateMaskResponse_MissingValueFailsClosed(t *testing.T) {
	resp := wireResult{Version: 1, Op: wasmproto.OpMaskValue, Changed: boolPtr(false)}
	if _, err := validateMaskResponse("john@example.com", resp); err == nil {
		t.Fatal("expected an error when 'value' is absent")
	}
}

func TestValidateMaskResponse_MissingChangedFailsClosed(t *testing.T) {
	resp := wireResult{Version: 1, Op: wasmproto.OpMaskValue, Value: strPtr("john@example.com")}
	if _, err := validateMaskResponse("john@example.com", resp); err == nil {
		t.Fatal("expected an error when 'changed' is absent")
	}
}

func TestValidateMaskResponse_ChangedFalseWithDifferentValueFailsClosed(t *testing.T) {
	resp := wireResult{Version: 1, Op: wasmproto.OpMaskValue, Value: strPtr("SOMETHING_ELSE"), Changed: boolPtr(false)}
	if _, err := validateMaskResponse("john@example.com", resp); err == nil {
		t.Fatal("expected an error when changed=false but the value differs from the original")
	}
}

func TestValidateMaskResponse_ChangedTrueWithOriginalValueFailsClosed(t *testing.T) {
	resp := wireResult{Version: 1, Op: wasmproto.OpMaskValue, Value: strPtr("john@example.com"), Changed: boolPtr(true)}
	if _, err := validateMaskResponse("john@example.com", resp); err == nil {
		t.Fatal("expected an error when changed=true but the value equals the original")
	}
}

func TestValidateMaskResponse_ConsistentResponsesAccepted(t *testing.T) {
	unchanged := wireResult{Version: 1, Op: wasmproto.OpMaskValue, Value: strPtr("not-an-email"), Changed: boolPtr(false)}
	if res, err := validateMaskResponse("not-an-email", unchanged); err != nil || res.Changed {
		t.Fatalf("expected a valid unchanged response to be accepted, got res=%+v err=%v", res, err)
	}

	changed := wireResult{Version: 1, Op: wasmproto.OpMaskValue, Value: strPtr("jo****@example.com"), Changed: boolPtr(true)}
	if res, err := validateMaskResponse("john@example.com", changed); err != nil || !res.Changed || res.Value != "jo****@example.com" {
		t.Fatalf("expected a valid changed response to be accepted, got res=%+v err=%v", res, err)
	}
}

func TestValidateMaskResponse_InvalidUTF8FailsClosed(t *testing.T) {
	resp := wireResult{Version: 1, Op: wasmproto.OpMaskValue, Value: strPtr("invalid: \xff\xfe"), Changed: boolPtr(true)}
	if _, err := validateMaskResponse("john@example.com", resp); err == nil {
		t.Fatal("expected an error for invalid UTF-8 output")
	}
}

func TestValidateMaskResponse_OversizedValueFailsClosed(t *testing.T) {
	huge := strings.Repeat("a", maxMaskedValueSize+1)
	resp := wireResult{Version: 1, Op: wasmproto.OpMaskValue, Value: &huge, Changed: boolPtr(true)}
	if _, err := validateMaskResponse("john@example.com", resp); err == nil {
		t.Fatal("expected an error for an oversized value")
	}
}

// --- gorev B: eklenti ciktisinin hicbir hataya sizmadigini dogrulayan
// uctan uca test ---

// buildLeakyTestPlugin, kasitli olarak bozuk bir yanit doner VE hem
// stdout hem stderr'e secretMarker'i yazan, gercekten GOOS=wasip1 ile
// derlenmis bir Wasm ikilisi uretir. Bu, TestRuntime_ErrorsNeverLeakPluginOutput'un
// host'un donen hicbir hata mesajina bu iceriği sizdirmadigini KANITLAMASINI
// saglar (Go-seviyesi string formatlamamiza guvenmek yerine gercek bir
// calisma zamani ile).
func buildLeakyTestPlugin(t *testing.T, secretMarker string) string {
	t.Helper()

	srcDir := t.TempDir()
	// verdict'i kasitli olarak gecersiz (secretMarker) yapiyoruz ki
	// decodeStrictResult basarili olsun ama validateEvaluateResponse
	// reddetsin - boylece hem "JSON gecerli ama anlamsal olarak gecersiz"
	// hem stderr sizinti yollari tek testte kapsanmis olur.
	src := fmt.Sprintf(`package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprint(os.Stdout, `+"`"+`{"version":1,"op":"evaluate_query","verdict":%q,"changed":false,"value":""}`+"`"+`)
	fmt.Fprint(os.Stderr, %q+" - kritik hata ayiklama bilgisi, asla loglanmamali")
}
`, secretMarker, secretMarker)

	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("leaky plugin kaynagi yazilamadi: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module leakyplugin\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatalf("go.mod yazilamadi: %v", err)
	}

	out := filepath.Join(t.TempDir(), "leaky.wasm")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("leaky plugin derlenemedi: %v\n%s", err, output)
	}
	return out
}

func TestRuntime_ErrorsNeverLeakPluginOutput(t *testing.T) {
	const secretMarker = "SUPER_SECRET_MARKER_XYZ123_do_not_leak"

	ctx := context.Background()
	wasmPath := buildLeakyTestPlugin(t, secretMarker)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		t.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	_, _, evalErr := rt.Evaluate(ctx, "SELECT 1;", nil)
	if evalErr == nil {
		t.Fatal("expected an error since the leaky plugin returns an invalid verdict")
	}
	if strings.Contains(evalErr.Error(), secretMarker) {
		t.Fatalf("returned error leaked the plugin's raw output:\n%v", evalErr)
	}

	_, maskErr := rt.Mask(ctx, "email", "email", "john@example.com")
	if maskErr == nil {
		t.Fatal("expected an error since the leaky plugin's response op does not match mask_value")
	}
	if strings.Contains(maskErr.Error(), secretMarker) {
		t.Fatalf("returned error leaked the plugin's raw output:\n%v", maskErr)
	}
}

// buildOversizedOutputTestPlugin, stdout'a maxStdoutBytes'i asan bir
// miktarda veri yazan gercek bir Wasm ikilisi uretir.
func buildOversizedOutputTestPlugin(t *testing.T) string {
	t.Helper()

	srcDir := t.TempDir()
	src := `package main

import (
	"os"
	"strings"
)

func main() {
	os.Stdout.WriteString(strings.Repeat("A", 1<<20)) // 1 MiB, sinirin cok uzerinde
}
`
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("oversized plugin kaynagi yazilamadi: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module oversizedplugin\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatalf("go.mod yazilamadi: %v", err)
	}

	out := filepath.Join(t.TempDir(), "oversized.wasm")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("oversized plugin derlenemedi: %v\n%s", err, output)
	}
	return out
}

func TestRuntime_OversizedOutputFailsClosed(t *testing.T) {
	ctx := context.Background()
	wasmPath := buildOversizedOutputTestPlugin(t)

	rt, err := NewRuntime(ctx, wasmPath)
	if err != nil {
		t.Fatalf("unexpected error creating runtime: %v", err)
	}
	defer rt.Close(ctx)

	_, _, evalErr := rt.Evaluate(ctx, "SELECT 1;", nil)
	if evalErr == nil {
		t.Fatal("expected an error when the plugin exceeds the stdout size limit")
	}
	// Hata mesaji sadece guvenli metadata (bayt sayilari) icerebilir,
	// milyonlarca 'A' karakterinin kendisini degil.
	if strings.Count(evalErr.Error(), "A") > 10 {
		t.Fatalf("expected the error to summarize byte counts, not echo the oversized content: %v", evalErr)
	}
}

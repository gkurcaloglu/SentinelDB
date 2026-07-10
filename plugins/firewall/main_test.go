package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/gkurcaloglu/sentineldb/internal/wasmproto"
)

// Bu testler plugins/firewall'un karar mantığını (evaluate/run) normal
// "go test" ile, herhangi bir Wasm derlemesi gerektirmeden dogrular. Ayni
// binary'nin gercekten GOOS=wasip1 altinda calistigini dogrulayan
// entegrasyon testi internal/wasm/runtime_test.go'dadir.

func TestEvaluate_BlocksMatchingPhrase(t *testing.T) {
	req := wasmproto.Request{
		Query:          "DROP TABLE users;",
		BlockedPhrases: []string{"DROP TABLE", "DELETE FROM"},
	}
	resp := evaluate(req)
	if resp.Verdict != wasmproto.VerdictBlock {
		t.Fatalf("expected BLOCK, got %+v", resp)
	}
	if resp.Reason == "" {
		t.Fatal("expected a non-empty reason for a blocked query")
	}
}

func TestEvaluate_AllowsSafeQuery(t *testing.T) {
	req := wasmproto.Request{
		Query:          "SELECT * FROM users;",
		BlockedPhrases: []string{"DROP TABLE", "DELETE FROM"},
	}
	resp := evaluate(req)
	if resp.Verdict != wasmproto.VerdictAllow {
		t.Fatalf("expected ALLOW, got %+v", resp)
	}
	if resp.Reason != "" {
		t.Fatalf("expected empty reason for an allowed query, got %q", resp.Reason)
	}
}

func TestRun_RoundTripsJSONOverStdinStdout(t *testing.T) {
	reqBytes, err := json.Marshal(wasmproto.Request{
		Query:          "TRUNCATE users;",
		BlockedPhrases: []string{"TRUNCATE"},
	})
	if err != nil {
		t.Fatalf("unexpected error marshaling request: %v", err)
	}

	var stdout bytes.Buffer
	if err := run(bytes.NewReader(reqBytes), &stdout); err != nil {
		t.Fatalf("unexpected error from run: %v", err)
	}

	var resp wasmproto.Response
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("unexpected error unmarshaling response: %v (raw=%q)", err, stdout.String())
	}
	if resp.Verdict != wasmproto.VerdictBlock {
		t.Fatalf("expected BLOCK, got %+v", resp)
	}
}

func TestRun_MalformedInputReturnsError(t *testing.T) {
	var stdout bytes.Buffer
	if err := run(bytes.NewReader([]byte("not json")), &stdout); err == nil {
		t.Fatal("expected an error for malformed JSON input")
	}
}

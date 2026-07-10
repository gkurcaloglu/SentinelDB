package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/gkurcaloglu/sentineldb/internal/wasmproto"
)

// Bu testler plugins/firewall'un karar mantığını (dispatch/run) normal
// "go test" ile, herhangi bir Wasm derlemesi gerektirmeden dogrular. Ayni
// binary'nin gercekten GOOS=wasip1 altinda calistigini dogrulayan
// entegrasyon testleri internal/wasm/runtime_test.go ve
// internal/wasm/masker_test.go'dadir.

func TestDispatch_EvaluateQuery_BlocksMatchingPhrase(t *testing.T) {
	req := wasmproto.Envelope{
		Version:        wasmproto.ProtocolVersion,
		Op:             wasmproto.OpEvaluateQuery,
		Query:          "DROP TABLE users;",
		BlockedPhrases: []string{"DROP TABLE", "DELETE FROM"},
	}
	resp := dispatch(req)
	if resp.Error != "" {
		t.Fatalf("unexpected error result: %+v", resp)
	}
	if resp.Verdict != wasmproto.VerdictBlock {
		t.Fatalf("expected BLOCK, got %+v", resp)
	}
	if resp.Reason == "" {
		t.Fatal("expected a non-empty reason for a blocked query")
	}
	if resp.Op != wasmproto.OpEvaluateQuery || resp.Version != wasmproto.ProtocolVersion {
		t.Fatalf("expected echoed op/version, got %+v", resp)
	}
}

func TestDispatch_EvaluateQuery_AllowsSafeQuery(t *testing.T) {
	req := wasmproto.Envelope{
		Version:        wasmproto.ProtocolVersion,
		Op:             wasmproto.OpEvaluateQuery,
		Query:          "SELECT * FROM users;",
		BlockedPhrases: []string{"DROP TABLE", "DELETE FROM"},
	}
	resp := dispatch(req)
	if resp.Verdict != wasmproto.VerdictAllow {
		t.Fatalf("expected ALLOW, got %+v", resp)
	}
	if resp.Reason != "" {
		t.Fatalf("expected empty reason for an allowed query, got %q", resp.Reason)
	}
}

func TestDispatch_MaskValue_MasksEmail(t *testing.T) {
	req := wasmproto.Envelope{
		Version: wasmproto.ProtocolVersion,
		Op:      wasmproto.OpMaskValue,
		Column:  "email",
		Kind:    wasmproto.KindEmail,
		Value:   "john@example.com",
	}
	resp := dispatch(req)
	if resp.Error != "" {
		t.Fatalf("unexpected error result: %+v", resp)
	}
	if !resp.Changed {
		t.Fatalf("expected Changed=true, got %+v", resp)
	}
	if resp.Value != "jo****@example.com" {
		t.Fatalf("expected masked value 'jo****@example.com', got %q", resp.Value)
	}
}

func TestDispatch_MaskValue_NonEmailUnchanged(t *testing.T) {
	req := wasmproto.Envelope{
		Version: wasmproto.ProtocolVersion,
		Op:      wasmproto.OpMaskValue,
		Column:  "email",
		Kind:    wasmproto.KindEmail,
		Value:   "not-an-email",
	}
	resp := dispatch(req)
	if resp.Error != "" {
		t.Fatalf("unexpected error result: %+v", resp)
	}
	if resp.Changed {
		t.Fatalf("expected Changed=false for a non-email value, got %+v", resp)
	}
	if resp.Value != "not-an-email" {
		t.Fatalf("expected the original value to be returned unchanged, got %q", resp.Value)
	}
}

func TestDispatch_MaskValue_MissingColumnFailsClosed(t *testing.T) {
	req := wasmproto.Envelope{
		Version: wasmproto.ProtocolVersion,
		Op:      wasmproto.OpMaskValue,
		Kind:    wasmproto.KindEmail,
		Value:   "john@example.com",
	}
	resp := dispatch(req)
	if resp.Error == "" {
		t.Fatal("expected a non-empty Error for a missing column")
	}
}

func TestDispatch_MaskValue_UnknownKindFailsClosed(t *testing.T) {
	req := wasmproto.Envelope{
		Version: wasmproto.ProtocolVersion,
		Op:      wasmproto.OpMaskValue,
		Column:  "phone",
		Kind:    "phone_number",
		Value:   "555-1234",
	}
	resp := dispatch(req)
	if resp.Error == "" {
		t.Fatal("expected a non-empty Error for an unknown masking kind")
	}
}

func TestDispatch_MaskValue_InvalidUTF8FailsClosed(t *testing.T) {
	req := wasmproto.Envelope{
		Version: wasmproto.ProtocolVersion,
		Op:      wasmproto.OpMaskValue,
		Column:  "email",
		Kind:    wasmproto.KindEmail,
		Value:   "invalid utf8: \xff\xfe",
	}
	resp := dispatch(req)
	if resp.Error == "" {
		t.Fatal("expected a non-empty Error for invalid UTF-8 input")
	}
}

func TestDispatch_UnknownOperationFailsClosed(t *testing.T) {
	req := wasmproto.Envelope{Version: wasmproto.ProtocolVersion, Op: "delete_everything"}
	resp := dispatch(req)
	if resp.Error == "" {
		t.Fatal("expected a non-empty Error for an unknown operation")
	}
}

func TestDispatch_UnsupportedVersionFailsClosed(t *testing.T) {
	req := wasmproto.Envelope{Version: 999, Op: wasmproto.OpEvaluateQuery, Query: "SELECT 1;"}
	resp := dispatch(req)
	if resp.Error == "" {
		t.Fatal("expected a non-empty Error for an unsupported protocol version")
	}
}

func TestRun_RoundTripsJSONOverStdinStdout(t *testing.T) {
	reqBytes, err := json.Marshal(wasmproto.Envelope{
		Version:        wasmproto.ProtocolVersion,
		Op:             wasmproto.OpEvaluateQuery,
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

	var resp wasmproto.Result
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

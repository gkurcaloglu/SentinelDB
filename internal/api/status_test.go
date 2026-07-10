package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gkurcaloglu/sentineldb/internal/metrics"
)

func TestStatusHandler_ReturnsCurrentCountersAndRules(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	m.ConnectionsTotal.Add(4)
	m.BlockedQueriesTotal.Add(1)

	handler := NewStatusHandler(m, []string{"DROP TABLE", "DELETE FROM"})

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var got Status
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unexpected error unmarshaling response: %v (body=%s)", err, rec.Body.String())
	}

	if got.ConnectionsTotal != 4 {
		t.Errorf("ConnectionsTotal = %v, want 4", got.ConnectionsTotal)
	}
	if got.BlockedQueriesTotal != 1 {
		t.Errorf("BlockedQueriesTotal = %v, want 1", got.BlockedQueriesTotal)
	}
	if len(got.ActiveRules) != 2 || got.ActiveRules[0] != "DROP TABLE" {
		t.Errorf("ActiveRules = %v, want [DROP TABLE DELETE FROM]", got.ActiveRules)
	}
}

func TestStatusHandler_NilRulesSerializeAsEmptyArray(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	handler := NewStatusHandler(m, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Body.String(); !strings.Contains(got, `"active_rules":[]`) {
		t.Errorf("expected active_rules to serialize as [], got body: %s", got)
	}
}

func TestStatusHandler_RejectsNonGET(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	handler := NewStatusHandler(m, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rec.Code)
	}
}

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithCORS_SetsHeadersAndPassesThroughGET(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	WithCORS(inner).ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected the inner handler to be called for a GET request")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
}

func TestWithCORS_HandlesPreflightWithoutCallingInner(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodOptions, "/api/status", nil)
	rec := httptest.NewRecorder()
	WithCORS(inner).ServeHTTP(rec, req)

	if called {
		t.Fatal("expected the inner handler NOT to be called for an OPTIONS preflight request")
	}
	if rec.Code != http.StatusNoContent {
		t.Errorf("expected status 204 for preflight, got %d", rec.Code)
	}
}

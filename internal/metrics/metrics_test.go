package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNew_RegistersBothCounters(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("unexpected error gathering metrics: %v", err)
	}

	names := make(map[string]bool, len(families))
	for _, f := range families {
		names[f.GetName()] = true
	}

	for _, want := range []string{"sentineldb_connections_total", "sentineldb_blocked_queries_total"} {
		if !names[want] {
			t.Errorf("expected registry to contain metric %q, got families %v", want, names)
		}
	}

	if m.ConnectionsTotal == nil || m.BlockedQueriesTotal == nil {
		t.Fatal("expected both counters to be non-nil")
	}
}

func TestNew_RegistersMaskingMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	if m.MaskedCellsTotal == nil || m.MaskingErrorsTotal == nil || m.MaskingPluginDuration == nil {
		t.Fatal("expected all masking metrics to be initialized")
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("unexpected error gathering metrics: %v", err)
	}
	names := make(map[string]bool, len(families))
	for _, f := range families {
		names[f.GetName()] = true
	}
	for _, want := range []string{
		"sentineldb_masked_cells_total",
		"sentineldb_masking_errors_total",
		"sentineldb_masking_plugin_duration_seconds",
	} {
		if !names[want] {
			t.Errorf("expected registry to contain metric %q, got families %v", want, names)
		}
	}
}

func TestMetrics_MaskingCountersIncrementIndependently(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.MaskedCellsTotal.Add(3)
	m.MaskingErrorsTotal.Inc()
	m.MaskingPluginDuration.Observe(0.004)
	m.MaskingPluginDuration.Observe(0.012)

	if got := testutil.ToFloat64(m.MaskedCellsTotal); got != 3 {
		t.Errorf("MaskedCellsTotal = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.MaskingErrorsTotal); got != 1 {
		t.Errorf("MaskingErrorsTotal = %v, want 1", got)
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("unexpected error gathering metrics: %v", err)
	}
	var sampleCount uint64
	for _, f := range families {
		if f.GetName() != "sentineldb_masking_plugin_duration_seconds" {
			continue
		}
		sampleCount = f.GetMetric()[0].GetHistogram().GetSampleCount()
	}
	if sampleCount != 2 {
		t.Errorf("expected 2 histogram observations, got %d", sampleCount)
	}
}

func TestMetrics_CountersIncrementIndependently(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.ConnectionsTotal.Inc()
	m.ConnectionsTotal.Inc()
	m.ConnectionsTotal.Inc()
	m.BlockedQueriesTotal.Inc()

	if got := testutil.ToFloat64(m.ConnectionsTotal); got != 3 {
		t.Errorf("ConnectionsTotal = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.BlockedQueriesTotal); got != 1 {
		t.Errorf("BlockedQueriesTotal = %v, want 1", got)
	}
}

func TestMetrics_Snapshot(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.ConnectionsTotal.Add(7)
	m.BlockedQueriesTotal.Add(2)

	snap, err := m.Snapshot()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if snap.ConnectionsTotal != 7 {
		t.Errorf("Snapshot().ConnectionsTotal = %v, want 7", snap.ConnectionsTotal)
	}
	if snap.BlockedQueriesTotal != 2 {
		t.Errorf("Snapshot().BlockedQueriesTotal = %v, want 2", snap.BlockedQueriesTotal)
	}
}

func TestMetrics_SnapshotIncludesMaskingMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.MaskedCellsTotal.Add(5)
	m.MaskingErrorsTotal.Add(2)
	m.MaskingPluginDuration.Observe(0.010)
	m.MaskingPluginDuration.Observe(0.030)

	snap, err := m.Snapshot()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if snap.MaskedCellsTotal != 5 {
		t.Errorf("Snapshot().MaskedCellsTotal = %v, want 5", snap.MaskedCellsTotal)
	}
	if snap.MaskingErrorsTotal != 2 {
		t.Errorf("Snapshot().MaskingErrorsTotal = %v, want 2", snap.MaskingErrorsTotal)
	}
	if snap.MaskingPluginDurationCount != 2 {
		t.Errorf("Snapshot().MaskingPluginDurationCount = %v, want 2", snap.MaskingPluginDurationCount)
	}
	if got, want := snap.MaskingPluginDurationSumSecs, 0.040; got < want-1e-9 || got > want+1e-9 {
		t.Errorf("Snapshot().MaskingPluginDurationSumSecs = %v, want %v", got, want)
	}
}

func TestMetrics_SnapshotBeforeAnyIncrementIsZero(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	snap, err := m.Snapshot()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if snap.ConnectionsTotal != 0 || snap.BlockedQueriesTotal != 0 {
		t.Errorf("expected zero-value snapshot, got %+v", snap)
	}
}

// TestMetrics_ExposedOverHTTP, gercek promhttp.Handler uzerinden /metrics
// cikti formatinin beklenen sayac isimlerini ve degerlerini icerdigini
// dogrular (uc-uca, Gate/main.go'nun kuracagi ile ayni yol).
func TestMetrics_ExposedOverHTTP(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	m.ConnectionsTotal.Add(2)
	m.BlockedQueriesTotal.Add(5)

	srv := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("unexpected error fetching /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("unexpected error reading body: %v", err)
	}
	text := string(body)

	if !strings.Contains(text, "sentineldb_connections_total 2") {
		t.Errorf("expected body to contain 'sentineldb_connections_total 2', got:\n%s", text)
	}
	if !strings.Contains(text, "sentineldb_blocked_queries_total 5") {
		t.Errorf("expected body to contain 'sentineldb_blocked_queries_total 5', got:\n%s", text)
	}
}

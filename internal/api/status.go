// Package api, SentinelDB dashboard'unun (React) tükettiği salt okunur JSON
// API'sini barındırır.
package api

import (
	"encoding/json"
	"net/http"

	"github.com/gkurcaloglu/sentineldb/internal/metrics"
)

// Status, GET /api/status'un döndürdüğü JSON gövdesidir.
type Status struct {
	ConnectionsTotal    float64  `json:"connections_total"`
	BlockedQueriesTotal float64  `json:"blocked_queries_total"`
	ActiveRules         []string `json:"active_rules"`

	// MaskedCellsTotal/MaskingErrorsTotal, sentineldb_masked_cells_total ve
	// sentineldb_masking_errors_total sayaçlarının o anki değerleridir.
	MaskedCellsTotal   float64 `json:"masked_cells_total"`
	MaskingErrorsTotal float64 `json:"masking_errors_total"`
	// MaskingPluginAvgDurationMs, sentineldb_masking_plugin_duration_seconds
	// histogramından hesaplanan ortalama süredir (milisaniye). Henüz hiç
	// gözlem yoksa 0'dır.
	MaskingPluginAvgDurationMs float64 `json:"masking_plugin_avg_duration_ms"`
}

// NewStatusHandler, güncel bağlantı/engelleme sayaçlarını ve aktif
// firewall kurallarını JSON olarak döndüren bir handler oluşturur.
// activeRules, config.yaml'daki firewall.blocked_phrases listesidir.
func NewStatusHandler(m *metrics.Metrics, activeRules []string) http.Handler {
	if activeRules == nil {
		activeRules = []string{} // JSON'da null yerine [] donsun
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		snap, err := m.Snapshot()
		if err != nil {
			http.Error(w, "metrikler okunamadi", http.StatusInternalServerError)
			return
		}

		var avgDurationMs float64
		if snap.MaskingPluginDurationCount > 0 {
			avgDurationMs = (snap.MaskingPluginDurationSumSecs / float64(snap.MaskingPluginDurationCount)) * 1000
		}

		status := Status{
			ConnectionsTotal:           snap.ConnectionsTotal,
			BlockedQueriesTotal:        snap.BlockedQueriesTotal,
			ActiveRules:                activeRules,
			MaskedCellsTotal:           snap.MaskedCellsTotal,
			MaskingErrorsTotal:         snap.MaskingErrorsTotal,
			MaskingPluginAvgDurationMs: avgDurationMs,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})
}

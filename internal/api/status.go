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

		status := Status{
			ConnectionsTotal:    snap.ConnectionsTotal,
			BlockedQueriesTotal: snap.BlockedQueriesTotal,
			ActiveRules:         activeRules,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})
}

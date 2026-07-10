// Package metrics, SentinelDB gateway'inin Prometheus üzerinden dışarı
// verdiği sayaçları tanımlar.
package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	nameConnectionsTotal    = "sentineldb_connections_total"
	nameBlockedQueriesTotal = "sentineldb_blocked_queries_total"
)

// Metrics, gateway'in dışa verdiği Prometheus sayaçlarını bir arada tutar.
type Metrics struct {
	// ConnectionsTotal, gateway'e gelen toplam TCP bağlantı sayısıdır.
	ConnectionsTotal prometheus.Counter
	// BlockedQueriesTotal, firewall politikası tarafından engellenen
	// (gerçek veritabanına hiç ulaştırılmayan) sorgu sayısıdır.
	BlockedQueriesTotal prometheus.Counter

	registry *prometheus.Registry
}

// New, verilen registry'ye kayıtlı yeni bir Metrics döndürür. Aynı registry,
// /metrics endpoint'ini sunmak için promhttp.HandlerFor'a verilebilir.
func New(reg *prometheus.Registry) *Metrics {
	m := &Metrics{
		ConnectionsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: nameConnectionsTotal,
			Help: "Gateway'e gelen toplam TCP bağlantı sayısı.",
		}),
		BlockedQueriesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: nameBlockedQueriesTotal,
			Help: "Firewall politikası tarafından engellenen tehlikeli sorgu sayısı.",
		}),
		registry: reg,
	}
	reg.MustRegister(m.ConnectionsTotal, m.BlockedQueriesTotal)
	return m
}

// Snapshot, sayaçların o anki değerlerini basit bir veri yapısı olarak
// döndürür. Prometheus istemcisi sayaç değerlerinin doğrudan okunmasını
// desteklemez (by design); resmi yol, sayacın kayıtlı olduğu registry'yi
// Gather etmektir — /api/status gibi bir JSON endpoint'i beslemek için de
// aynı yol kullanılır.
func (m *Metrics) Snapshot() (Snapshot, error) {
	families, err := m.registry.Gather()
	if err != nil {
		return Snapshot{}, fmt.Errorf("metrikler toplanamadi: %w", err)
	}

	var snap Snapshot
	for _, f := range families {
		metrics := f.GetMetric()
		if len(metrics) == 0 {
			continue
		}
		value := metrics[0].GetCounter().GetValue()
		switch f.GetName() {
		case nameConnectionsTotal:
			snap.ConnectionsTotal = value
		case nameBlockedQueriesTotal:
			snap.BlockedQueriesTotal = value
		}
	}
	return snap, nil
}

// Snapshot, Metrics.Snapshot tarafından döndürülen, o ana ait sayaç değerleridir.
type Snapshot struct {
	ConnectionsTotal    float64
	BlockedQueriesTotal float64
}

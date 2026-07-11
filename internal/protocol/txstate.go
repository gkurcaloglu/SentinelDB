package protocol

import "sync/atomic"

// TxStatusIdle, TxStatusInTransaction ve TxStatusFailedTransaction,
// PostgreSQL ReadyForQuery mesajının taşıdığı işlem durumu baytlarıdır.
const (
	TxStatusIdle              byte = 'I'
	TxStatusInTransaction     byte = 'T'
	TxStatusFailedTransaction byte = 'E'
)

// TxState, bir bağlantının en son bilinen ReadyForQuery işlem durumunu
// (I=idle, T=işlem içinde, E=başarısız işlem) concurrency-safe şekilde
// tutar.
//
// Sunucudan gelen gerçek ReadyForQuery mesajları bu durumu günceller (bkz.
// internal/masking.Transformer); firewall.Gate, sentetik bir ReadyForQuery
// üretirken (ör. bir sorgu engellendiğinde) her zaman 'I' varsaymak yerine
// bu son bilinen durumu kullanır - böylece bir işlem ortasında engellenen
// bir sorgu, istemciye yanlışlıkla "işlem bitti/boşta" sinyali vermez.
type TxState struct {
	status atomic.Int32
}

// NewTxState, başlangıç durumu TxStatusIdle olan yeni bir TxState
// döndürür (henüz hiçbir ReadyForQuery görülmemiş bir bağlantı için doğru
// varsayılan).
func NewTxState() *TxState {
	s := &TxState{}
	s.Set(TxStatusIdle)
	return s
}

// Set, en son bilinen durumu günceller.
func (s *TxState) Set(status byte) {
	s.status.Store(int32(status))
}

// Get, en son bilinen durumu döndürür.
func (s *TxState) Get() byte {
	return byte(s.status.Load())
}

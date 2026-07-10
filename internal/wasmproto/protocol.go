// Package wasmproto, gateway (host) ile firewall/masking Wasm eklentisi
// (guest) arasındaki stdin/stdout tabanlı, sürümlü JSON operasyon
// zarfını tanımlar. Bağımlılığı olmadığı için hem internal/wasm (host,
// wazero'ya bağımlı) hem de plugins/firewall (guest, GOOS=wasip1 ile
// derlenir) tarafından güvenle import edilebilir.
//
// Tek bir yüklü Wasm modülü, versiyonlu bir operasyon zarfı üzerinden
// birden fazla işlevi (bkz. Op sabitleri) destekler; ayrı bir ikinci
// runtime ya da ayrı bir eklenti gerekmez.
package wasmproto

// ProtocolVersion, Envelope/Result şemasının sürümüdür. Host ve eklenti
// bunu karşılıklı doğrular; uyuşmazlık bir eklenti protokolü hatası
// sayılır (fail-closed).
const ProtocolVersion = 1

// Desteklenen operasyonlar.
const (
	OpEvaluateQuery = "evaluate_query"
	OpMaskValue     = "mask_value"
)

// evaluate_query için geçerli kararlar.
const (
	VerdictAllow = "ALLOW"
	VerdictBlock = "BLOCK"
)

// mask_value için desteklenen maskeleme türleri (kind). V1'de yalnızca
// KindEmail vardır.
const (
	KindEmail = "email"
)

// Envelope, host'un eklentiye stdin üzerinden JSON olarak gönderdiği
// istektir. Hangi alanların dolu olması gerektiği Op'a göre değişir:
//
//   - OpEvaluateQuery: Query, BlockedPhrases
//   - OpMaskValue: Column, Kind, Value
type Envelope struct {
	Version int    `json:"version"`
	Op      string `json:"op"`

	// OpEvaluateQuery alanları.
	Query          string   `json:"query,omitempty"`
	BlockedPhrases []string `json:"blocked_phrases,omitempty"`

	// OpMaskValue alanları.
	Column string `json:"column,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Value  string `json:"value,omitempty"`
}

// Result, eklentinin stdout üzerinden JSON olarak döndürdüğü yanıttır.
// Error doluysa isteğin işlenemediği anlamına gelir (bilinmeyen operasyon,
// eksik alan, vb.); bu durumda Verdict/Value/Changed geçersiz sayılmalı ve
// host fail-closed davranmalıdır.
type Result struct {
	Version int    `json:"version"`
	Op      string `json:"op"`
	Error   string `json:"error,omitempty"`

	// OpEvaluateQuery yanıt alanları.
	Verdict string `json:"verdict,omitempty"`

	// Hem OpEvaluateQuery (engelleme sebebi) hem OpMaskValue (isteğe
	// bağlı açıklama) tarafından kullanılır.
	Reason string `json:"reason,omitempty"`

	// OpMaskValue yanıt alanları.
	Value   string `json:"value,omitempty"`
	Changed bool   `json:"changed,omitempty"`
}

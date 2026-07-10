// Package wasmproto, gateway (host) ile firewall Wasm eklentisi (guest)
// arasındaki stdin/stdout tabanlı JSON protokolünü tanımlar. Bağımlılığı
// olmadığı için hem internal/wasm (host, wazero'ya bağımlı) hem de
// plugins/firewall (guest, GOOS=wasip1 ile derlenir) tarafından güvenle
// import edilebilir.
package wasmproto

// Request, host'un eklentiye stdin üzerinden JSON olarak gönderdiği giriştir.
type Request struct {
	Query          string   `json:"query"`
	BlockedPhrases []string `json:"blocked_phrases"`
}

// Response, eklentinin stdout üzerinden JSON olarak döndürdüğü karardır.
type Response struct {
	Verdict string `json:"verdict"` // VerdictAllow ya da VerdictBlock
	Reason  string `json:"reason,omitempty"`
}

const (
	VerdictAllow = "ALLOW"
	VerdictBlock = "BLOCK"
)

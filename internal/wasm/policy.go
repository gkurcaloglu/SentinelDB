package wasm

import (
	"context"
	"fmt"

	"github.com/gkurcaloglu/sentineldb/internal/firewall"
	"github.com/gkurcaloglu/sentineldb/internal/protocol"
	"github.com/gkurcaloglu/sentineldb/internal/wasmproto"
)

// evaluator, Policy'nin ihtiyaç duyduğu tek metodu tanımlar. *Runtime bunu
// karşılar; testlerde gerçek bir Wasm eklentisi derlemeden sahte bir
// evaluator enjekte etmeyi mümkün kılar.
type evaluator interface {
	Evaluate(ctx context.Context, query string, blockedPhrases []string) (verdict, reason string, err error)
}

// Policy, mevcut internal/firewall.Policy arayüzünü bir Wasm eklentisinden
// (Runtime.Evaluate) besleyen bir implementasyondur. Böylece
// firewall.NewGate hiç değişmeden, native firewall.DenyKeywords yerine bu
// Policy verilerek karar mantığı tamamen Wasm sandbox'ına taşınabilir.
type Policy struct {
	rt             evaluator
	blockedPhrases []string
	onError        func(error)
}

// NewPolicy, rt üzerinden çalışan bir Policy oluşturur. blockedPhrases,
// config.yaml'dan okunan yasaklı ifade listesidir; her Evaluate çağrısında
// eklentiye parametre olarak geçilir (eklenti kendi başına bir kelime
// listesine sahip değildir, tamamen host'un verdiği listeye göre karar
// verir). onError, Wasm çağrısı başarısız olduğunda (ör. zaman aşımı, bozuk
// çıktı) loglama amacıyla çağrılır; nil olabilir.
func NewPolicy(rt *Runtime, blockedPhrases []string, onError func(error)) *Policy {
	return &Policy{rt: rt, blockedPhrases: blockedPhrases, onError: onError}
}

// Evaluate, firewall.Policy arayüzünü karşılar.
func (p *Policy) Evaluate(m protocol.Message) (firewall.Verdict, string) {
	if m.Type != protocol.MsgQuery {
		return firewall.Allow, ""
	}

	verdict, reason, err := p.rt.Evaluate(context.Background(), m.Query, p.blockedPhrases)
	if err != nil {
		return p.failClosed(fmt.Errorf("wasm politika degerlendirmesi basarisiz: %w", err))
	}

	// Yalnizca tam olarak "ALLOW" ve "BLOCK" gecerli kararlardir. Eksik,
	// hatali yazilmis (ör. "BLOKC") ya da beklenmeyen herhangi bir deger
	// bir eklenti protokolu hatasi sayilir ve ayni calisma zamani hatasi
	// gibi guvenli tarafta kalinip sorgu engellenir (fail-closed). Onceki
	// implementasyon yalnizca "BLOCK" ile esitligi kontrol edip her sey
	// digerini sessizce Allow sayiyordu; bu, eklentinin bozuk/beklenmedik
	// bir cikti uretmesi durumunda politika denetimini fiilen devre disi
	// birakabilirdi.
	switch verdict {
	case wasmproto.VerdictAllow:
		return firewall.Allow, ""
	case wasmproto.VerdictBlock:
		return firewall.Block, reason
	default:
		return p.failClosed(fmt.Errorf("eklenti gecersiz verdict dondurdu: %q", verdict))
	}
}

// failClosed, wasm calisma zamani hatasi ya da eklenti sozlesmesine
// uymayan bir verdict oldugunda ortak guvenli-taraf davranisini uygular:
// hatayi (varsa) onError'a bildirir ve sorguyu engeller.
func (p *Policy) failClosed(err error) (firewall.Verdict, string) {
	if p.onError != nil {
		p.onError(err)
	}
	return firewall.Block, "SentinelDB policy: wasm degerlendirme hatasi, sorgu guvenlik icin engellendi"
}

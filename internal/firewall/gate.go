package firewall

import (
	"io"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// Gate, client -> server yönünü bir Policy'ye göre denetleyen aktif bir
// yönlendiricidir. protocol.SniffReader'ın aksine (salt gözlemci, akışı
// değiştirmez), Gate akışa fiilen müdahale eder: izin verilen (Allow)
// mesajların ham baytlarını target'a olduğu gibi yazar; engellenen
// (Block) mesajlar target'a hiç ulaşmaz, bunun yerine doğrudan respond'a
// (gerçek client bağlantısı) sentetik bir ErrorResponse + ReadyForQuery
// yazılır. Böylece istemci, protokol açısından normal bir sorgu hatası
// almış gibi davranır ve senkron durumunu kaybetmez.
type Gate struct {
	dec      *protocol.Decoder
	target   io.Writer
	respond  io.Writer
	policy   Policy
	onDecide func(protocol.Message, Verdict, string)
	err      error
}

// NewGate, verilen Policy ile bir Gate oluşturur. target, izin verilen
// mesajların iletileceği gerçek sunucu bağlantısıdır; respond, engelleme
// yanıtlarının yazılacağı gerçek client bağlantısıdır. onDecide her mesaj
// için (loglama amacıyla) çağrılır; nil olabilir.
//
// Dönen Gate kendi protocol.Decoder'ını yönetir. SSL/GSS müzakeresi için
// karşı yöndeki (server) Decoder'a bağlamak amacıyla Decoder() ile erişilebilir.
func NewGate(policy Policy, target, respond io.Writer, onDecide func(protocol.Message, Verdict, string), onError func(error)) *Gate {
	g := &Gate{target: target, respond: respond, policy: policy, onDecide: onDecide}
	g.dec = protocol.NewClientDecoder(g.handle, onError)
	return g
}

// Decoder, Gate'in kullandığı alttaki protocol.Decoder'a erişim sağlar.
func (g *Gate) Decoder() *protocol.Decoder {
	return g.dec
}

// Run, client'tan EOF olana ya da bir yazma hatası oluşana kadar okur.
// Okunan her tam mesaj için politika uygulanır. io.Copy ile aynı hata
// sözleşmesine sahiptir: normal kapanışta nil, aksi halde oluşan hata
// döndürülür.
func (g *Gate) Run(client io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := client.Read(buf)
		if n > 0 {
			g.dec.Write(buf[:n])
			if g.err != nil {
				return g.err
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

func (g *Gate) handle(m protocol.Message) {
	if g.err != nil {
		return
	}

	verdict, reason := Allow, ""
	if g.policy != nil {
		verdict, reason = g.policy.Evaluate(m)
	}
	if g.onDecide != nil {
		g.onDecide(m, verdict, reason)
	}

	if verdict == Block {
		if _, err := g.respond.Write(protocol.BuildErrorResponse("ERROR", "42501", reason)); err != nil {
			g.err = err
			return
		}
		if _, err := g.respond.Write(protocol.BuildReadyForQuery('I')); err != nil {
			g.err = err
		}
		return
	}

	if len(m.Raw) > 0 {
		if _, err := g.target.Write(m.Raw); err != nil {
			g.err = err
		}
	}
}

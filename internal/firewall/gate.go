package firewall

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// ErrUnsupportedProtocol, client PostgreSQL genişletilmiş sorgu protokolüne
// (Parse/Bind/Describe/Execute/Close/Flush/Sync) ait bir mesaj gönderdiğinde
// Run tarafından döndürülür. SentinelDB V1 yalnızca Simple Query Protokolünü
// (tek 'Q' mesajı) destekler; bkz. Gate.handle.
var ErrUnsupportedProtocol = errors.New("firewall: desteklenmeyen genisletilmis sorgu protokolu mesaji")

// ErrDecodeFailed, alttaki protocol.Decoder bir mesajı ayrıştıramadığında
// (bozuk, aşırı büyük ya da desteklenmeyen bir uzunluk alanı) Run
// tarafından döndürülür. Bu durumda Gate, ayrıştırılamayan baytları
// sessizce yutup akışı "passthrough" olarak geçirmez (bu, politika
// denetimini atlatabilirdi); bunun yerine istemciye bir hata döner ve
// bağlantıyı güvenli şekilde kapatır.
var ErrDecodeFailed = errors.New("firewall: protokol ayristirma hatasi, baglanti kapatildi")

// IsFailClosed, Run'ın döndürdüğü bir hatanın, Gate'in bilerek (istemciye
// bir ErrorResponse yazıp) bağlantıyı kapattığı bir "fail-closed" durumu mu,
// yoksa sıradan bir G/Ç hatası mı olduğunu ayırt etmeye yarar. Çağıran
// (cmd/gateway), bu durumda upstream bağlantısını hemen tam kapatarak karşı
// yöndeki bloklu okumanın da hemen sonlanmasını sağlayabilir; aksi halde
// yarım kapanmanın (CloseWrite) sunucu tarafından fark edilmesini bekler.
func IsFailClosed(err error) bool {
	return errors.Is(err, ErrUnsupportedProtocol) || errors.Is(err, ErrDecodeFailed)
}

// Gate, client -> server yönünü bir Policy'ye göre denetleyen aktif bir
// yönlendiricidir. protocol.SniffReader'ın aksine (salt gözlemci, akışı
// değiştirmez), Gate akışa fiilen müdahale eder: izin verilen (Allow)
// mesajların ham baytlarını target'a olduğu gibi yazar; engellenen
// (Block) mesajlar target'a hiç ulaşmaz, bunun yerine doğrudan respond'a
// (gerçek client bağlantısı) sentetik bir ErrorResponse + ReadyForQuery
// yazılır. Böylece istemci, protokol açısından normal bir sorgu hatası
// almış gibi davranır ve senkron durumunu kaybetmez.
//
// Gate ayrıca V1 kapsamının sınırlarını da uygular:
//   - SSLRequest/GSSENCRequest asla gerçek sunucuya iletilmez; Gate
//     istemciye doğrudan 'N' (reddedildi) yazar, böylece trafik her zaman
//     düz metin kalır ve incelenebilir.
//   - Genişletilmiş sorgu protokolü (Parse/Bind/Describe/Execute/Close/
//     Flush/Sync) desteklenmez: bu mesajlar politika denetimini
//     atlatabileceğinden sessizce iletilmez; bunun yerine bir
//     ErrorResponse yazılır ve bağlantı kapatılır (ErrUnsupportedProtocol).
//   - Ayrıştırılamayan (bozuk/aşırı büyük) mesajlar "passthrough"a
//     düşürülüp sessizce yutulmaz; Gate bir ErrorResponse yazıp bağlantıyı
//     kapatır (ErrDecodeFailed).
type Gate struct {
	dec      *protocol.Decoder
	target   io.Writer
	respond  io.Writer
	policy   Policy
	onDecide func(m protocol.Message, v Verdict, reason string, duration time.Duration)
	onError  func(error)
	err      error
	txState  *protocol.TxState
}

// NewGate, verilen Policy ile bir Gate oluşturur. target, izin verilen
// mesajların iletileceği gerçek sunucu bağlantısıdır; respond, engelleme
// yanıtlarının yazılacağı gerçek client bağlantısıdır. onDecide her
// politika/protokol kararı için (loglama amacıyla) çağrılır; nil olabilir.
// onError, alttaki Decoder ayrıştırma hatalarında çağrılır; nil olabilir.
//
// Dönen Gate kendi protocol.Decoder'ını yönetir.
func NewGate(policy Policy, target, respond io.Writer, onDecide func(m protocol.Message, v Verdict, reason string, duration time.Duration), onError func(error)) *Gate {
	g := &Gate{target: target, respond: respond, policy: policy, onDecide: onDecide, onError: onError}
	g.dec = protocol.NewClientDecoder(g.handle, g.handleDecodeError)
	return g
}

// Decoder, Gate'in kullandığı alttaki protocol.Decoder'a erişim sağlar.
func (g *Gate) Decoder() *protocol.Decoder {
	return g.dec
}

// SetTxState, Gate'in sentetik ReadyForQuery ürettiğinde (bir sorgu
// engellendiğinde) kullanacağı paylaşılan işlem-durumu izleyicisini
// bağlar. ts nil ise (ya da hiç çağrılmazsa) Gate her zaman 'I' (idle)
// varsayar - önceki davranışla birebir aynıdır.
//
// ts, tipik olarak internal/masking.Transformer'ın gerçek sunucudan gelen
// ReadyForQuery mesajlarıyla güncellediği AYNI *protocol.TxState'tir;
// böylece bir işlem ortasında ('T') engellenen bir sorgu, istemciye
// yanlışlıkla "işlem bitti" sinyali vermez.
func (g *Gate) SetTxState(ts *protocol.TxState) {
	g.txState = ts
}

func (g *Gate) readyForQueryStatus() byte {
	if g.txState != nil {
		return g.txState.Get()
	}
	return protocol.TxStatusIdle
}

// Run, client'tan EOF olana ya da bir hata oluşana kadar okur. Okunan her
// tam mesaj için politika uygulanır. Normal kapanışta nil, ayrıştırma ya da
// desteklenmeyen protokol nedeniyle bilerek kapatılan bağlantılarda
// ErrDecodeFailed/ErrUnsupportedProtocol (bkz. IsFailClosed), aksi halde
// oluşan G/Ç hatası döndürülür.
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

// handleDecodeError, alttaki Decoder bir mesajı ayrıştıramadığında çağrılır
// (bkz. ErrDecodeFailed). Decoder kendisi "passthrough"a düşüp baytları
// sessizce yutmaya devam edeceği için (bkz. protocol.Decoder.fail), Gate
// burada araya girip istemciye bir hata döndürüp bağlantıyı kapatarak
// bunun bir güvenlik boşluğuna dönüşmesini engeller.
func (g *Gate) handleDecodeError(err error) {
	if g.onError != nil {
		g.onError(err)
	}
	if g.err != nil {
		return
	}
	const reason = "SentinelDB policy: protokol ayristirilamadi, baglanti guvenlik icin kapatildi"
	g.respond.Write(protocol.BuildErrorResponse("FATAL", "08P01", reason))
	g.err = fmt.Errorf("%w: %v", ErrDecodeFailed, err)
}

func (g *Gate) handle(m protocol.Message) {
	if g.err != nil {
		return
	}

	// SentinelDB V1 sifrelemeyi desteklemez: trafigin her zaman duz metin
	// kalmasi gerekir ki Policy denetimi yapilabilsin. SSLRequest/
	// GSSENCRequest bu yuzden gercek sunucuya HIC iletilmez; Gate
	// istemciye dogrudan 'N' (reddedildi) yazar ve istemci duz metin
	// StartupMessage ile devam eder (bkz. protocol.Decoder.consumeStartup,
	// bu mesajdan sonra dogrudan phaseStartup'a doner).
	if m.Name == protocol.NameSSLRequest || m.Name == protocol.NameGSSENCRequest {
		if g.onDecide != nil {
			g.onDecide(m, Allow, "", 0)
		}
		if _, err := g.respond.Write([]byte{'N'}); err != nil {
			g.err = err
		}
		return
	}

	// SentinelDB V1 yalnizca Simple Query Protokolunu destekler. Genisletilmis
	// protokol mesajlari (Parse/Bind/Describe/Execute/Close/Flush/Sync)
	// keyfi SQL metni tasiyabilir; bunlari Policy'ye hic sormadan sessizce
	// gercek sunucuya iletmek, firewall'u tamamen atlatmanin bir yolu olurdu.
	// Bu yuzden V1 bu mesajlari reddeder: istemciye aciklayici bir
	// ErrorResponse doner ve baglantiyi kapatir (dogru "resync" semantigi
	// -hatadan sonraki Sync'e kadar gelen mesajlari yoksayip
	// ReadyForQuery donmek- gercek bir extended-protocol uygulamasi
	// gerektirir; bu V1 kapsaminin disindadir).
	if isExtendedProtocolMessage(m.Type) {
		g.rejectExtendedProtocol(m)
		return
	}

	start := time.Now()
	verdict, reason := Allow, ""
	if g.policy != nil {
		verdict, reason = g.policy.Evaluate(m)
	}
	duration := time.Since(start)
	if g.onDecide != nil {
		g.onDecide(m, verdict, reason, duration)
	}

	if verdict == Block {
		if _, err := g.respond.Write(protocol.BuildErrorResponse("ERROR", "42501", reason)); err != nil {
			g.err = err
			return
		}
		if _, err := g.respond.Write(protocol.BuildReadyForQuery(g.readyForQueryStatus())); err != nil {
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

// isExtendedProtocolMessage, PostgreSQL genişletilmiş sorgu protokolüne ait
// frontend mesaj tiplerini tanır. SentinelDB V1 yalnızca Simple Query
// Protokolünü (tek 'Q' mesajı) destekler; bkz. Gate.handle ve Gate doc
// yorumu.
func isExtendedProtocolMessage(t protocol.MessageType) bool {
	switch t {
	case protocol.MsgParse, protocol.MsgBind, protocol.MsgDescribe,
		protocol.MsgExecute, protocol.MsgClose, protocol.MsgFlush, protocol.MsgSync:
		return true
	default:
		return false
	}
}

func (g *Gate) rejectExtendedProtocol(m protocol.Message) {
	const reason = "SentinelDB V1 yalnizca Simple Query Protokolunu destekler; genisletilmis sorgu protokolu (Parse/Bind/Describe/Execute/Close/Flush/Sync) bu surumde desteklenmiyor."
	if g.onDecide != nil {
		g.onDecide(m, Block, reason, 0)
	}
	if _, err := g.respond.Write(protocol.BuildErrorResponse("ERROR", "0A000", reason)); err != nil {
		g.err = err
		return
	}
	g.err = ErrUnsupportedProtocol
}

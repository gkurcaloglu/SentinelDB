package firewall

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

func encodeQuery(sql string) []byte {
	payload := append([]byte(sql), 0)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)+4))
	return append(append([]byte{byte(protocol.MsgQuery)}, length...), payload...)
}

func encodeSSLRequest() []byte {
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], 80877103)
	return req
}

// encodeParse, genisletilmis sorgu protokolunun Parse ('P') mesajini uretir.
// Gercek bir istemci (ör. bir ORM/driver), tehlikeli SQL'i pekala bunun
// icinde tasiyabilir - tam olarak Gate'in D gorevi kapsaminda engellemesi
// gereken senaryo budur.
func encodeParse(statementName, query string) []byte {
	var payload []byte
	payload = append(payload, []byte(statementName)...)
	payload = append(payload, 0)
	payload = append(payload, []byte(query)...)
	payload = append(payload, 0)
	payload = append(payload, 0, 0) // parametre tipi sayisi: 0
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)+4))
	return append(append([]byte{byte(protocol.MsgParse)}, length...), payload...)
}

// encodeStartupMessage, gercek bir baglantida her zaman ilk gonderilen
// mesaji uretir. Gate'in Decoder'i phaseStartup'ta baslar, bu yuzden test
// akislari Query'lerden once bunu icermeli (tipki gercek bir psql
// baglantisinda oldugu gibi).
func encodeStartupMessage() []byte {
	body := []byte{0, 3, 0, 0} // protokol 3.0
	body = append(body, []byte("user")...)
	body = append(body, 0)
	body = append(body, []byte("sentinel")...)
	body = append(body, 0)
	body = append(body, 0)

	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(body)+4))
	return append(length, body...)
}

func TestGate_AllowsSafeQuery(t *testing.T) {
	var target, respond bytes.Buffer
	var decisions []Verdict
	g := NewGate(DenyKeywords("DROP TABLE", "DELETE FROM"), &target, &respond,
		func(m protocol.Message, v Verdict, reason string, duration time.Duration) {
			decisions = append(decisions, v)
		},
		func(err error) { t.Fatalf("unexpected decode error: %v", err) },
	)

	startup := encodeStartupMessage()
	query := encodeQuery("SELECT 1")
	stream := append(append([]byte{}, startup...), query...)
	if err := g.Run(bytes.NewReader(stream)); err != nil {
		t.Fatalf("unexpected Run error: %v", err)
	}

	if !bytes.Equal(target.Bytes(), stream) {
		t.Fatalf("expected raw bytes forwarded to target unchanged\ngot:  %v\nwant: %v", target.Bytes(), stream)
	}
	if respond.Len() != 0 {
		t.Fatalf("expected no response written to client for an allowed query, got %d bytes", respond.Len())
	}
	if len(decisions) != 2 || decisions[0] != Allow || decisions[1] != Allow {
		t.Fatalf("expected [Allow, Allow] (startup, query), got %+v", decisions)
	}
}

func TestGate_BlocksDangerousQuery(t *testing.T) {
	var target, respond bytes.Buffer
	var decisions []Verdict
	var reasons []string
	g := NewGate(DenyKeywords("DROP TABLE"), &target, &respond,
		func(m protocol.Message, v Verdict, reason string, duration time.Duration) {
			decisions = append(decisions, v)
			reasons = append(reasons, reason)
		},
		func(err error) { t.Fatalf("unexpected decode error: %v", err) },
	)

	startup := encodeStartupMessage()
	query := encodeQuery("DROP TABLE users;")
	stream := append(append([]byte{}, startup...), query...)
	if err := g.Run(bytes.NewReader(stream)); err != nil {
		t.Fatalf("unexpected Run error: %v", err)
	}

	if !bytes.Equal(target.Bytes(), startup) {
		t.Fatalf("expected only the StartupMessage forwarded to target, blocked query must not reach it\ngot:  %v\nwant: %v", target.Bytes(), startup)
	}
	if len(decisions) != 2 || decisions[0] != Allow || decisions[1] != Block {
		t.Fatalf("expected [Allow, Block] (startup, query), got %+v", decisions)
	}
	if reasons[1] == "" {
		t.Fatalf("expected a non-empty block reason")
	}

	// respond'a yazilan baytlarin gercek, gecerli bir ErrorResponse +
	// ReadyForQuery cifti oldugunu bagimsiz bir Decoder ile geri cozerek
	// dogrula (istemcinin senkron durumunu kaybetmemesi icin sart).
	var got []protocol.Message
	dec := protocol.NewServerDecoder(func(m protocol.Message) { got = append(got, m) }, func(err error) {
		t.Fatalf("unexpected re-decode error: %v", err)
	})
	dec.Write(respond.Bytes())

	if len(got) != 2 || got[0].Name != "ErrorResponse" || got[1].Name != "ReadyForQuery" {
		t.Fatalf("expected [ErrorResponse, ReadyForQuery] in response, got %+v", got)
	}
}

func TestGate_MultipleQueriesInOneStream(t *testing.T) {
	var target, respond bytes.Buffer
	var verdicts []Verdict
	g := NewGate(DenyKeywords("DROP TABLE"), &target, &respond,
		func(m protocol.Message, v Verdict, reason string, duration time.Duration) {
			verdicts = append(verdicts, v)
		},
		func(err error) { t.Fatalf("unexpected decode error: %v", err) },
	)

	var stream bytes.Buffer
	stream.Write(encodeStartupMessage())
	stream.Write(encodeQuery("SELECT 1"))
	stream.Write(encodeQuery("DROP TABLE users;"))
	stream.Write(encodeQuery("SELECT 2"))

	if err := g.Run(&stream); err != nil {
		t.Fatalf("unexpected Run error: %v", err)
	}

	if len(verdicts) != 4 || verdicts[0] != Allow || verdicts[1] != Allow || verdicts[2] != Block || verdicts[3] != Allow {
		t.Fatalf("expected [Allow, Allow, Block, Allow] (startup, select, drop, select), got %+v", verdicts)
	}

	wantTarget := append(append([]byte{}, encodeStartupMessage()...), encodeQuery("SELECT 1")...)
	wantTarget = append(wantTarget, encodeQuery("SELECT 2")...)
	if !bytes.Equal(target.Bytes(), wantTarget) {
		t.Fatalf("expected the startup message and the two safe queries forwarded to target\ngot:  %v\nwant: %v", target.Bytes(), wantTarget)
	}
	if respond.Len() == 0 {
		t.Fatalf("expected a block response to have been written for the dangerous query")
	}
}

// TestGate_SSLRequest_RepliesNDirectlyWithoutForwarding gorev C'yi dogrular:
// SentinelDB V1 sifrelemeyi desteklemez. SSLRequest gercek sunucuya HIC
// iletilmemeli; Gate istemciye dogrudan tek bir 'N' baytiyla cevap vermeli
// ve istemcinin ardindan gonderdigi duz metin StartupMessage'i normal
// sekilde ilerlemelidir.
func TestGate_SSLRequest_RepliesNDirectlyWithoutForwarding(t *testing.T) {
	var target, respond bytes.Buffer
	var decisions []Verdict
	g := NewGate(DenyKeywords("DROP TABLE"), &target, &respond,
		func(m protocol.Message, v Verdict, reason string, duration time.Duration) {
			decisions = append(decisions, v)
		},
		func(err error) { t.Fatalf("unexpected decode error: %v", err) },
	)

	sslRequest := encodeSSLRequest()
	startup := encodeStartupMessage()
	stream := append(append([]byte{}, sslRequest...), startup...)

	if err := g.Run(bytes.NewReader(stream)); err != nil {
		t.Fatalf("unexpected Run error: %v", err)
	}

	if !bytes.Equal(respond.Bytes(), []byte{'N'}) {
		t.Fatalf("expected respond to contain exactly a single 'N' byte, got %v", respond.Bytes())
	}
	if !bytes.Equal(target.Bytes(), startup) {
		t.Fatalf("expected the SSLRequest to never reach target, only the plaintext StartupMessage\ngot:  %v\nwant: %v", target.Bytes(), startup)
	}
	if len(decisions) != 2 || decisions[0] != Allow || decisions[1] != Allow {
		t.Fatalf("expected [Allow, Allow] (sslrequest handled internally, then startup forwarded), got %+v", decisions)
	}
}

// TestGate_ParseMessageCannotBypassInspection gorev D'yi dogrular: bir
// istemci Simple Query yerine genisletilmis protokolun Parse mesajini
// kullanip tehlikeli SQL'i icine gizleyerek politikayi atlatmaya
// calisirsa, bu mesaj hicbir zaman target'a ulasmamali; bunun yerine bir
// ErrorResponse donup baglanti guvenli sekilde kapatilmalidir.
func TestGate_ParseMessageCannotBypassInspection(t *testing.T) {
	var target, respond bytes.Buffer
	var decisions []Verdict
	var reasons []string
	g := NewGate(DenyKeywords("DROP TABLE"), &target, &respond,
		func(m protocol.Message, v Verdict, reason string, duration time.Duration) {
			decisions = append(decisions, v)
			reasons = append(reasons, reason)
		},
		func(err error) { t.Fatalf("unexpected decode error: %v", err) },
	)

	startup := encodeStartupMessage()
	parse := encodeParse("", "DROP TABLE users;")
	stream := append(append([]byte{}, startup...), parse...)

	err := g.Run(bytes.NewReader(stream))
	if !errors.Is(err, ErrUnsupportedProtocol) || !IsFailClosed(err) {
		t.Fatalf("expected ErrUnsupportedProtocol (fail-closed), got %v", err)
	}

	if !bytes.Equal(target.Bytes(), startup) {
		t.Fatalf("expected the Parse message to NEVER reach target (would bypass inspection)\ngot:  %v\nwant: %v", target.Bytes(), startup)
	}
	if len(decisions) != 2 || decisions[0] != Allow || decisions[1] != Block {
		t.Fatalf("expected [Allow, Block] (startup, parse-rejected), got %+v", decisions)
	}
	if reasons[1] == "" {
		t.Fatalf("expected a non-empty rejection reason for the Parse message")
	}

	var got []protocol.Message
	dec := protocol.NewServerDecoder(func(m protocol.Message) { got = append(got, m) }, func(err error) {
		t.Fatalf("unexpected re-decode error: %v", err)
	})
	dec.Write(respond.Bytes())
	if len(got) != 1 || got[0].Name != "ErrorResponse" {
		t.Fatalf("expected a single ErrorResponse in response, got %+v", got)
	}
}

// TestGate_ExtendedProtocolMessages_AllRejected, Parse disindaki tum
// genisletilmis protokol mesaj tiplerinin de (Bind/Describe/Execute/Close/
// Flush/Sync) ayni sekilde reddedildigini dogrular.
func TestGate_ExtendedProtocolMessages_AllRejected(t *testing.T) {
	msgTypes := []protocol.MessageType{
		protocol.MsgBind, protocol.MsgDescribe, protocol.MsgExecute,
		protocol.MsgClose, protocol.MsgFlush, protocol.MsgSync,
	}

	for _, mt := range msgTypes {
		t.Run(string(rune(mt)), func(t *testing.T) {
			var target, respond bytes.Buffer
			g := NewGate(DenyKeywords("DROP TABLE"), &target, &respond,
				func(m protocol.Message, v Verdict, reason string, duration time.Duration) {},
				func(err error) { t.Fatalf("unexpected decode error: %v", err) },
			)

			startup := encodeStartupMessage()
			// Govdesi bos, sadece tag+length'i test edilen tipe ait bir mesaj.
			msg := append([]byte{byte(mt)}, 0, 0, 0, 4)
			stream := append(append([]byte{}, startup...), msg...)

			err := g.Run(bytes.NewReader(stream))
			if !errors.Is(err, ErrUnsupportedProtocol) {
				t.Fatalf("expected ErrUnsupportedProtocol for message type %q, got %v", mt, err)
			}
			if !bytes.Equal(target.Bytes(), startup) {
				t.Fatalf("expected message type %q to never reach target, got %v", mt, target.Bytes())
			}
		})
	}
}

// TestGate_OversizedMessage_FailsClosed gorev E'yi dogrular: uzunluk alani
// izin verilen azami boyutu asan bir mesaj sessizce yutulup goz ardi
// edilmemeli (passthrough); bunun yerine acik bir hata ile baglanti
// guvenli sekilde kapatilmalidir.
func TestGate_OversizedMessage_FailsClosed(t *testing.T) {
	var target, respond bytes.Buffer
	var decodeErrs int
	g := NewGate(DenyKeywords("DROP TABLE"), &target, &respond,
		func(m protocol.Message, v Verdict, reason string, duration time.Duration) {},
		func(err error) { decodeErrs++ },
	)

	startup := encodeStartupMessage()
	// 0x7FFFFFFF, maxMessageLength'i (1 MiB) asiyor.
	oversized := []byte{byte(protocol.MsgQuery), 0x7F, 0xFF, 0xFF, 0xFF}
	stream := append(append([]byte{}, startup...), oversized...)

	err := g.Run(bytes.NewReader(stream))
	if !errors.Is(err, ErrDecodeFailed) || !IsFailClosed(err) {
		t.Fatalf("expected ErrDecodeFailed (fail-closed), got %v", err)
	}
	if decodeErrs != 1 {
		t.Fatalf("expected onError to be called once for the oversized message, got %d", decodeErrs)
	}
	if !bytes.Equal(target.Bytes(), startup) {
		t.Fatalf("expected only the StartupMessage forwarded, oversized message must not reach target\ngot:  %v\nwant: %v", target.Bytes(), startup)
	}
	if respond.Len() == 0 {
		t.Fatalf("expected an ErrorResponse to be written to the client")
	}
}

// TestGate_MalformedMessage_DoesNotSilentlyDiscardSubsequentBytes gorev
// E'yi dogrular: bozuk bir mesajdan sonra gelen, aksi halde gecerli olacak
// baytlar (ör. tam bir Query mesaji) sessizce yutulup yok sayilmamali.
// Gate bunun yerine baglantiyi tamamen (fail-closed) kapatir, boylece
// hicbir sey "fark edilmeden" sonradan target'a sizamaz.
func TestGate_MalformedMessage_DoesNotSilentlyDiscardSubsequentBytes(t *testing.T) {
	var target, respond bytes.Buffer
	g := NewGate(DenyKeywords("DROP TABLE"), &target, &respond,
		func(m protocol.Message, v Verdict, reason string, duration time.Duration) {},
		func(err error) {},
	)

	startup := encodeStartupMessage()
	malformed := []byte{byte(protocol.MsgQuery), 0, 0, 0, 2} // length=2, standart cerceve icin gecersiz (< 4)
	trailingQuery := encodeQuery("SELECT 1")
	stream := append(append(append([]byte{}, startup...), malformed...), trailingQuery...)

	err := g.Run(bytes.NewReader(stream))
	if !IsFailClosed(err) {
		t.Fatalf("expected a fail-closed error, got %v", err)
	}
	if bytes.Contains(target.Bytes(), []byte("SELECT 1")) {
		t.Fatalf("expected bytes after the malformed message to never silently reach target, got %v", target.Bytes())
	}
	if respond.Len() == 0 {
		t.Fatalf("expected an ErrorResponse to be written to the client instead of silent discard")
	}
}

// TestGate_BlockedQuery_UsesLastKnownTxState gorev G'yi dogrular: bir
// sorgu, baglanti bir islem (transaction) ortasindayken ('T') engellenirse,
// Gate'in urettigi sentetik ReadyForQuery her zamanki gibi sabit 'I'
// degil, SetTxState ile bildirilen son bilinen durumu tasimalidir - aksi
// halde istemciye yanlislikla "islem bitti/bosta" sinyali verilir.
func TestGate_BlockedQuery_UsesLastKnownTxState(t *testing.T) {
	var target, respond bytes.Buffer
	txState := protocol.NewTxState()
	txState.Set(protocol.TxStatusInTransaction)

	g := NewGate(DenyKeywords("DROP TABLE"), &target, &respond,
		func(m protocol.Message, v Verdict, reason string, duration time.Duration) {},
		func(err error) { t.Fatalf("unexpected decode error: %v", err) },
	)
	g.SetTxState(txState)

	startup := encodeStartupMessage()
	query := encodeQuery("DROP TABLE users;")
	stream := append(append([]byte{}, startup...), query...)

	if err := g.Run(bytes.NewReader(stream)); err != nil {
		t.Fatalf("unexpected Run error: %v", err)
	}

	var got []protocol.Message
	dec := protocol.NewServerDecoder(func(m protocol.Message) { got = append(got, m) }, func(err error) {
		t.Fatalf("unexpected re-decode error: %v", err)
	})
	dec.Write(respond.Bytes())

	if len(got) != 2 || got[1].Name != "ReadyForQuery" {
		t.Fatalf("expected [ErrorResponse, ReadyForQuery], got %+v", got)
	}
	// ReadyForQuery'nin ham baytlarindan durum baytini (tag+length'ten
	// sonraki tek bayt) dogrudan kontrol et.
	statusByte := got[1].Raw[len(got[1].Raw)-1]
	if statusByte != protocol.TxStatusInTransaction {
		t.Fatalf("expected synthetic ReadyForQuery status %q (in-transaction), got %q", protocol.TxStatusInTransaction, statusByte)
	}
}

// TestGate_BlockedQuery_DefaultsToIdleWithoutTxState, SetTxState hic
// cagrilmadiginda onceki davranisin (her zaman 'I') korundugunu dogrular.
func TestGate_BlockedQuery_DefaultsToIdleWithoutTxState(t *testing.T) {
	var target, respond bytes.Buffer
	g := NewGate(DenyKeywords("DROP TABLE"), &target, &respond,
		func(m protocol.Message, v Verdict, reason string, duration time.Duration) {},
		func(err error) { t.Fatalf("unexpected decode error: %v", err) },
	)

	startup := encodeStartupMessage()
	query := encodeQuery("DROP TABLE users;")
	stream := append(append([]byte{}, startup...), query...)

	if err := g.Run(bytes.NewReader(stream)); err != nil {
		t.Fatalf("unexpected Run error: %v", err)
	}

	var got []protocol.Message
	dec := protocol.NewServerDecoder(func(m protocol.Message) { got = append(got, m) }, func(err error) {
		t.Fatalf("unexpected re-decode error: %v", err)
	})
	dec.Write(respond.Bytes())

	if len(got) != 2 {
		t.Fatalf("expected 2 messages, got %+v", got)
	}
	statusByte := got[1].Raw[len(got[1].Raw)-1]
	if statusByte != protocol.TxStatusIdle {
		t.Fatalf("expected default status %q, got %q", protocol.TxStatusIdle, statusByte)
	}
}

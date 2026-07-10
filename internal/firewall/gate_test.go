package firewall

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

func encodeQuery(sql string) []byte {
	payload := append([]byte(sql), 0)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)+4))
	return append(append([]byte{byte(protocol.MsgQuery)}, length...), payload...)
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
		func(m protocol.Message, v Verdict, reason string) { decisions = append(decisions, v) },
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
		func(m protocol.Message, v Verdict, reason string) {
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
		func(m protocol.Message, v Verdict, reason string) { verdicts = append(verdicts, v) },
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

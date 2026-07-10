package protocol

import (
	"encoding/binary"
	"testing"
)

func encodeStartupMessage(params map[string]string) []byte {
	var body []byte
	code := make([]byte, 4)
	binary.BigEndian.PutUint32(code, 196608) // protocol 3.0
	body = append(body, code...)
	for k, v := range params {
		body = append(body, []byte(k)...)
		body = append(body, 0)
		body = append(body, []byte(v)...)
		body = append(body, 0)
	}
	body = append(body, 0)

	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(body)+4))
	return append(length, body...)
}

func encodeQuery(sql string) []byte {
	payload := append([]byte(sql), 0)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)+4))
	return append(append([]byte{byte(MsgQuery)}, length...), payload...)
}

func TestDecoder_StartupThenQuery(t *testing.T) {
	var got []Message
	dec := NewClientDecoder(func(m Message) { got = append(got, m) }, func(err error) {
		t.Fatalf("unexpected decode error: %v", err)
	})

	startup := encodeStartupMessage(map[string]string{"user": "sentinel", "database": "app"})
	query := encodeQuery("SELECT 1")

	// Baytlari tek seferde degil, parcali besleyerek eksik-cerceve yolunu da sinamis oluyoruz.
	dec.Write(startup[:3])
	dec.Write(startup[3:])
	dec.Write(query)

	if len(got) != 2 {
		t.Fatalf("expected 2 messages, got %d: %+v", len(got), got)
	}
	if got[0].Name != "StartupMessage" || got[0].StartupParams["user"] != "sentinel" || got[0].StartupParams["database"] != "app" {
		t.Fatalf("unexpected startup message: %+v", got[0])
	}
	if got[0].ProtocolMajor != 3 || got[0].ProtocolMinor != 0 {
		t.Fatalf("unexpected protocol version: %d.%d", got[0].ProtocolMajor, got[0].ProtocolMinor)
	}
	if got[1].Name != "Query" || got[1].Query != "SELECT 1" {
		t.Fatalf("unexpected query message: %+v", got[1])
	}
}

func TestDecoder_SSLRequestWithoutPeerWaitsForReply(t *testing.T) {
	var got []Message
	dec := NewClientDecoder(func(m Message) { got = append(got, m) }, func(err error) {
		t.Fatalf("unexpected decode error: %v", err)
	})

	sslRequest := make([]byte, 8)
	binary.BigEndian.PutUint32(sslRequest[0:4], 8)
	binary.BigEndian.PutUint32(sslRequest[4:8], 80877103)
	dec.Write(sslRequest)

	if len(got) != 1 || got[0].Name != "SSLRequest" {
		t.Fatalf("expected SSLRequest message, got %+v", got)
	}
	if dec.getPhase() != phasePendingSSLReply {
		t.Fatalf("expected phasePendingSSLReply after SSLRequest, got %v", dec.getPhase())
	}
}

func TestDecoder_InvalidLengthStopsParsingWithoutPanicking(t *testing.T) {
	var errs int
	dec := NewServerDecoder(func(Message) {}, func(error) { errs++ })

	bad := []byte{byte(MsgErrorResponse), 0xFF, 0xFF, 0xFF, 0xFF}
	dec.Write(bad)

	if errs != 1 {
		t.Fatalf("expected 1 decode error, got %d", errs)
	}
	if dec.getPhase() != phasePassthrough {
		t.Fatalf("expected passthrough phase after invalid length, got %v", dec.getPhase())
	}
}

// TestDecoder_SSLNegotiation_Rejected, gercek psql/postgres davranisini
// dogrular: client SSLRequest gonderir, sunucu 'N' ile reddeder, client
// duz metin StartupMessage'i tekrar gonderir ve normal akis devam eder.
func TestDecoder_SSLNegotiation_Rejected(t *testing.T) {
	var clientMsgs, serverMsgs []Message
	clientDec := NewClientDecoder(func(m Message) { clientMsgs = append(clientMsgs, m) }, func(err error) {
		t.Fatalf("unexpected client decode error: %v", err)
	})
	serverDec := NewServerDecoder(func(m Message) { serverMsgs = append(serverMsgs, m) }, func(err error) {
		t.Fatalf("unexpected server decode error: %v", err)
	})
	clientDec.SetPeer(serverDec)
	serverDec.SetPeer(clientDec)

	sslRequest := make([]byte, 8)
	binary.BigEndian.PutUint32(sslRequest[0:4], 8)
	binary.BigEndian.PutUint32(sslRequest[4:8], 80877103)
	clientDec.Write(sslRequest)

	if clientDec.getPhase() != phasePendingSSLReply {
		t.Fatalf("expected client phasePendingSSLReply, got %v", clientDec.getPhase())
	}
	if serverDec.getPhase() != phaseSSLReply {
		t.Fatalf("expected server phaseSSLReply, got %v", serverDec.getPhase())
	}

	serverDec.Write([]byte{'N'})

	if clientDec.getPhase() != phaseStartup {
		t.Fatalf("expected client back to phaseStartup after 'N', got %v", clientDec.getPhase())
	}
	if serverDec.getPhase() != phaseNormal {
		t.Fatalf("expected server phaseNormal after 'N', got %v", serverDec.getPhase())
	}

	// Client artik duz metin StartupMessage'i tekrar gonderir.
	startup := encodeStartupMessage(map[string]string{"user": "sentinel"})
	clientDec.Write(startup)

	found := false
	for _, m := range clientMsgs {
		if m.Name == "StartupMessage" && m.StartupParams["user"] == "sentinel" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected retried StartupMessage to be parsed, got %+v", clientMsgs)
	}

	// Sunucu artik normal cerceveli mesajlar gonderebilir (ör. Authentication).
	auth := []byte{byte(MsgAuthentication), 0, 0, 0, 8, 0, 0, 0, 0}
	serverDec.Write(auth)
	if len(serverMsgs) < 2 || serverMsgs[len(serverMsgs)-1].Name != "Authentication" {
		t.Fatalf("expected Authentication message to be parsed after negotiation, got %+v", serverMsgs)
	}
}

// TestDecoder_SSLNegotiation_Accepted, sunucunun sifrelemeyi kabul ettigi
// durumda her iki yonun de passthrough'a gectigini dogrular (TLS
// handshake'i ayristirmaya calismiyoruz).
func TestDecoder_SSLNegotiation_Accepted(t *testing.T) {
	clientDec := NewClientDecoder(func(Message) {}, func(err error) {
		t.Fatalf("unexpected client decode error: %v", err)
	})
	serverDec := NewServerDecoder(func(Message) {}, func(err error) {
		t.Fatalf("unexpected server decode error: %v", err)
	})
	clientDec.SetPeer(serverDec)
	serverDec.SetPeer(clientDec)

	sslRequest := make([]byte, 8)
	binary.BigEndian.PutUint32(sslRequest[0:4], 8)
	binary.BigEndian.PutUint32(sslRequest[4:8], 80877103)
	clientDec.Write(sslRequest)
	serverDec.Write([]byte{'S'})

	if clientDec.getPhase() != phasePassthrough {
		t.Fatalf("expected client passthrough after 'S', got %v", clientDec.getPhase())
	}
	if serverDec.getPhase() != phasePassthrough {
		t.Fatalf("expected server passthrough after 'S', got %v", serverDec.getPhase())
	}
}

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

// TestDecoder_SSLRequest_ReturnsDirectlyToStartup dogrular: SentinelDB V1
// sifrelemeyi hicbir zaman desteklemez (bkz. firewall.Gate, istemciye
// dogrudan 'N' yazan taraf). Decoder, SSLRequest'i emit ettikten sonra
// gercek bir sunucu cevabi beklemeden dogrudan phaseStartup'a doner ve
// hemen ardindan gelen duz metin StartupMessage'i ayni Write cagrisinda
// bile ayristirabilir.
func TestDecoder_SSLRequest_ReturnsDirectlyToStartup(t *testing.T) {
	var got []Message
	dec := NewClientDecoder(func(m Message) { got = append(got, m) }, func(err error) {
		t.Fatalf("unexpected decode error: %v", err)
	})

	sslRequest := make([]byte, 8)
	binary.BigEndian.PutUint32(sslRequest[0:4], 8)
	binary.BigEndian.PutUint32(sslRequest[4:8], 80877103)
	dec.Write(sslRequest)

	if len(got) != 1 || got[0].Name != NameSSLRequest {
		t.Fatalf("expected SSLRequest message, got %+v", got)
	}
	if dec.getPhase() != phaseStartup {
		t.Fatalf("expected phaseStartup immediately after SSLRequest, got %v", dec.getPhase())
	}

	startup := encodeStartupMessage(map[string]string{"user": "sentinel"})
	dec.Write(startup)

	if len(got) != 2 || got[1].Name != NameStartupMessage || got[1].StartupParams["user"] != "sentinel" {
		t.Fatalf("expected plaintext StartupMessage to be parsed right after SSLRequest, got %+v", got)
	}
}

// TestDecoder_GSSENCRequest_ReturnsDirectlyToStartup, GSSENCRequest icin
// ayni "her zaman duz metin" davranisini dogrular.
func TestDecoder_GSSENCRequest_ReturnsDirectlyToStartup(t *testing.T) {
	var got []Message
	dec := NewClientDecoder(func(m Message) { got = append(got, m) }, func(err error) {
		t.Fatalf("unexpected decode error: %v", err)
	})

	gssRequest := make([]byte, 8)
	binary.BigEndian.PutUint32(gssRequest[0:4], 8)
	binary.BigEndian.PutUint32(gssRequest[4:8], 80877104)
	dec.Write(gssRequest)

	if len(got) != 1 || got[0].Name != NameGSSENCRequest {
		t.Fatalf("expected GSSENCRequest message, got %+v", got)
	}
	if dec.getPhase() != phaseStartup {
		t.Fatalf("expected phaseStartup immediately after GSSENCRequest, got %v", dec.getPhase())
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

// FuzzDecoderWrite, hem client (Startup-first) hem server (Normal-first)
// Decoder'in guvenilmeyen, keyfi bayt akislari uzerinde -asla panic
// etmeme- degismezini korur (bkz. gorev C/I). Girdi rastgele iki parcaya
// bolunup ayri Write cagrilariyla beslenir; boylece parcali (fragmented)
// TCP okumalarini taklit eden yol da fuzz kapsamina girer.
func FuzzDecoderWrite(f *testing.F) {
	f.Add(encodeStartupMessage(map[string]string{"user": "sentinel"}), 3)
	f.Add(encodeQuery("SELECT 1"), 1)
	f.Add([]byte{byte(MsgErrorResponse), 0xFF, 0xFF, 0xFF, 0xFF}, 0)
	f.Add([]byte{0x00, 0x00, 0x00, 0x04}, 2)
	f.Add([]byte{}, 0)

	f.Fuzz(func(t *testing.T, data []byte, split int) {
		run := func(dec *Decoder) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Decoder.Write panicked on input %v (split=%d): %v", data, split, r)
				}
			}()
			if len(data) == 0 {
				dec.Write(nil)
				return
			}
			at := split % len(data)
			if at < 0 {
				at = -at
			}
			dec.Write(data[:at])
			dec.Write(data[at:])
		}

		run(NewClientDecoder(func(Message) {}, func(error) {}))
		run(NewServerDecoder(func(Message) {}, func(error) {}))
	})
}

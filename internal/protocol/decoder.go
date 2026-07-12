package protocol

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
)

// Direction, bir mesajın akış yönünü belirtir.
type Direction int

const (
	Frontend Direction = iota // client -> server
	Backend                   // server -> client
)

type phase int32

const (
	// phaseStartup: yalnızca Frontend yönü için başlangıç durumu. İlk mesaj
	// StartupMessage, SSLRequest, GSSENCRequest ya da CancelRequest olabilir;
	// bunların hiçbirinde standart tag+length çerçevesi yoktur.
	phaseStartup phase = iota
	phaseNormal
	// phasePassthrough: mesaj sınırları artık güvenilir şekilde takip
	// edilemiyor (ör. bozuk/parçalanmış veri sonrası fail hali). Bu
	// noktadan sonra Decoder hiçbir şey ayrıştırmaz ve Write basitçe geri
	// döner (bkz. Write) - hiçbir bayt ne yönlendirilir ne de
	// yorumlanır. firewall.Gate ve masking.Transformer gibi aktif
	// müdahale eden bileşenler bu duruma geçişi kendi onError
	// callback'lerinde yakalayıp bağlantıyı güvenli şekilde kapatır
	// (bkz. firewall.NewGate, masking.NewTransformer) — bu yüzden bu faz
	// pratikte hiçbir zaman veri sessizce yutup ileri akıtmaz.
	phasePassthrough
)

// SentinelDB V1 sınırlaması: SSLRequest/GSSENCRequest ve StartupMessage
// standart tag+length çerçevesine uymadığından (bkz. consumeStartup), bu
// mesajların MessageType tag'i yoktur (Message.Type == 0). Bunları
// birbirinden ayırmak için Name alanı kullanılır; firewall.Gate bu
// sabitlerle karşılaştırma yapar.
const (
	NameStartupMessage = "StartupMessage"
	NameSSLRequest     = "SSLRequest"
	NameGSSENCRequest  = "GSSENCRequest"
)

// maxMessageLength, tek bir mesaj için kabul edilen üst sınırdır. Bunun
// üzerindeki bir uzunluk alanı, protokolü yanlış ayrıştırdığımızın ya da
// akışın artık düz metin PostgreSQL trafiği olmadığının işaretidir.
const maxMessageLength = 1 << 20 // 1 MiB

// Message, ayrıştırılmış tek bir PostgreSQL wire protokolü paketini temsil eder.
type Message struct {
	Direction Direction
	Type      MessageType // Startup/SSLRequest/CancelRequest için anlamsız (0)
	Name      string
	Length    int // wire üzerindeki length alanının değeri

	// Yalnızca StartupMessage için doldurulur.
	ProtocolMajor int
	ProtocolMinor int
	StartupParams map[string]string

	// Yalnızca Query (simple query) için doldurulur.
	Query string

	// Raw, mesajın tam ham baytlarıdır (varsa tag + length + payload, ya da
	// startup aşamasında length + body). Aktif müdahale eden bileşenlerin
	// (ör. firewall.Gate) mesajı yeniden kodlamadan olduğu gibi iletebilmesi
	// için tutulur.
	Raw []byte
}

// Handler, ayrıştırılan her mesaj için çağrılır.
type Handler func(Message)

// Decoder, bir bağlantı yönünden akan ham baytları PostgreSQL wire
// protokolü mesajlarına ayrıştıran, duruma sahip (stateful) bir ayrıştırıcıdır.
// Kendisi hiçbir baytı ileri yönlendirmez/yazmaz - bu, çağıranın (bkz.
// firewall.Gate.Run, masking.Transformer.Run) Write'a beslediği veriyi
// handler/onError geri çağrıları üzerinden yorumlayıp kendi yazma
// mantığını uygulamasıyla olur.
//
// buf yalnızca bu Decoder'ı besleyen goroutine tarafından dokunulur
// (Gate.Run/Transformer.Run, kendi tek okuma döngülerinden çağırır). phase
// yine de atomic tutulur: gelecekte birden fazla goroutine'in aynı
// Decoder'ı gözlemlemesi (ör. metrik/debug amaçlı) durumunda veri
// yarışını önler.
type Decoder struct {
	dir     Direction
	phase   atomic.Int32
	buf     []byte
	handler Handler
	onError func(error)
}

// NewClientDecoder, client -> server yönü için bir Decoder oluşturur.
// İlk mesajın StartupMessage/SSLRequest/GSSENCRequest/CancelRequest
// olmasını bekler.
func NewClientDecoder(h Handler, onError func(error)) *Decoder {
	d := &Decoder{dir: Frontend, handler: h, onError: onError}
	d.setPhase(phaseStartup)
	return d
}

// NewServerDecoder, server -> client yönü için bir Decoder oluşturur.
// Sunucu hiçbir zaman StartupMessage göndermediğinden doğrudan normal
// (tag+length) çerçeveleme moduyla başlar.
func NewServerDecoder(h Handler, onError func(error)) *Decoder {
	d := &Decoder{dir: Backend, handler: h, onError: onError}
	d.setPhase(phaseNormal)
	return d
}

func (d *Decoder) getPhase() phase {
	return phase(d.phase.Load())
}

func (d *Decoder) setPhase(p phase) {
	d.phase.Store(int32(p))
}

// Write, akıştan geçen ham baytları besler ve tamponda biriken tam
// mesajları ayrıştırıp handler'a iletir. Eksik mesajlar bir sonraki
// Write çağrısını bekler.
func (d *Decoder) Write(p []byte) {
	if d.getPhase() == phasePassthrough {
		// Artik hicbir sey ayristirilmiyor (bkz. fail). Cagiran taraf
		// (SniffReader) baytlari kendi Read() dönüşünde zaten oldugu gibi
		// akitmaya devam eder; burada sadece ayristirma/gozlem durur.
		return
	}
	d.buf = append(d.buf, p...)

	for {
		switch d.getPhase() {
		case phaseStartup:
			if !d.consumeStartup() {
				return
			}
		case phaseNormal:
			if !d.consumeNormal() {
				return
			}
		default: // phasePassthrough
			return
		}
	}
}

func (d *Decoder) fail(err error) {
	if d.onError != nil {
		d.onError(err)
	}
	d.setPhase(phasePassthrough)
	d.buf = nil
}

// consumeStartup, tamponun başındaki StartupMessage/SSLRequest/
// GSSENCRequest/CancelRequest çerçevesini ayrıştırmayı dener. Tam mesaj
// henüz elde değilse false döner.
func (d *Decoder) consumeStartup() bool {
	if len(d.buf) < 4 {
		return false
	}
	length := int(binary.BigEndian.Uint32(d.buf[0:4]))
	if length < 8 || length > maxMessageLength {
		d.fail(fmt.Errorf("gecersiz startup mesaj uzunlugu: %d", length))
		return false
	}
	if len(d.buf) < length {
		return false
	}
	body := d.buf[4:length]
	code := binary.BigEndian.Uint32(body[0:4])
	raw := append([]byte(nil), d.buf[0:length]...)

	switch code {
	case 80877103, 80877104: // SSLRequest, GSSENCRequest
		name := NameSSLRequest
		if code == 80877104 {
			name = NameGSSENCRequest
		}
		d.emit(Message{Direction: d.dir, Name: name, Length: length, Raw: raw})
		// SentinelDB V1 sınırlaması: sifreleme/GSS müzakeresi hiçbir zaman
		// gerçek sunucuya iletilmez ve hiçbir zaman kabul edilmez. Bu,
		// firewall.Gate'in trafiği her zaman düz metin olarak inceleyebilmesi
		// için kasıtlı bir tasarım kararıdır (bkz. firewall.Gate.handle).
		// Gate, bu mesajı gördüğünde istemciye doğrudan 'N' yazıp gerçek
		// sunucuya hiç dokunmaz; Decoder de -sanki cevap zaten alınmış gibi-
		// doğrudan bir sonraki StartupMessage'ı (düz metin) beklemeye döner.
		d.setPhase(phaseStartup)
	case 80877102: // CancelRequest
		if len(body) >= 12 {
			pid := binary.BigEndian.Uint32(body[4:8])
			d.emit(Message{Direction: d.dir, Name: fmt.Sprintf("CancelRequest(pid=%d)", pid), Length: length, Raw: raw})
		}
		// CancelRequest ayrı, kısa ömürlü bir bağlantı üzerinden gönderilir;
		// sunucudan bir cevap gelmez, bağlantı hemen kapanır.
		d.setPhase(phasePassthrough)
	default:
		major := int(code >> 16)
		minor := int(code & 0xFFFF)
		d.emit(Message{
			Direction:     d.dir,
			Name:          NameStartupMessage,
			Length:        length,
			ProtocolMajor: major,
			ProtocolMinor: minor,
			StartupParams: parseStartupParams(body[4:]),
			Raw:           raw,
		})
		d.setPhase(phaseNormal)
	}

	d.buf = d.buf[length:]
	return true
}

// consumeNormal, tamponun başındaki standart tag(1) + length(4) + payload
// çerçevesini ayrıştırır. Tam mesaj henüz elde değilse false döner.
func (d *Decoder) consumeNormal() bool {
	if len(d.buf) < 5 {
		return false
	}
	msgType := MessageType(d.buf[0])
	length := int(binary.BigEndian.Uint32(d.buf[1:5])) // length kendisini icerir, tag'i icermez
	if length < 4 || length > maxMessageLength {
		d.fail(fmt.Errorf("gecersiz mesaj uzunlugu: %d (tip %q)", length, msgType))
		return false
	}
	total := 1 + length
	if len(d.buf) < total {
		return false
	}
	payload := d.buf[5:total]

	msg := Message{
		Direction: d.dir,
		Type:      msgType,
		Name:      messageName(d.dir, msgType),
		Length:    length,
		Raw:       append([]byte(nil), d.buf[0:total]...),
	}
	if d.dir == Frontend && msgType == MsgQuery {
		msg.Query = trimNullTerminator(payload)
	}
	d.emit(msg)

	d.buf = d.buf[total:]
	return true
}

func (d *Decoder) emit(m Message) {
	if d.handler != nil {
		d.handler(m)
	}
}

// parseStartupParams, StartupMessage gövdesindeki null ile ayrılmış
// key,value,key,value,... dizisini bir map'e çevirir.
func parseStartupParams(b []byte) map[string]string {
	parts := splitNullTerminated(b)
	params := make(map[string]string, len(parts)/2)
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] == "" {
			break
		}
		params[parts[i]] = parts[i+1]
	}
	return params
}

func splitNullTerminated(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == 0 {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	return out
}

func trimNullTerminator(b []byte) string {
	if n := len(b); n > 0 && b[n-1] == 0 {
		b = b[:n-1]
	}
	return string(b)
}

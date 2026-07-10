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
	// phasePendingSSLReply: Frontend tarafı SSLRequest/GSSENCRequest
	// gönderdikten sonra sunucunun tek baytlık kararını bekler. Protokole
	// göre client bu sırada başka veri göndermez; yine de temkinli
	// davranıp bu aşamada gelen baytları ayrıştırmaya çalışmadan atlarız.
	phasePendingSSLReply
	// phaseSSLReply: Backend tarafı, karşı taraf SSLRequest/GSSENCRequest
	// gönderdiğinde peer Decoder tarafından bu duruma geçirilir. Sıradaki
	// tek bayt standart tag+length çerçevesine uymaz ('S'/'N'/'G').
	phaseSSLReply
	// phasePassthrough: mesaj sınırları artık güvenilir şekilde takip
	// edilemiyor (ör. TLS müzakeresi kabul edildi, bozuk/parçalanmış veri).
	// Bu noktadan sonra Decoder hiçbir şey ayrıştırmaz; SniffReader
	// baytları olduğu gibi akıtmaya devam eder, sadece gözlem durur.
	phasePassthrough
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
// Trafiği değiştirmez ya da geciktirmez: SniffReader tarafından yalnızca
// gözlem amacıyla beslenir.
//
// buf yalnızca bu Decoder'ı besleyen goroutine tarafından dokunulur (SniffReader
// tek bir okuma döngüsünden çağrılır). phase ise SSL/GSS müzakeresi sırasında
// peer Decoder tarafından da yazılabildiği için atomic tutulur.
type Decoder struct {
	dir     Direction
	phase   atomic.Int32
	buf     []byte
	handler Handler
	onError func(error)
	peer    *Decoder
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

// SetPeer, aynı bağlantının karşı yönündeki Decoder'ı bağlar. SSLRequest/
// GSSENCRequest gibi tek yönde başlayıp karşı yöndeki tek baytlık bir
// cevapla sonuçlanan müzakereleri doğru ayrıştırmak için gereklidir.
func (d *Decoder) SetPeer(peer *Decoder) {
	d.peer = peer
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
	switch d.getPhase() {
	case phasePassthrough, phasePendingSSLReply:
		// phasePassthrough: artik hicbir sey ayristirilmiyor.
		// phasePendingSSLReply: protokole gore bu yonde veri beklenmez;
		// yine de gelirse (beklenmedik durum) ayristirmaya calismadan atlariz.
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
		case phaseSSLReply:
			if !d.consumeSSLReply() {
				return
			}
		default: // phasePassthrough ya da phasePendingSSLReply'a gecilmis olabilir
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
		name := "SSLRequest"
		if code == 80877104 {
			name = "GSSENCRequest"
		}
		d.emit(Message{Direction: d.dir, Name: name, Length: length, Raw: raw})
		// Sunucu tek baytlık bir kabul/red cevabı verecek; bu standart
		// tag+length çerçevesine uymaz. Karşı yöndeki (server) Decoder'ı
		// bu tek baytı bekleyecek şekilde işaretliyoruz, kendimiz de
		// sonucu öğrenene kadar bekliyoruz (bkz. consumeSSLReply).
		if d.peer != nil {
			d.peer.setPhase(phaseSSLReply)
		}
		d.setPhase(phasePendingSSLReply)
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
			Name:          "StartupMessage",
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

// consumeSSLReply, peer Decoder'ın SSLRequest/GSSENCRequest gönderdiğini
// bildirmesinin ardından beklenen tek baytlık kabul/red cevabını okur.
// 'S' (SSL) ya da 'G' (GSS) kabul anlamına gelir ve ardından şifreli
// handshake başlar; bu noktadan sonra ayrıştırma imkansız hale gelir.
// 'N' ise reddedildiği ve client'ın düz metin StartupMessage'ı tekrar
// göndereceği anlamına gelir.
func (d *Decoder) consumeSSLReply() bool {
	if len(d.buf) < 1 {
		return false
	}
	b := d.buf[0]
	d.buf = d.buf[1:]

	accepted := b == 'S' || b == 'G'
	status := "reddedildi (duz metinle devam)"
	if accepted {
		status = "kabul edildi (sifreleme baslayacak)"
	}
	d.emit(Message{Direction: d.dir, Name: fmt.Sprintf("EncryptionReply(%q): %s", b, status), Length: 1, Raw: []byte{b}})

	if accepted {
		d.setPhase(phasePassthrough)
		if d.peer != nil {
			d.peer.setPhase(phasePassthrough)
		}
	} else {
		d.setPhase(phaseNormal)
		if d.peer != nil {
			d.peer.setPhase(phaseStartup)
		}
	}
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

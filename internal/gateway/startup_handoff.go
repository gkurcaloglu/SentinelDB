// Bu dosya, opt-in Extended Query yolu icin bir baglantinin
// startup/authentication asamasini - ExtendedRuntime/ExtendedFrontend
// baslamadan ONCE - tek seferlik, kisa omurlu bir bilesen olarak yonetir.
//
// ExtendedRuntime ve firewall.Gate.RunExtended, kasitli olarak steady-state
// (authentication TAMAMLANMIS) bileşenlerdir (bkz. protocol.
// NewSteadyStateFrontendFrameDecoder) - hicbiri SSLRequest/GSSENCRequest/
// StartupMessage/CancelRequest/Authentication* baytlarini asla gormemelidir.
// RunStartupHandoff, bu iki dunya arasindaki TEK gecis noktasidir: hem
// client hem backend baglantisini authentication'in gercek ilk
// ReadyForQuery'sine kadar MUNHASIRAN sahiplenir, sonra HICBIR I/O yapmadan
// geri doner - boylece cagiran (bkz. cmd/gateway), aynı iki net.Conn'u
// dogrudan ExtendedRuntime/Gate.RunExtended'e devredebilir.
package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// --- Sabit, guvenli hata kategorileri --------------------------------------
//
// Hicbiri startup parametre degeri, kullanici adi/veritabani adi, sifre/
// SASL/SCRAM verisi, ham cerceve bayti ya da backend ErrorResponse alani
// icermez. Alttaki G/C hatasi (%w ile sarilan) yalnizca baglanti/aktarim
// duzeyinde metin tasir (ör. "connection reset"), hicbir zaman protokol
// yuku degil - bu, internal/gateway/extended_runtime.go'nun kendi hata
// sarmalama disipliniyle AYNIDIR.
var (
	// ErrStartupInvalidLimits, StartupLimits'in herhangi bir alani pozitif
	// degilse RunStartupHandoff'un basinda (hicbir I/O denenmeden) donulur.
	ErrStartupInvalidLimits = errors.New("startuphandoff: gecersiz startup sinirlari (pozitif olmali)")
	// ErrStartupClientEOF, istemci ilk baytini bile gondermeden ya da iki
	// cerceve arasinda TEMIZ bir sekilde baglantiyi kapattiginda donulur.
	ErrStartupClientEOF = errors.New("startuphandoff: istemci baglantiyi startup/authentication sirasinda temiz sekilde kapatti (EOF)")
	// ErrStartupClientReadFailed, istemciden okuma EOF-DISI bir nedenle
	// (ör. kismi/kesilmis bir cerceve, aktarim hatasi) basarisiz oldugunda
	// donulur.
	ErrStartupClientReadFailed = errors.New("startuphandoff: istemciden okuma basarisiz")
	// ErrStartupClientWriteFailed, istemciye yazma basarisiz oldugunda
	// donulur.
	ErrStartupClientWriteFailed = errors.New("startuphandoff: istemciye yazma basarisiz")
	// ErrStartupBackendEOF, backend authentication tamamlanmadan TEMIZ bir
	// sekilde baglantiyi kapattiginda donulur.
	ErrStartupBackendEOF = errors.New("startuphandoff: backend baglantiyi startup/authentication sirasinda temiz sekilde kapatti (EOF)")
	// ErrStartupBackendReadFailed, backend'den okuma EOF-DISI bir nedenle
	// basarisiz oldugunda donulur.
	ErrStartupBackendReadFailed = errors.New("startuphandoff: backend'den okuma basarisiz")
	// ErrStartupBackendWriteFailed, backend'e yazma basarisiz oldugunda
	// donulur.
	ErrStartupBackendWriteFailed = errors.New("startuphandoff: backend'e yazma basarisiz")
	// ErrStartupProtocolFailure, startup/authentication cercevelemesi
	// (uzunluk, tag, beklenen mesaj sirasi) ihlal edildiginde donulur -
	// hicbir kismi cerceve iletilmez.
	ErrStartupProtocolFailure = errors.New("startuphandoff: startup/authentication protokolu ihlal edildi")
	// ErrStartupUnsupportedAuth, backend'in istedigi kimlik dogrulama kodu
	// SentinelDB'nin acikca desteklediği taahhut edilen kumenin (bkz.
	// authKind) disindaysa donulur - tahmin YURUTULMEZ, fail-closed
	// reddedilir.
	ErrStartupUnsupportedAuth = errors.New("startuphandoff: desteklenmeyen kimlik dogrulama kodu")
	// ErrStartupBackendErrorResponse, backend authentication/startup
	// tamamlanmadan bir ErrorResponse donderdiginde kullanilir - bu
	// ErrorResponse istemciye ZATEN AYNEN iletildikten sonra donulur;
	// baglanti sonlandirilir, ExtendedRuntime hic olusturulmaz.
	ErrStartupBackendErrorResponse = errors.New("startuphandoff: backend, authentication tamamlanmadan bir ErrorResponse dondurdu")
)

// --- Genel/tip tanimlari ----------------------------------------------------

// Transport, RunStartupHandoff'un istemci tarafinda ihtiyac duydugu asgari
// G/C yuzeyidir: tam okuma/yazma + kapatma (bkz. gorev 11 - baglam iptalinde
// bloklu bir Read/Write'i kesebilmek icin Close gereklidir). BackendTransport
// (bkz. extended_runtime.go) ile ayni sekle sahiptir; backend parametresi
// icin dogrudan o tur kullanilir.
type Transport interface {
	io.Reader
	io.Writer
	io.Closer
}

// StartupLimits, RunStartupHandoff'un tek bir cercevede kabul ettigi azami
// bayt sinirlaridir. Ikisi de pozitif olmalidir.
type StartupLimits struct {
	// MaxStartupFrameBytes, ilk (startup-tarzi, tag'siz, 4 baytlik uzunluk
	// on ekli) cercevenin - SSLRequest/GSSENCRequest/CancelRequest/
	// StartupMessage - izin verilen azami toplam boyutudur.
	MaxStartupFrameBytes int
	// MaxAuthFrameBytes, authentication asamasindaki (backend Authentication*/
	// ParameterStatus/BackendKeyData/NoticeResponse/ErrorResponse/
	// ReadyForQuery VE istemci PasswordMessage) her bir normal (tag+uzunluk)
	// cercevesinin izin verilen azami toplam boyutudur.
	MaxAuthFrameBytes int
}

// DefaultStartupLimits, uretim amacli makul, pozitif varsayilan sinirlar
// dondurur.
func DefaultStartupLimits() StartupLimits {
	return StartupLimits{
		MaxStartupFrameBytes: 64 * 1024,
		MaxAuthFrameBytes:    1 << 20, // protocol.maxMessageLength ile tutarli
	}
}

func (l StartupLimits) validate() error {
	if l.MaxStartupFrameBytes <= 0 || l.MaxAuthFrameBytes <= 0 {
		return ErrStartupInvalidLimits
	}
	return nil
}

// StartupResult, basarili bir RunStartupHandoff cagrisinin degismez
// sonucudur.
type StartupResult struct {
	// ReadyStatus, authentication'i tamamlayan ilk GERCEK ReadyForQuery'nin
	// islem durumu baytidir (protocol.TxStatusIdle/InTransaction/
	// FailedTransaction). CancelOnly true ise anlamsizdir.
	ReadyStatus byte
	// CancelOnly true ise, baglanti bir CancelRequest'ti: istenen cerceve
	// backend'e TAM OLARAK BIR KEZ iletildi, hicbir yanit beklenmedi ve
	// hicbir ExtendedRuntime olusturulmamalidir - cagiran, her iki
	// baglantiyi da kapatip donmelidir.
	CancelOnly bool
}

// --- PostgreSQL wire sabitleri (yalnizca bu dosya icin gerekli olanlar) ----

const (
	sslRequestCode     uint32 = 80877103
	gssEncRequestCode  uint32 = 80877104
	cancelRequestCode  uint32 = 80877102
	cancelRequestBytes        = 16 // length(4)+code(4)+pid(4)+secretkey(4), TAM OLARAK

	startupFrameLenSize = 4
	minStartupFrameLen  = 8 // en az uzunluk(4)+kod(4)

	normalFrameHeaderSize = 5 // tag(1)+uzunluk(4)

	tagPasswordMessage    byte = 'p'
	tagAuthentication     byte = 'R'
	tagParameterStatus    byte = 'S'
	tagBackendKeyData     byte = 'K'
	tagNoticeResponse     byte = 'N'
	tagErrorResponse      byte = 'E'
	tagReadyForQuery      byte = 'Z'
	tagNegotiateProtoVers byte = 'v'
)

// Authentication alt-kodlari (backend 'R' mesajinin govdesindeki ilk
// uint32). Yalnizca acikca desteklenen, guvenle relay edilebilen kodlar
// listelenir - bkz. dosya sonundaki authKind tablosu.
const (
	authOk                = 0
	authCleartextPassword = 3
	authMD5Password       = 5
	authSASL              = 10
	authSASLContinue      = 11
	authSASLFinal         = 12
)

// RunStartupHandoff, client/backend baglantisinin startup/authentication
// asamasini MUNHASIRAN sahiplenir ve authentication'i tamamlayan ilk GERCEK
// ReadyForQuery'ye kadar (ya da bir CancelRequest tamamlanana kadar) her iki
// yonu de relay eder.
//
// Sahiplik siniri (bkz. gorev 10) KESINDIR: donene kadar bu fonksiyon
// (dogrudan kendisi, baska hicbir goroutine degil) client'in TEK okuyucusu/
// yazicisi VE backend'in TEK okuyucusu/yazicisidir. Basarili donusten SONRA
// bu fonksiyon (ve ic gozetmen goroutine'i) HICBIR I/O yapmaz - cagiran ayni
// iki baglantiyi guvenle ExtendedRuntime/Gate.RunExtended'e devredebilir.
//
// io.ReadFull DISINDA hicbir okuyucu (ozellikle bufio.Reader gibi
// onden-okuma yapabilen hicbir sarmalayici) kullanilmaz - her cerceve TAM
// OLARAK kendi uzunlugu kadar okunur, bir sonraki cercevenin ilk baytina
// asla dokunulmaz (bkz. gorev 5).
//
// Basarili donuste hicbir baglanti kapatilmaz (CancelRequest DAHIL - cagiran
// StartupResult.CancelOnly'i inceleyip kendisi kapatir). Hata durumunda da
// bu fonksiyon baglantilari kapatmaz (bkz. gorev 11 - yalnizca ic gozetmen,
// SADECE ctx iptalinde kapatir); cagiran her zaman kendi kapama sorumlulugunu
// tasir.
func RunStartupHandoff(ctx context.Context, client Transport, backend BackendTransport, limits StartupLimits) (StartupResult, error) {
	if err := limits.validate(); err != nil {
		return StartupResult{}, err
	}

	// bkz. gorev 11: bloklu bir io.ReadFull/writeAll cagrisini kesebilmek
	// icin, ctx iptalinde HER IKI baglantiyi da kapatan kucuk, bagimsiz bir
	// gozetmen. Hicbir protokol bayti okumaz/yazmaz. done kapatildiginda
	// (basarili DONE ya da ic bir hata SONUCU) sessizce cikar - baglantilara
	// DOKUNMADAN (basarili/hata donusunde baglanti kapatma KESINLIKLE
	// cagirana aittir).
	var cause causeFlag
	done := make(chan struct{})
	watcherJoined := make(chan struct{})
	go func() {
		defer close(watcherJoined)
		select {
		case <-ctx.Done():
			cause.claim(causeParent)
			_ = client.Close()
			_ = backend.Close()
		case <-done:
		}
	}()

	result, workErr := runStartupHandoffWork(client, backend, limits)
	if workErr != nil {
		cause.claim(causeInternal)
	}
	close(done)
	<-watcherJoined

	if cause.winner() == causeParent {
		// Parent ctx'in sona ermesi kapanmayi BASLATTI - workErr (varsa)
		// yalnizca bu ZORLA kapatmanin bir SEMPTOMU olabilir (ör. bloklu
		// bir Read/Write'in kesilmesinden kaynaklanan bir ErrStartup*
		// hatasi) - bu yuzden gercek nedeni (context.Canceled ya da
		// context.DeadlineExceeded) rapor ederiz, OS hata metnine
		// bakilmaz.
		return StartupResult{}, ctx.Err()
	}
	if workErr != nil {
		return StartupResult{}, workErr
	}
	return result, nil
}

// causeFlag, RunStartupHandoff'un ic nedensellik dogrusallastirmasidir -
// internal/gateway/extended_runtime.go'nun shutdownCause CAS desenininin
// kucuk olcekli bir esdegeri: hangi taraf (gozetmen'in ctx.Done()'i mi,
// yoksa is (work) yolunun kendi basarisizligi mi) ONCE claim ederse o
// kazanir; ikinci claim cagrisi sessizce no-op'tur.
type causeFlag struct{ v atomic.Int32 }

func (c *causeFlag) claim(v int32) bool { return c.v.CompareAndSwap(0, v) }
func (c *causeFlag) winner() int32      { return c.v.Load() }

const (
	causeParent   int32 = 1
	causeInternal int32 = 2
)

// runStartupHandoffWork, RunStartupHandoff'un GERCEK (G/C iceren) is
// yukunu, gozetmen/nedensellik mantigindan ayri olarak uygular: once
// negotiateStartup (SSLRequest/GSSENCRequest/CancelRequest/StartupMessage),
// ardindan (CancelRequest degilse) runAuthentication.
func runStartupHandoffWork(client Transport, backend BackendTransport, limits StartupLimits) (StartupResult, error) {
	cancelOnly, err := negotiateStartup(client, backend, limits)
	if err != nil {
		return StartupResult{}, err
	}
	if cancelOnly {
		return StartupResult{CancelOnly: true}, nil
	}
	return runAuthentication(client, backend, limits)
}

// negotiateStartup, ilk (startup-tarzi) cerceveyi okur ve turune gore
// davranir:
//   - SSLRequest/GSSENCRequest: istemciye TEK bayt 'N' yazar, backend'e HIC
//     dokunmadan bir SONRAKI baslangic cercevesini beklemeye devam eder
//     (istemci birden fazla kez "problayabilir" - bkz. gorev 6).
//   - CancelRequest: TAM OLARAK 16 baytlik cerceveyi backend'e bir kez
//     iletir, yanit beklemeden (true, nil) doner.
//   - Baska herhangi bir kod (StartupMessage): cerceveyi backend'e AYNEN
//     bir kez iletir, (false, nil) doner - cagiran authentication'a gecer.
func negotiateStartup(client Transport, backend BackendTransport, limits StartupLimits) (cancelOnly bool, err error) {
	for {
		frame, code, err := readStartupStyleFrame(client, limits.MaxStartupFrameBytes)
		if err != nil {
			return false, err
		}
		switch code {
		case sslRequestCode, gssEncRequestCode:
			if err := writeAll(client, []byte{'N'}); err != nil {
				return false, classifyClientWriteErr(err)
			}
			continue
		case cancelRequestCode:
			if len(frame) != cancelRequestBytes {
				return false, ErrStartupProtocolFailure
			}
			if err := writeAll(backend, frame); err != nil {
				return false, classifyBackendWriteErr(err)
			}
			return true, nil
		default:
			if err := writeAll(backend, frame); err != nil {
				return false, classifyBackendWriteErr(err)
			}
			return false, nil
		}
	}
}

// runAuthentication, StartupMessage backend'e iletildikten SONRA, backend'in
// authentication akisini (bkz. dosya basi authKind tablosu) tuketir. Her
// desteklenen Authentication* mesaji icin: (1) TAM cerceve istemciye relay
// edilir, (2) yanit gerekiyorsa TEK bir PasswordMessage okunup backend'e
// relay edilir ve gecici dilim ANINDA atilir, (3) AuthenticationOk
// GORULENE kadar backend'den okumaya devam edilir. AuthenticationOk
// gorulunce runPostAuthPhase'e gecilir.
func runAuthentication(client Transport, backend BackendTransport, limits StartupLimits) (StartupResult, error) {
	for {
		tag, frame, err := readNormalFrame(backend, limits.MaxAuthFrameBytes)
		if err != nil {
			return StartupResult{}, classifyBackendReadErr(err)
		}
		switch tag {
		case tagAuthentication:
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, classifyClientWriteErr(err)
			}
			kind, needsResponse, err := authKind(frame)
			if err != nil {
				return StartupResult{}, err
			}
			if needsResponse {
				pwTag, pwFrame, err := readNormalFrame(client, limits.MaxAuthFrameBytes)
				if err != nil {
					return StartupResult{}, classifyClientReadErr(err)
				}
				if pwTag != tagPasswordMessage {
					return StartupResult{}, ErrStartupProtocolFailure
				}
				werr := writeAll(backend, pwFrame)
				// bkz. gorev 8: gecici bayt dilimi (sifre/SASL/SCRAM verisi
				// icerebilir) iletildikten hemen sonra ANINDA atilir -
				// hicbir yerde saklanmaz.
				pwFrame = nil
				if werr != nil {
					return StartupResult{}, classifyBackendWriteErr(werr)
				}
			}
			if kind == authOk {
				return runPostAuthPhase(client, backend, limits)
			}
			continue
		case tagErrorResponse:
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, classifyClientWriteErr(err)
			}
			return StartupResult{}, ErrStartupBackendErrorResponse
		case tagNoticeResponse:
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, classifyClientWriteErr(err)
			}
			continue
		default:
			return StartupResult{}, ErrStartupProtocolFailure
		}
	}
}

// runPostAuthPhase, AuthenticationOk GORULDUKTEN SONRA backend'den okumaya
// devam eder: ParameterStatus/BackendKeyData/NoticeResponse/
// NegotiateProtocolVersion degismeden relay edilir; ilk ReadyForQuery
// GORULDUGUNDE dogrulanir, relay edilir ve basarili sonuc dondurulur -
// ResponseSequencer'a HIC beslenmez, sahte bir Sync/ikinci bir
// ReadyForQuery ASLA uretilmez.
func runPostAuthPhase(client Transport, backend BackendTransport, limits StartupLimits) (StartupResult, error) {
	for {
		tag, frame, err := readNormalFrame(backend, limits.MaxAuthFrameBytes)
		if err != nil {
			return StartupResult{}, classifyBackendReadErr(err)
		}
		switch tag {
		case tagParameterStatus, tagBackendKeyData, tagNoticeResponse, tagNegotiateProtoVers:
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, classifyClientWriteErr(err)
			}
			continue
		case tagErrorResponse:
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, classifyClientWriteErr(err)
			}
			return StartupResult{}, ErrStartupBackendErrorResponse
		case tagReadyForQuery:
			status, verr := validateReadyForQueryBody(frame)
			if verr != nil {
				return StartupResult{}, verr
			}
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, classifyClientWriteErr(err)
			}
			return StartupResult{ReadyStatus: status}, nil
		default:
			return StartupResult{}, ErrStartupProtocolFailure
		}
	}
}

// authKind, bir Authentication ('R') cercevesinin govdesindeki alt-kodu
// yorumlar ve bu kod icin BIR frontend yaniti (PasswordMessage) gerekip
// gerekmedigini bildirir. Yalnizca acikca desteklenen kodlar kabul edilir -
// bkz. dosya basi sabit tanimlari (authOk/authCleartextPassword/
// authMD5Password/authSASL/authSASLContinue/authSASLFinal). Baska HERHANGI
// bir kod (KerberosV5/SCMCredential/GSS/GSSContinue/SSPI DAHIL - SentinelDB
// yalnizca duz metin baglanti destekler, sifreleme/GSS gerektiren hicbir
// yontem GUVENLE relay edilemez) ErrStartupUnsupportedAuth ile fail-closed
// reddedilir - TAHMIN YURUTULMEZ.
func authKind(frame []byte) (code uint32, needsResponse bool, err error) {
	body := frame[normalFrameHeaderSize:]
	if len(body) < 4 {
		return 0, false, ErrStartupProtocolFailure
	}
	code = binary.BigEndian.Uint32(body[0:4])
	switch code {
	case authOk, authSASLFinal:
		return code, false, nil
	case authCleartextPassword, authMD5Password, authSASL, authSASLContinue:
		return code, true, nil
	default:
		return code, false, ErrStartupUnsupportedAuth
	}
}

// validateReadyForQueryBody, bir ReadyForQuery cercevesinin govdesinin TAM
// OLARAK bir bayt oldugunu ve bu baytin bilinen uc islem durumundan
// (protocol.TxStatusIdle/InTransaction/FailedTransaction) biri oldugunu
// dogrular.
func validateReadyForQueryBody(frame []byte) (byte, error) {
	body := frame[normalFrameHeaderSize:]
	if len(body) != 1 {
		return 0, ErrStartupProtocolFailure
	}
	status := body[0]
	if status != protocol.TxStatusIdle && status != protocol.TxStatusInTransaction && status != protocol.TxStatusFailedTransaction {
		return 0, ErrStartupProtocolFailure
	}
	return status, nil
}

// --- Tam cerceve okuma yardimcilari (bkz. gorev 5: io.ReadFull DISINDA
// hicbir onden-okuma yapan sarmalayici kullanilmaz) --------------------

// readStartupStyleFrame, TAM OLARAK bir startup-tarzi (tag'siz, 4 baytlik
// uzunluk on ekli) cerceve okur: once 4 bayt uzunluk alani (io.ReadFull),
// sinirlar dogrulanir, ardindan TAM OLARAK uzunluk-4 bayt govde
// (io.ReadFull) - bir sonraki cercevenin ilk baytina ASLA dokunulmaz.
// code, govdenin ilk 4 baytidir (SSLRequest/GSSENCRequest/CancelRequest
// kodu ya da bir StartupMessage icin protokol surumu).
func readStartupStyleFrame(r io.Reader, maxLen int) (frame []byte, code uint32, err error) {
	lenBuf := make([]byte, startupFrameLenSize)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, 0, classifyClientReadErr(err)
	}
	length := int(binary.BigEndian.Uint32(lenBuf))
	if length < minStartupFrameLen || length > maxLen {
		return nil, 0, ErrStartupProtocolFailure
	}
	rest := make([]byte, length-startupFrameLenSize)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, 0, classifyClientReadErr(err)
	}
	frame = append(lenBuf, rest...)
	code = binary.BigEndian.Uint32(rest[0:4])
	return frame, code, nil
}

// readNormalFrame, TAM OLARAK bir normal (tag(1)+uzunluk(4) on ekli)
// cerceve okur: once 5 baytlik baslik (io.ReadFull), sinirlar dogrulanir,
// ardindan TAM OLARAK uzunluk-4 bayt govde (io.ReadFull) - bir sonraki
// cercevenin ilk baytina ASLA dokunulmaz. tag, cagirana hangi mesaj
// turuyle karsi karsiya oldugunu (ayristirmadan ONCE) bildirir; okuma
// hatasi burada siniflandirilmaz - cagiran (yon bilgisine sahip oldugu
// icin) classifyClientReadErr/classifyBackendReadErr'i kendisi uygular.
func readNormalFrame(r io.Reader, maxLen int) (tag byte, frame []byte, err error) {
	header := make([]byte, normalFrameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint32(header[1:5]))
	if length < 4 || 1+length > maxLen {
		return 0, nil, ErrStartupProtocolFailure
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	frame = append(header, body...)
	return header[0], frame, nil
}

func classifyClientReadErr(err error) error {
	if errors.Is(err, io.EOF) {
		return ErrStartupClientEOF
	}
	return fmt.Errorf("%w: %w", ErrStartupClientReadFailed, err)
}

func classifyClientWriteErr(err error) error {
	return fmt.Errorf("%w: %w", ErrStartupClientWriteFailed, err)
}

func classifyBackendReadErr(err error) error {
	if errors.Is(err, io.EOF) {
		return ErrStartupBackendEOF
	}
	return fmt.Errorf("%w: %w", ErrStartupBackendReadFailed, err)
}

func classifyBackendWriteErr(err error) error {
	return fmt.Errorf("%w: %w", ErrStartupBackendWriteFailed, err)
}

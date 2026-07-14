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
//
// Bu revizyon, ikinci bir sertlestirme (hardening) turudur: her cerceve
// TIPI relay EDILMEDEN ONCE govdesi/sirasi yapisal olarak dogrulanir (bkz.
// authState makinesi, validate* yardimcilari) - artik hicbir cerceve
// "once relay et, sonra kontrol et" seklinde islenmez.
package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// --- Sabit, guvenli hata kategorileri --------------------------------------
//
// Hicbiri startup parametre degeri, kullanici adi/veritabani adi, sifre/
// SASL/SCRAM verisi, ham cerceve bayti ya da backend ErrorResponse alani
// icermez. Alttaki G/C hatasinin KENDI metni ARTIK hicbir sekilde
// sarilmaz/eklenmez (bkz. classifyClientReadErr/vb. - "gorev 7") - Transport
// bir arayuz oldugundan, enjekte edilmis/test amacli bir uygulama rastgele
// bir hata metni dondurebilir; bu metnin RunStartupHandoff'un donen
// hatasina, loglara ya da bicimlendirilmis (%v/%+v/%#v) hicbir degere asla
// sizmamasi gerekir.
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
	// (uzunluk, tag, beklenen mesaj sirasi, govde yapisi) ihlal edildiginde
	// donulur - hicbir kismi cerceve iletilmez.
	ErrStartupProtocolFailure = errors.New("startuphandoff: startup/authentication protokolu ihlal edildi")
	// ErrStartupUnsupportedAuth, backend'in istedigi kimlik dogrulama kodu
	// SentinelDB'nin acikca desteklediği taahhut edilen kumenin (bkz.
	// validateAuthFrame) disindaysa donulur - tahmin YURUTULMEZ, fail-closed
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
	// islem durumu baytidir. Basarili (CancelOnly olmayan) her sonucta bu
	// HER ZAMAN protocol.TxStatusIdle'dir (bkz. gorev 5) - yeni olusturulan
	// ExtendedRuntime/protocol.State her zaman bos (idle) baslar, bu yuzden
	// 'T'/'E' ile baslayan bir handoff asla basarili sayilmaz. CancelOnly
	// true ise anlamsizdir.
	ReadyStatus byte
	// CancelOnly true ise, baglanti bir CancelRequest'ti: istenen cerceve
	// backend'e TAM OLARAK BIR KEZ iletildi, hicbir yanit beklenmedi ve
	// hicbir ExtendedRuntime olusturulmamalidir - cagiran, her iki
	// baglantiyi da kapatip donmelidir.
	CancelOnly bool
}

// --- PostgreSQL wire sabitleri (yalnizca bu dosya icin gerekli olanlar) ----

const (
	sslRequestCode    uint32 = 80877103
	gssEncRequestCode uint32 = 80877104
	cancelRequestCode uint32 = 80877102

	// cancelRequestPrefixLen, CancelRequest'in surum kodundan SONRAKI,
	// secret key'den ONCEKI sabit onekidir: Int32 backend PID (4 bayt).
	// Uzunluk(4)+kod(4) zaten readStartupStyleFrame tarafindan ayri
	// tutulur (frame degiskeni onlari da icerir) - bkz. asagidaki
	// min/maxCancelRequestBytes hesaplamasi (12 = uzunluk(4)+kod(4)+pid(4)
	// DEGIL, yalnizca frame'in surum-kodu ALANINDAN sonraki kisim; asil
	// hesap negotiateStartup icinde frame'in TOPLAM boyutu uzerinden
	// yapilir - bkz. oradaki yorum).
	cancelRequestPIDLen = 4

	// PostgreSQL protokol 3.2 (PostgreSQL 18+) ile CancelRequest'in secret
	// key alani ARTIK sabit 4 bayt DEGIL, degisken uzunlukludur (govdenin
	// SONUNA kadar uzanir) - protokol belgelerinde belirtilen sinirlar 4
	// ile 256 bayt ARASINDADIR (dahil). Protokol 3.0'da anahtar HER ZAMAN
	// tam olarak 4 bayttir - bu, asagidaki minimum (4 baytlik anahtar)
	// durumuyla ZATEN kapsanir; ayri bir surum dallanmasi GEREKMEZ, cunku
	// CancelRequest'in kendisi bir surum numarasi tasimaz (yalnizca sabit
	// bir istek kodu) - gateway her iki bicimi de, hangi PostgreSQL
	// surumunun gonderdigine bakmaksizin, SEFFAF sekilde kabul eder.
	minCancelSecretKeyLen = 4
	maxCancelSecretKeyLen = 256

	// minCancelRequestBytes/maxCancelRequestBytes, TOPLAM CancelRequest
	// cerceve boyutunun (uzunluk(4)+kod(4)+pid(4)+secretkey(4..256)) izin
	// verilen araligidir: 16 (eski, 4 baytlik anahtar) ile 268 (protokol
	// 3.2'nin belgelenmis ust siniri, 256 baytlik anahtar) ARASINDA.
	minCancelRequestBytes = startupMessageHeaderSize + cancelRequestPIDLen + minCancelSecretKeyLen // 16
	maxCancelRequestBytes = startupMessageHeaderSize + cancelRequestPIDLen + maxCancelSecretKeyLen // 268

	startupFrameLenSize = 4
	minStartupFrameLen  = 8 // en az uzunluk(4)+kod(4) - SSLRequest/GSSENCRequest icin TAM OLARAK bu kadar
	// startupMessageHeaderSize, bir StartupMessage'in uzunluk(4)+surum
	// kodu(4) onekinin toplam boyutudur - parametre alani bundan SONRA
	// baslar.
	startupMessageHeaderSize = startupFrameLenSize + 4

	supportedStartupMajorVersion uint32 = 3

	normalFrameHeaderSize = 5 // tag(1)+uzunluk(4)

	tagPasswordMessage    byte = 'p'
	tagAuthentication     byte = 'R'
	tagParameterStatus    byte = 'S'
	tagBackendKeyData     byte = 'K'
	tagNoticeResponse     byte = 'N'
	tagErrorResponse      byte = 'E'
	tagReadyForQuery      byte = 'Z'
	tagNegotiateProtoVers byte = 'v'

	// backendKeyDataPIDLen, BackendKeyData govdesinin surum-bagimsiz sabit
	// onekidir: Int32 process ID (4 bayt).
	backendKeyDataPIDLen = 4

	// PostgreSQL protokol 3.2 (PostgreSQL 18+) ile BackendKeyData'nin
	// secret key alani ARTIK sabit 4 bayt DEGIL, govdenin SONUNA kadar
	// uzanan degisken uzunluklu bir alandir - protokol belgelerinde
	// belirtilen sinirlar 4 ile 256 bayt ARASINDADIR (dahil). Protokol
	// 3.0'da anahtar HER ZAMAN tam olarak 4 bayttir; PostgreSQL 18
	// su anda 32 baytlik anahtarlar gonderir - HER IKI bicim de (ve
	// belgelenmis 256 baytlik ust sinira kadar HERHANGI bir uzunluk) ayni
	// sekilde, SEFFAF olarak kabul edilip relay edilir; StartupMessage'in
	// surum alanina (3.0 ya da 3.2) bakilarak dallanma YAPILMAZ - bu,
	// gateway'in transparan bir relay olmasi ilkesiyle tutarlidir (bkz.
	// gorev 3).
	minBackendKeyDataSecretLen = 4
	maxBackendKeyDataSecretLen = 256

	// minBackendKeyDataBodyLen/maxBackendKeyDataBodyLen, TOPLAM
	// BackendKeyData GOVDE boyutunun (pid(4)+secretkey(4..256)) izin
	// verilen araligidir: 8 (eski, 4 baytlik anahtar) ile 260 (protokol
	// 3.2'nin belgelenmis ust siniri, 256 baytlik anahtar) ARASINDA.
	minBackendKeyDataBodyLen = backendKeyDataPIDLen + minBackendKeyDataSecretLen // 8
	maxBackendKeyDataBodyLen = backendKeyDataPIDLen + maxBackendKeyDataSecretLen // 260
)

// Authentication alt-kodlari (backend 'R' mesajinin govdesindeki ilk
// uint32). Yalnizca acikca desteklenen, guvenle relay edilebilen kodlar
// listelenir - bkz. authState makinesi ve validateAuthFrame.
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
	return runStartupHandoffInternal(ctx, client, backend, limits, nil)
}

// runStartupHandoffInternal, RunStartupHandoff'un GERCEK govdesidir; hooks
// yalnizca paket testleri tarafindan (nedensellik yaris durumlarini
// sleep KULLANMADAN, deterministik olarak kanitlamak icin) kullanilan
// isteğe bagli bir senkronizasyon kancasi kumesidir - production
// cagrisinda (RunStartupHandoff) HER ZAMAN nil'dir.
func runStartupHandoffInternal(ctx context.Context, client Transport, backend BackendTransport, limits StartupLimits, hooks *causeHooks) (StartupResult, error) {
	if err := limits.validate(); err != nil {
		return StartupResult{}, err
	}

	// bkz. gorev 6 (nedensellik dogrusallastirma): cause, ARTIK yalnizca
	// "ic hata mi parent iptali mi" ayrimini DEGIL, "basarili tamamlanma mi
	// parent iptali mi ic hata mi" UC YONLU yarisini da kapsar - hem ic hata
	// hem BASARILI tamamlanma, KENDI GERCEKLESTIGI TAM NOKTADA (calisan is
	// yolu icinde, cagrilan en derin fonksiyonda) claim edilir; boylece
	// runStartupHandoffWork'un ust katmanlara donmesi icin gereken sure
	// (ve bu surede olasi bir goroutine yeniden zamanlamasi) ARTIK bir yaris
	// penceresi OLUSTURMAZ.
	cause := &causeFlag{hooks: hooks}

	// bkz. gorev 11: bloklu bir io.ReadFull/writeAll cagrisini kesebilmek
	// icin, ctx iptalinde HER IKI baglantiyi da kapatan kucuk, bagimsiz bir
	// gozetmen. Hicbir protokol bayti okumaz/yazmaz. done kapatildiginda
	// (basarili DONE ya da ic bir hata SONUCU) sessizce cikar - baglantilara
	// DOKUNMADAN (basarili/hata donusunde baglanti kapatma KESINLIKLE
	// cagirana aittir). Kapatma cagrilari YALNIZCA bu gozetmenin causeParent
	// CLAIM'i GERCEKTEN KAZANDIGI durumda yapilir (bkz. gorev 6) - aksi
	// halde (ic is yolu zaten BASARILI ya da BASARISIZ olarak
	// dogrusallasmissa) gozetmen baglantilara DOKUNMAZ; "basarili handoff
	// hicbir baglantiyi kapatmaz" garantisi boylece parent iptaliyle
	// yarisan GEC bir cancel() cagrisina karsi da korunur.
	done := make(chan struct{})
	watcherJoined := make(chan struct{})
	go func() {
		defer close(watcherJoined)
		select {
		case <-ctx.Done():
			if cause.claim(causeParent) {
				_ = client.Close()
				_ = backend.Close()
			}
		case <-done:
		}
	}()

	result, workErr := runStartupHandoffWork(client, backend, limits, cause)
	if workErr != nil {
		// Guvenlik agi: yukaridaki her donus noktasi ZATEN kendi hatasini
		// claim ETMIS OLMALIDIR (bkz. cause.fail) - bu ikinci cagri, CAS
		// zaten kazanilmissa sessiz bir no-op'tur, yalnizca gozden kacan bir
		// yolu savunmaci sekilde kapatir.
		cause.claim(causeInternal)
	} else {
		cause.claim(causeSuccess)
	}
	close(done)
	<-watcherJoined

	switch cause.winner() {
	case causeParent:
		// Parent ctx'in sona ermesi kapanmayi BASLATTI - workErr (varsa)
		// yalnizca bu ZORLA kapatmanin bir SEMPTOMU olabilir (ör. bloklu
		// bir Read/Write'in kesilmesinden kaynaklanan bir ErrStartup*
		// hatasi) - bu yuzden gercek nedeni (context.Canceled ya da
		// context.DeadlineExceeded) rapor ederiz, OS hata metnine
		// bakilmaz.
		return StartupResult{}, ctx.Err()
	case causeSuccess:
		return result, nil
	default: // causeInternal
		return StartupResult{}, workErr
	}
}

// causeHooks, YALNIZCA paket testleri tarafindan kullanilan, isteğe bagli
// senkronizasyon kancalaridir - production'da (RunStartupHandoff) HER ZAMAN
// nil'dir.
type causeHooks struct {
	// onClaimed, causeFlag.claim bir degeri BASARIYLA (ilk kez) claim
	// ettiginde, AYNI (claim'i yapan) goroutine uzerinde, ESZAMANLI olarak
	// cagirilir. Testler bunu, ORNEGIN "ic hata TAM OLARAK claim edildigi
	// anda" parent ctx'i iptal ederek, sleep KULLANMADAN gercek bir yaris
	// durumu uretmek icin kullanir (bkz. gorev 6 testleri).
	onClaimed func(v int32)
}

// causeFlag, RunStartupHandoff'un ic nedensellik dogrusallastirmasidir -
// internal/gateway/extended_runtime.go'nun shutdownCause CAS desenininin
// kucuk olcekli bir esdegeri: ucuncelighangi taraf (gozetmen'in ctx.Done()'i
// mi, is (work) yolunun kendi basarisizligi mi, yoksa is yolunun BASARILI
// tamamlanmasi mi) ONCE claim ederse o kazanir; sonraki claim cagrilari
// sessizce no-op'tur.
type causeFlag struct {
	v     atomic.Int32
	hooks *causeHooks
}

func (c *causeFlag) claim(v int32) bool {
	won := c.v.CompareAndSwap(0, v)
	if won && c.hooks != nil && c.hooks.onClaimed != nil {
		c.hooks.onClaimed(v)
	}
	return won
}
func (c *causeFlag) winner() int32 { return c.v.Load() }

// fail, err nil DEGILSE causeInternal'i HEMEN (cagiranin bulundugu tam
// noktada, herhangi bir ust katmana donmeden ONCE) claim eder ve err'i
// oldugu gibi dondurur - bkz. gorev 6, "Record the initiating cause at the
// failure linearization point". Her negotiateStartup/runAuthentication/
// runPostAuthPhase donus noktasi, dondurdugu HER hatayi bu yontemden
// GECIRMELIDIR.
func (c *causeFlag) fail(err error) error {
	if err != nil {
		c.claim(causeInternal)
	}
	return err
}

// succeed, is yolunun GERCEKTEN basariyla tamamlandigi TAM noktada (ör.
// negotiateStartup'in CancelRequest'i backend'e ilettigi an, ya da
// runPostAuthPhase'in ilk gercek ReadyForQuery'yi istemciye basariyla
// rolerledigi an) causeSuccess'i HEMEN claim eder - bkz. gorev 6,
// "successful handoff is also linearized against parent shutdown".
func (c *causeFlag) succeed() { c.claim(causeSuccess) }

const (
	causeParent   int32 = 1
	causeInternal int32 = 2
	causeSuccess  int32 = 3
)

// runStartupHandoffWork, RunStartupHandoff'un GERCEK (G/C iceren) is
// yukunu, gozetmen/nedensellik mantigindan ayri olarak uygular: once
// negotiateStartup (SSLRequest/GSSENCRequest/CancelRequest/StartupMessage),
// ardindan (CancelRequest degilse) runAuthentication.
func runStartupHandoffWork(client Transport, backend BackendTransport, limits StartupLimits, cause *causeFlag) (StartupResult, error) {
	cancelOnly, err := negotiateStartup(client, backend, limits, cause)
	if err != nil {
		return StartupResult{}, err
	}
	if cancelOnly {
		return StartupResult{CancelOnly: true}, nil
	}
	return runAuthentication(client, backend, limits, cause)
}

// negotiateStartup, ilk (startup-tarzi) cerceveyi okur ve turune gore
// davranir - her tur, relay/iletimden ONCE TAM OLARAK dogrulanir (bkz. gorev
// 1, "arbitrary unrecognized startup request codes"):
//   - SSLRequest/GSSENCRequest: cerceve TAM OLARAK 8 bayt (uzunluk+kod,
//     govde YOK) DEGILSE fail-closed reddedilir, hicbir yanit yazilmaz.
//     Gecerliyse istemciye TEK bayt 'N' yazilir, backend'e HIC dokunulmadan
//     bir SONRAKI baslangic cercevesi beklenir (istemci birden fazla kez
//     "problayabilir" - bkz. gorev 6/eski "SSL/GSS").
//   - CancelRequest: TOPLAM cerceve boyutu [minCancelRequestBytes,
//     maxCancelRequestBytes] araligi DISINDAYSA fail-closed reddedilir -
//     bkz. bu sabitlerin doc yorumu icin PostgreSQL protokol 3.2 (18+)
//     degisken uzunluklu secret key destegi. Gecerliyse cerceve (PID VE
//     secret key DAHIL, HERHANGI bir yorumlama/karsilastirma yapilmadan)
//     backend'e AYNEN bir kez iletilir, yanit beklenmeden (true, nil)
//     doner - bu, is yolunun BASARILI bir terminal noktasidir (bkz.
//     cause.succeed()).
//   - Surum kodu major==3 olan herhangi bir deger (StartupMessage): govde
//     (parametre alani) yapisal olarak dogrulanir (bkz.
//     validateStartupParams) - gecersizse ya da yapisal olarak dolu,
//     bos-olmayan bir "user" parametresi YOKSA fail-closed reddedilir.
//     Gecerliyse cerceve backend'e AYNEN bir kez iletilir, (false, nil)
//     doner - cagiran authentication'a gecer (bu, is yolunun TERMINAL bir
//     BASARISI DEGILDIR - authentication devam eder, bu yuzden burada
//     cause.succeed() cagrilmaz).
//   - Baska HERHANGI bir kod (major != 3, SSL/GSS/Cancel de degil):
//     ErrStartupProtocolFailure ile fail-closed reddedilir, hicbir sekilde
//     StartupMessage sanilip iletilmez.
func negotiateStartup(client Transport, backend BackendTransport, limits StartupLimits, cause *causeFlag) (cancelOnly bool, err error) {
	for {
		frame, code, err := readStartupStyleFrame(client, limits.MaxStartupFrameBytes)
		if err != nil {
			return false, cause.fail(err)
		}
		switch code {
		case sslRequestCode, gssEncRequestCode:
			if len(frame) != minStartupFrameLen {
				return false, cause.fail(ErrStartupProtocolFailure)
			}
			if err := writeAll(client, []byte{'N'}); err != nil {
				return false, cause.fail(classifyClientWriteErr(err))
			}
			continue
		case cancelRequestCode:
			if len(frame) < minCancelRequestBytes || len(frame) > maxCancelRequestBytes {
				return false, cause.fail(ErrStartupProtocolFailure)
			}
			if err := writeAll(backend, frame); err != nil {
				return false, cause.fail(classifyBackendWriteErr(err))
			}
			cause.succeed()
			return true, nil
		default:
			major := code >> 16
			if major != supportedStartupMajorVersion {
				return false, cause.fail(ErrStartupProtocolFailure)
			}
			body := frame[startupMessageHeaderSize:]
			hasUser, verr := validateStartupParams(body)
			if verr != nil {
				return false, cause.fail(verr)
			}
			if !hasUser {
				return false, cause.fail(ErrStartupProtocolFailure)
			}
			if err := writeAll(backend, frame); err != nil {
				return false, cause.fail(classifyBackendWriteErr(err))
			}
			return false, nil
		}
	}
}

// validateStartupParams, bir StartupMessage'in parametre alanini (surum
// kodundan SONRAKI govde) yapisal olarak dogrular - HICBIR isim/deger
// saklanmaz ya da loglanmaz, yalnizca "user" adinda, bos-olmayan bir
// parametrenin yapisal olarak VAR olup olmadigi (hasUser) gozlemlenir.
//
// Beklenen bicim: sifir ya da daha fazla (name\0 value\0) cifti, ardindan
// TEK bir sonlandirici sifir bayti - PostgreSQL StartupMessage govdesinin
// GERCEK biçimi. Asagidakilerin HERHANGI biri ErrStartupProtocolFailure ile
// reddedilir: sonlandirilmamis bir isim/deger dizesi, degeri olmayan bir
// isim (dizi govde sonuna kadar tukeniyor), sonlandiricidan SONRA kalan
// bayt, ya da sonlandiricinin hic gorulmemesi.
func validateStartupParams(body []byte) (hasUser bool, err error) {
	i := 0
	for i < len(body) {
		if body[i] == 0 {
			// Sonlandirici TAM OLARAK govdenin son bayti olmalidir -
			// aksi halde sonlandiricidan SONRA fazladan bayt var demektir.
			if i != len(body)-1 {
				return false, ErrStartupProtocolFailure
			}
			return hasUser, nil
		}
		nameStart := i
		for i < len(body) && body[i] != 0 {
			i++
		}
		if i >= len(body) {
			return false, ErrStartupProtocolFailure // sonlandirilmamis isim
		}
		name := body[nameStart:i]
		i++ // isim sonlandiricisini atla

		if i >= len(body) {
			return false, ErrStartupProtocolFailure // degersiz (esleşmemis) isim
		}
		valueStart := i
		for i < len(body) && body[i] != 0 {
			i++
		}
		if i >= len(body) {
			return false, ErrStartupProtocolFailure // sonlandirilmamis deger
		}
		value := body[valueStart:i]
		i++ // deger sonlandiricisini atla

		if len(value) > 0 && string(name) == "user" {
			hasUser = true
		}
	}
	// Dongu, tek basina bir sonlandirici bayta hic rastlamadan govde
	// sonuna ulasti - eksik sonlandirici.
	return false, ErrStartupProtocolFailure
}

// authState, bir baglantinin authentication alt-protokolu icindeki
// GEÇERLI ilerleme durumudur (bkz. gorev 3). Yalnizca runAuthentication'in
// TEK cagrildigi goroutine icinde, sirali okunur/yazilir - hicbir
// senkronizasyon gerektirmez.
type authState int

const (
	// authStateAwaitingInitialMethod, StartupMessage backend'e iletildikten
	// hemen sonraki baslangic durumudur: backend'den beklenen ILK
	// Authentication* kodu (Ok/Cleartext/MD5/SASL) - ya da NegotiateProtocolVersion/
	// ErrorResponse, bu durumu DEGISTIRMEDEN.
	authStateAwaitingInitialMethod authState = iota
	// authStateAwaitingSimpleResult, AuthenticationCleartextPassword ya da
	// AuthenticationMD5Password relay edilip istemcinin PasswordMessage'i
	// backend'e iletildikten SONRAKI durumdur - yalnizca AuthenticationOk
	// (ya da bir ErrorResponse) beklenir.
	authStateAwaitingSimpleResult
	// authStateAwaitingSASLContinuation, AuthenticationSASL relay edilip
	// istemcinin SASLInitialResponse'u (ya da daha sonraki bir tur icin
	// SASLResponse'u) backend'e iletildikten SONRAKI durumdur -
	// AuthenticationSASLContinue (baska bir tur icin, AYNI durumda kalir)
	// ya da AuthenticationSASLFinal beklenir.
	authStateAwaitingSASLContinuation
	// authStateSASLFinalReceived, AuthenticationSASLFinal GORULDUKTEN
	// SONRAKI durumdur - yalnizca AuthenticationOk (ya da bir
	// ErrorResponse) beklenir; baska hicbir SASLContinue/SASLFinal turu
	// gecerli degildir.
	authStateSASLFinalReceived
	// authStateSucceeded, AuthenticationOk GORULDUKTEN SONRAKI durumdur -
	// runAuthentication bu durumda HEMEN doner (runPostAuthPhase'e gecer),
	// bu yuzden bu durum authKind/validateAuthFrame'e bir daha ASLA geri
	// beslenmez.
	authStateSucceeded
)

// validateAuthFrame, bir Authentication ('R') cercevesinin (frame - tag ve
// uzunluk DAHIL tam cerceve) govdesindeki alt-kodu ve govde bicimini,
// TASINAN durumla (state) TUTARLILIGINI, relay/PasswordMessage OKUMADAN
// ONCE dogrular (bkz. gorev 3 - "Authentication frames must be validated
// before they are written to the client"). Basarili donuste newState,
// runAuthentication'in cagirandan SONRA benimsemesi gereken durumdur;
// needsResponse, bu kod icin backend'e iletilecek TEK bir istemci
// PasswordMessage'i okunup okunmayacagini bildirir.
//
// Asagidaki "imkansiz" sıralar KESINLIKLE reddedilir (durum makinesinin
// dogal bir sonucu olarak, ozel bir kontrol GEREKMEDEN): SASLContinue/
// SASLFinal, SASL hic baslamamisken; ikinci bir "baslangic yontemi"
// (Cleartext/MD5/SASL) zaten biri basladiktan sonra; Cleartext bir SASL
// alisverisinden sonra; SASL bir MD5 yanitindan sonra; tekrarlanan Ok
// (runAuthentication zaten Ok'ta doner, bu yuzden bu fonksiyona bir daha
// asla ulasmaz).
//
// Baska HERHANGI bir kod (KerberosV5/SCMCredential/GSS/GSSContinue/SSPI
// DAHIL - SentinelDB yalnizca duz metin baglanti destekler, sifreleme/GSS
// gerektiren hicbir yontem GUVENLE relay edilemez) ErrStartupUnsupportedAuth
// ile fail-closed reddedilir - TAHMIN YURUTULMEZ, cerceve ASLA relay
// edilmez.
func validateAuthFrame(state authState, frame []byte) (newState authState, needsResponse bool, err error) {
	body := frame[normalFrameHeaderSize:]
	if len(body) < 4 {
		return state, false, ErrStartupProtocolFailure
	}
	code := binary.BigEndian.Uint32(body[0:4])
	switch code {
	case authOk:
		if len(body) != 4 {
			return state, false, ErrStartupProtocolFailure
		}
		switch state {
		case authStateAwaitingInitialMethod, authStateAwaitingSimpleResult, authStateSASLFinalReceived:
			return authStateSucceeded, false, nil
		default:
			return state, false, ErrStartupProtocolFailure
		}
	case authCleartextPassword:
		if len(body) != 4 {
			return state, false, ErrStartupProtocolFailure
		}
		if state != authStateAwaitingInitialMethod {
			return state, false, ErrStartupProtocolFailure
		}
		return authStateAwaitingSimpleResult, true, nil
	case authMD5Password:
		if len(body) != 4+4 { // kod(4) + tuz(4)
			return state, false, ErrStartupProtocolFailure
		}
		if state != authStateAwaitingInitialMethod {
			return state, false, ErrStartupProtocolFailure
		}
		return authStateAwaitingSimpleResult, true, nil
	case authSASL:
		if state != authStateAwaitingInitialMethod {
			return state, false, ErrStartupProtocolFailure
		}
		if err := validateSASLMechanismList(body[4:]); err != nil {
			return state, false, err
		}
		return authStateAwaitingSASLContinuation, true, nil
	case authSASLContinue:
		if state != authStateAwaitingSASLContinuation {
			return state, false, ErrStartupProtocolFailure
		}
		return authStateAwaitingSASLContinuation, true, nil
	case authSASLFinal:
		if state != authStateAwaitingSASLContinuation {
			return state, false, ErrStartupProtocolFailure
		}
		return authStateSASLFinalReceived, false, nil
	default:
		return state, false, ErrStartupUnsupportedAuth
	}
}

// validateSASLMechanismList, AuthenticationSASL govdesinin (kod alani
// HARIC - yalnizca mekanizma listesi) yapisini dogrular: bir ya da daha
// fazla bos-olmayan, NUL-sonlandirilmis mekanizma adi, ardindan TEK bir bos
// dize (yani tek bir sonlandirici sifir bayti) ile sonlanan liste. Hicbir
// mekanizma adi saklanmaz/loglanmaz.
func validateSASLMechanismList(rest []byte) error {
	i := 0
	count := 0
	for i < len(rest) {
		if rest[i] == 0 {
			if i != len(rest)-1 {
				return ErrStartupProtocolFailure // sonlandiricidan sonra fazladan bayt
			}
			if count == 0 {
				return ErrStartupProtocolFailure // "bir ya da daha fazla" mekanizma gerekir
			}
			return nil
		}
		start := i
		for i < len(rest) && rest[i] != 0 {
			i++
		}
		if i >= len(rest) {
			return ErrStartupProtocolFailure // sonlandirilmamis mekanizma adi
		}
		i++ // sonlandiriciyi atla
		count++
		_ = start
	}
	return ErrStartupProtocolFailure // eksik son sonlandirici
}

// validateNegotiateProtocolVersion, bir NegotiateProtocolVersion ('v')
// govdesini dogrular: Int32 en yeni desteklenen minor surum + Int32
// desteklenmeyen-secenek sayisi + TAM OLARAK o sayida NUL-sonlandirilmis
// secenek adi dizesi, fazladan bayt olmadan. Hicbir secenek adi
// saklanmaz/loglanmaz. Sayim SINIRLIDIR: dizin, govde sinirlarini asarsa
// (count ne kadar buyuk olursa olsun) dongu guvenli sekilde eksik-veri
// hatasiyla durur - hicbir sinir-disi erisim olusmaz.
func validateNegotiateProtocolVersion(body []byte) error {
	if len(body) < 8 {
		return ErrStartupProtocolFailure
	}
	count := int32(binary.BigEndian.Uint32(body[4:8]))
	if count < 0 {
		return ErrStartupProtocolFailure
	}
	i := 8
	for n := int32(0); n < count; n++ {
		start := i
		for i < len(body) && body[i] != 0 {
			i++
		}
		if i >= len(body) {
			return ErrStartupProtocolFailure // sonlandirilmamis secenek adi (ya da govde erken bitti)
		}
		i++ // sonlandiriciyi atla
		_ = start
	}
	if i != len(body) {
		return ErrStartupProtocolFailure // fazladan bayt
	}
	return nil
}

// validateTwoStringFrame, ParameterStatus govdesinin TAM OLARAK iki
// NUL-sonlandirilmis dizeden olustugunu, fazladan bayt olmadan, dogrular.
// Hicbir deger saklanmaz/loglanmaz.
func validateTwoStringFrame(body []byte) error {
	i := 0
	for n := 0; n < 2; n++ {
		start := i
		for i < len(body) && body[i] != 0 {
			i++
		}
		if i >= len(body) {
			return ErrStartupProtocolFailure
		}
		i++
		_ = start
	}
	if i != len(body) {
		return ErrStartupProtocolFailure
	}
	return nil
}

// validateBackendKeyData, BackendKeyData govdesinin PostgreSQL protokol
// belgelerinde tanimlanan bicimine uydugunu dogrular: Int32 process ID
// (bkz. backendKeyDataPIDLen) + govdenin SONUNA kadar uzanan degisken
// uzunluklu bir secret key. Protokol 3.0'da anahtar HER ZAMAN 4 bayttir;
// protokol 3.2 (PostgreSQL 18+) ile anahtar 4 ile 256 bayt (dahil)
// arasinda HERHANGI bir uzunlukta olabilir (PostgreSQL su anda 32 bayt
// kullanir) - gateway StartupMessage'in surumune BAKMAKSIZIN her iki
// bicimi de SEFFAF olarak kabul eder (bkz. minBackendKeyDataBodyLen/
// maxBackendKeyDataBodyLen'in doc yorumu). Hicbir deger (PID ya da secret
// key) saklanmaz/loglanmaz/yorumlanmaz - yalnizca TOPLAM govde uzunlugu
// dogrulanir.
func validateBackendKeyData(body []byte) error {
	if len(body) < minBackendKeyDataBodyLen || len(body) > maxBackendKeyDataBodyLen {
		return ErrStartupProtocolFailure
	}
	return nil
}

// validateFieldedMessage, NoticeResponse/ErrorResponse govdesinin PostgreSQL
// protokol belgelerinde tanimlanan bicimine uydugunu dogrular: bir ya da
// daha fazla (alan-kodu bayti + NUL-sonlandirilmis dize) cifti, ardindan TEK
// bir sifir alan-kodu bayti ile sonlanan liste, fazladan bayt olmadan.
// Hicbir alan icerigi (metin) DONEN HATAYA ya da baska bir yere asla
// kopyalanmaz.
func validateFieldedMessage(body []byte) error {
	i := 0
	fieldCount := 0
	for i < len(body) {
		code := body[i]
		i++
		if code == 0 {
			if i != len(body) {
				return ErrStartupProtocolFailure // sonlandiricidan sonra fazladan bayt
			}
			if fieldCount == 0 {
				return ErrStartupProtocolFailure // "bir ya da daha fazla" alan gerekir
			}
			return nil
		}
		start := i
		for i < len(body) && body[i] != 0 {
			i++
		}
		if i >= len(body) {
			return ErrStartupProtocolFailure // sonlandirilmamis alan dizesi
		}
		i++ // sonlandiriciyi atla
		fieldCount++
		_ = start
	}
	return ErrStartupProtocolFailure // eksik son sonlandirici (sifir alan-kodu baytı)
}

// runAuthentication, StartupMessage backend'e iletildikten SONRA, backend'in
// authentication akisini authState makinesiyle (bkz. validateAuthFrame)
// tuketir. Her Authentication* cercevesi RELAY EDILMEDEN ONCE hem govdesi
// hem TASINAN authState ile tutarliligi dogrulanir (bkz. gorev 3) - yalnizca
// dogrulama basarili olursa cerceve istemciye iletilir. NegotiateProtocolVersion,
// AuthenticationOk'tan ONCE de (bkz. gorev 2) burada kabul edilir.
// AuthenticationOk gorulunce runPostAuthPhase'e gecilir.
func runAuthentication(client Transport, backend BackendTransport, limits StartupLimits, cause *causeFlag) (StartupResult, error) {
	state := authStateAwaitingInitialMethod
	for {
		tag, frame, err := readNormalFrame(backend, limits.MaxAuthFrameBytes)
		if err != nil {
			return StartupResult{}, cause.fail(classifyReadNormalFrameErr(err, classifyBackendReadErr))
		}
		body := frame[normalFrameHeaderSize:]
		switch tag {
		case tagNegotiateProtoVers:
			if err := validateNegotiateProtocolVersion(body); err != nil {
				return StartupResult{}, cause.fail(err)
			}
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, cause.fail(classifyClientWriteErr(err))
			}
			continue
		case tagAuthentication:
			newState, needsResponse, verr := validateAuthFrame(state, frame)
			if verr != nil {
				return StartupResult{}, cause.fail(verr)
			}
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, cause.fail(classifyClientWriteErr(err))
			}
			state = newState
			if needsResponse {
				pwTag, pwFrame, err := readNormalFrame(client, limits.MaxAuthFrameBytes)
				if err != nil {
					return StartupResult{}, cause.fail(classifyReadNormalFrameErr(err, classifyClientReadErr))
				}
				if pwTag != tagPasswordMessage {
					return StartupResult{}, cause.fail(ErrStartupProtocolFailure)
				}
				werr := writeAll(backend, pwFrame)
				// bkz. gorev 8 (onceki revizyon): gecici bayt dilimi
				// (sifre/SASL/SCRAM verisi icerebilir) iletildikten hemen
				// sonra ANINDA atilir - hicbir yerde saklanmaz.
				pwFrame = nil
				if werr != nil {
					return StartupResult{}, cause.fail(classifyBackendWriteErr(werr))
				}
			}
			if state == authStateSucceeded {
				return runPostAuthPhase(client, backend, limits, cause)
			}
			continue
		case tagErrorResponse:
			if err := validateFieldedMessage(body); err != nil {
				return StartupResult{}, cause.fail(err)
			}
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, cause.fail(classifyClientWriteErr(err))
			}
			return StartupResult{}, cause.fail(ErrStartupBackendErrorResponse)
		case tagNoticeResponse:
			if err := validateFieldedMessage(body); err != nil {
				return StartupResult{}, cause.fail(err)
			}
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, cause.fail(classifyClientWriteErr(err))
			}
			continue
		default:
			return StartupResult{}, cause.fail(ErrStartupProtocolFailure)
		}
	}
}

// runPostAuthPhase, AuthenticationOk GORULDUKTEN SONRA backend'den okumaya
// devam eder: ParameterStatus/BackendKeyData/NoticeResponse/
// NegotiateProtocolVersion, RELAY EDILMEDEN ONCE govde bicimleri dogrulanir
// (bkz. gorev 4) ve degismeden relay edilir; ilk ReadyForQuery
// GORULDUGUNDE, govdesinin TAM OLARAK bir bayt VE bu baytin
// protocol.TxStatusIdle ('I') OLDUGU dogrulanir (bkz. gorev 5 - taze bir
// State/ExtendedRuntime her zaman bos baslar, bu yuzden 'T'/'E' ile
// tamamlanan bir handoff GECERSIZDIR ve fail-closed reddedilir) - yalnizca
// gecerli 'I' relay edilir ve basarili sonuc dondurulur. ResponseSequencer'a
// HIC beslenmez, sahte bir Sync/ikinci bir ReadyForQuery ASLA uretilmez.
func runPostAuthPhase(client Transport, backend BackendTransport, limits StartupLimits, cause *causeFlag) (StartupResult, error) {
	for {
		tag, frame, err := readNormalFrame(backend, limits.MaxAuthFrameBytes)
		if err != nil {
			return StartupResult{}, cause.fail(classifyReadNormalFrameErr(err, classifyBackendReadErr))
		}
		body := frame[normalFrameHeaderSize:]
		switch tag {
		case tagParameterStatus:
			if err := validateTwoStringFrame(body); err != nil {
				return StartupResult{}, cause.fail(err)
			}
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, cause.fail(classifyClientWriteErr(err))
			}
			continue
		case tagBackendKeyData:
			if err := validateBackendKeyData(body); err != nil {
				return StartupResult{}, cause.fail(err)
			}
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, cause.fail(classifyClientWriteErr(err))
			}
			continue
		case tagNoticeResponse:
			if err := validateFieldedMessage(body); err != nil {
				return StartupResult{}, cause.fail(err)
			}
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, cause.fail(classifyClientWriteErr(err))
			}
			continue
		case tagNegotiateProtoVers:
			if err := validateNegotiateProtocolVersion(body); err != nil {
				return StartupResult{}, cause.fail(err)
			}
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, cause.fail(classifyClientWriteErr(err))
			}
			continue
		case tagErrorResponse:
			if err := validateFieldedMessage(body); err != nil {
				return StartupResult{}, cause.fail(err)
			}
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, cause.fail(classifyClientWriteErr(err))
			}
			return StartupResult{}, cause.fail(ErrStartupBackendErrorResponse)
		case tagReadyForQuery:
			status, verr := validateInitialReadyForQueryBody(frame)
			if verr != nil {
				return StartupResult{}, cause.fail(verr)
			}
			if err := writeAll(client, frame); err != nil {
				return StartupResult{}, cause.fail(classifyClientWriteErr(err))
			}
			cause.succeed()
			return StartupResult{ReadyStatus: status}, nil
		default:
			return StartupResult{}, cause.fail(ErrStartupProtocolFailure)
		}
	}
}

// validateInitialReadyForQueryBody, bir ReadyForQuery cercevesinin
// govdesinin TAM OLARAK bir bayt oldugunu VE bu baytin
// protocol.TxStatusIdle ('I') OLDUGUNU dogrular (bkz. gorev 5) - taze bir
// protocol.State/ExtendedRuntime her zaman bos (idle) baslar, bu yuzden
// authentication'i tamamlayan ilk ReadyForQuery'nin 'T' (islem icinde) ya da
// 'E' (basarisiz islem) bildirmesi GERCEKTEN imkansiz bir durumdur ve
// fail-closed reddedilir - relay EDILMEZ.
func validateInitialReadyForQueryBody(frame []byte) (byte, error) {
	body := frame[normalFrameHeaderSize:]
	if len(body) != 1 {
		return 0, ErrStartupProtocolFailure
	}
	status := body[0]
	if status != protocol.TxStatusIdle {
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
// classifyReadNormalFrameErr, readNormalFrame'in dondurdugu bir hatayi
// dogru kategoriye ayirir. readNormalFrame IKI FARKLI TURDE hata
// dondurebilir: (a) KENDI cerceveleme dogrulamasinin (uzunluk siniri)
// URETTIGI, ZATEN sabit/guvenli ErrStartupProtocolFailure - bu OLDUGU GIBI
// donulmelidir, ikinci kez siniflandirilip (potansiyel olarak) daha az
// ozel bir kategoriyle EZILMEMELIDIR; (b) io.ReadFull'dan gelen HAM bir G/C
// hatasi - bu, classify parametresiyle (classifyClientReadErr/
// classifyBackendReadErr) siniflandirilmalidir (bkz. gorev 7 - Transport
// enjekte edilmis rastgele metin, yalnizca BU yolla temizlenir).
func classifyReadNormalFrameErr(err error, classify func(error) error) error {
	if errors.Is(err, ErrStartupProtocolFailure) {
		return err
	}
	return classify(err)
}

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

// --- Guvenli hata siniflandirmasi (bkz. gorev 7) ----------------------------
//
// Hicbiri, altta yatan G/C hatasinin (err) KENDI metnini/sarmalamasini
// DONEN degere KOPYALAMAZ - Transport bir arayuz oldugundan, enjekte
// edilmis/hatali bir uygulama rastgele bir hata metni dondurebilir; bu
// metnin RunStartupHandoff'un donen hatasina, cagiranin loglarina ya da
// %v/%+v/%#v ile bicimlendirilmis HICBIR degere sizmamasi icin, yalnizca
// SABIT, guvenli kategoriler donulur - errors.Is ile kontrol edilebilir,
// ama Error() dizesi HER ZAMAN sabittir.

func classifyClientReadErr(err error) error {
	if errors.Is(err, io.EOF) {
		return ErrStartupClientEOF
	}
	return ErrStartupClientReadFailed
}

func classifyClientWriteErr(error) error {
	return ErrStartupClientWriteFailed
}

func classifyBackendReadErr(err error) error {
	if errors.Is(err, io.EOF) {
		return ErrStartupBackendEOF
	}
	return ErrStartupBackendReadFailed
}

func classifyBackendWriteErr(error) error {
	return ErrStartupBackendWriteFailed
}

package protocol

import "errors"

// Bu dosya, PostgreSQL Simple Query Protocol'un (bkz.
// https://www.postgresql.org/docs/current/protocol-flow.html, "Simple
// Query") BACKEND YANIT GRAMERI icin baglanti-yerel (connection-local) bir
// DURUM MODELI tanimlar. extended_correlation.go'daki BackendCorrelator ile
// AYNI tasarim disiplinini izler:
//
//   - baglanti-yereldir (connection-local)
//   - hicbir G/C (I/O) yapmaz, hicbir goroutine/kanal baslatmaz, hicbir sey
//     loglamaz
//   - tek bir goroutine tarafindan SIRALI cagrilmak uzere tasarlanmistir -
//     dahili hicbir kilitleme (mutex) yapmaz
//   - ham backend cerceve baytlarini, SQL metnini, komut etiketini
//     (command tag), ErrorResponse/NoticeResponse alan degerlerini,
//     ParameterStatus adi/degerini, bildirim (notification) kanali/
//     payload'ini ya da backend surec kimligini (PID) ASLA saklamaz -
//     yalnizca sinirli (bounded) faz (phase) meta verisi tutar
//   - O(1) bellek kullanir: statement/satir sayisindan bagimsizdir
//   - tek bir SimpleQueryTracker orneği, cok sayida Simple Query cycle'i
//     boyunca YENIDEN KULLANILABILIR (Reset ile, yeniden tahsis
//     edilmeden)
//
// gateway/firewall/masking paketlerine HENUZ BAGLI DEGILDIR - hicbir
// runtime cagirani yoktur. Bu dosya yalnizca
// docs/design/0002-mixed-query-routing.md'nin "Simple Query response
// grammar" bolumunde tarif edilen, ileriki asamalarin (Stage B ve sonrasi)
// uzerine insa edecegi bagimsiz bir yapi tasidir.
//
// Kaynak: https://www.postgresql.org/docs/current/protocol-flow.html ve
// https://www.postgresql.org/docs/current/protocol-message-formats.html.

// --- Sabit, guvenli hata kategorileri --------------------------------------
//
// extended_correlation.go'daki ile AYNI ilke: hicbir hata SQL metni, ham
// protokol baytlari, sunucu ErrorResponse/Notice metni, CommandComplete
// etiketi, ParameterStatus adi/degeri, bildirim kanali/payload'i ya da
// sinirsiz istemci/sunucu-saglanan veri icermez.
//
// ErrWrongBackendPhase, ErrMalformedBackendMessage ve
// ErrInvalidTransactionStatus KASITLI OLARAK burada yeniden tanimlanmaz -
// anlamlari extended_correlation.go/extended_state.go'daki mevcut
// tanimlarla ZATEN birebir eslesir (bkz. asagidaki Handle), bu yuzden
// dogrudan yeniden kullanilir.
var (
	// ErrSimpleResponseOrderingViolation, SimpleQueryTracker'in Simple
	// Query gramerinin yasakladigi bir backend mesaj sirasi (ya da
	// tracker bosken - idle - bir Handle cagrisi) gozlemledigini bildirir.
	ErrSimpleResponseOrderingViolation = errors.New("simplequery: gecersiz/imkansiz backend mesaj sirasi")
	// ErrSimpleQueryCOPYUnsupported, bir Simple Query yaniti sirasinda bir
	// COPY yanit turu (CopyInResponse/CopyOutResponse/CopyBothResponse)
	// gozlemlendigini bildirir. SentinelDB COPY protokolunu desteklemez
	// (bkz. extended_correlation.go'daki ErrUnsupportedCopyResponse ile
	// AYNI ilke, Simple Query icin ayri bir kategori).
	ErrSimpleQueryCOPYUnsupported = errors.New("simplequery: COPY protokolu desteklenmiyor")
)

// simpleQueryPhase, bir Simple Query cycle'inin SimpleQueryTracker
// tarafindan izlenen dahili fazidir. SIFIR DEGERI (simpleQueryPhase(0))
// KASITLI OLARAK gecerli hicbir faza karsilik gelmez - bu, "bos" (idle)
// durumunu, ekstra bir alan gerekmeden, SimpleQueryTracker'in sifir
// degerinin dogrudan kullanilabilir olmasini saglayacak sekilde temsil
// eder (bkz. SimpleQueryTracker).
type simpleQueryPhase int

const (
	// simplePhaseAwaitingFirstMessage: bu cycle icin henuz hicbir mesaj
	// islenmedi. Gecerli girdiler: RowDescription, CommandComplete,
	// EmptyQueryResponse, ErrorResponse. ReadyForQuery burada GECERSIZDIR
	// (bkz. "bos sorgu" grameri kurali - sifir onceki mesajla gelen "cIplak"
	// bir ReadyForQuery, gercek bir sunucu icin imkansizdir ve fail-closed
	// reddedilir).
	simplePhaseAwaitingFirstMessage simpleQueryPhase = iota + 1

	// simplePhaseAwaitingGroupOrReady: en az bir deyim-sonucu (statement-
	// result) grubu CommandComplete ile tamamlandi YA DA bu, RowDescription'in
	// KENDI grubunun tamamlanmasindan hemen sonrasidir. Gecerli girdiler:
	// RowDescription (sonraki grup baslar), CommandComplete (sonraki,
	// satir-dondurmeyen grup), ReadyForQuery (Query mesaji tamamen islendi).
	simplePhaseAwaitingGroupOrReady

	// simplePhaseInRows: MEVCUT grup icin RowDescription gorulduSSSmu;
	// DataRow* ardindan CommandComplete beklenmektedir. Gecerli girdiler:
	// DataRow (kal), CommandComplete (grup bitti ->
	// simplePhaseAwaitingGroupOrReady), ErrorResponse (satir-akisi
	// ortasinda hata -> simplePhaseAwaitingReadyOnly).
	simplePhaseInRows

	// simplePhaseAwaitingReadyOnly: bu Query mesaji icin EmptyQueryResponse
	// ya da ErrorResponse ZATEN gorulduSSSmu. "Sorgu metninin ileri islenmesi
	// ErrorResponse ile TAMAMEN durdurulur" kuralina gore, kalan TEK gecerli
	// girdi ReadyForQuery'dir.
	simplePhaseAwaitingReadyOnly
)

// SimpleQueryResult, tek bir backend Message'in SimpleQueryTracker.Handle
// tarafindan islenmesinin sonucudur. YALNIZCA sinirli, deger-tipli meta
// veri tasir - CorrelationResult ile AYNI ilke (bkz. extended_correlation.go):
// ham cerceve baytlari, SQL metni, komut etiketi, ErrorResponse/Notice alan
// degeri, ParameterStatus adi/degeri, bildirim kanali/payload'i, backend
// PID'i ya da statement/portal adi ASLA icermez. Donen deger, yalnizca
// hata nil oldugunda anlamlidir.
type SimpleQueryResult struct {
	// MessageType, islenen backend mesajinin etiketidir.
	MessageType MessageType

	// Async true ise mesaj eszamansizdir (NoticeResponse/ParameterStatus/
	// NotificationResponse) - Simple Query yanit fazini DEGISTIRMEZ.
	Async bool

	// CycleCompleted true ise bu mesaj (yalnizca gecerli bir ReadyForQuery)
	// Simple Query cycle'ini tamamladi - tracker bu cagridan sonra IsIdle()
	// dondurur.
	CycleCompleted bool

	// ReadyForQueryStatus, YALNIZCA CycleCompleted true oldugunda anlamlidir
	// ve dogrulanmis 'I'/'T'/'E' degerlerinden biridir. Tamamlanmayan her
	// mesaj icin bu alan SIFIR DEGERINDE kalir (gecerli hicbir islem durumu
	// degildir).
	ReadyForQueryStatus byte
}

// SimpleQueryTracker, PostgreSQL Simple Query Protocol'unun backend yanit
// gramerini (bkz. dosya basi) izleyen, baglanti-yerel, I/O-suz, tek-
// goroutine bir bilesendir.
//
// SIFIR DEGERI DOGRUDAN KULLANILABILIR ve BOS (idle) durumdadir - sync.Mutex
// ile ayni ilke: `var t SimpleQueryTracker` (ya da `new(SimpleQueryTracker)`)
// gecerli, hazir bir tracker'dir; herhangi bir cycle baslamadan once Reset
// cagrilmalidir. Ozel bir yapici (constructor) fonksiyon KASITLI OLARAK
// yoktur.
//
// Tek bir SimpleQueryTracker orneği, cagiran tarafindan (bkz.
// docs/design/0002-mixed-query-routing.md, "Runtime state machine")
// YENIDEN TAHSIS EDILMEDEN, cok sayida Simple Query cycle'i boyunca
// yeniden kullanilmak uzere tasarlanmistir - her cycle'in basinda/sonunda
// yalnizca Reset cagrilir.
//
// Concurrency: State/BackendCorrelator ile AYNI ilke - dahili hicbir
// kilitleme yapmaz, tek bir goroutine tarafindan sirali cagrilmalidir.
type SimpleQueryTracker struct {
	phase simpleQueryPhase
}

// Reset, SimpleQueryTracker'i (bos - idle, tamamlanmis onceki bir cycle
// sonrasi, ya da hala aktif bir fazdaki savunmaci yeniden kullanim -
// HERHANGI bir mevcut durumdan) YENI bir Simple Query cycle'inin basi olan
// simplePhaseAwaitingFirstMessage fazina getirir. Bir onceki cycle'dan
// kalan hicbir meta veri yoktur (SimpleQueryResult hicbir zaman tutulmaz) -
// bu yuzden Reset'in kendisi HICBIR ek durumu temizlemek ZORUNDA DEGILDIR.
//
// Ayni tracker orneği, her YENI Simple Query cycle'inin basinda (bkz.
// dosya basi "yeniden kullanim") tekrar tekrar cagrilmak uzere
// tasarlanmistir.
func (t *SimpleQueryTracker) Reset() {
	t.phase = simplePhaseAwaitingFirstMessage
}

// IsIdle, tracker'in su an AKTIF bir Simple Query cycle'i IZLEMEDIGINI
// bildirir - ya hic Reset cagrilmamistir (sifir deger) ya da en son
// islenen mesaj gecerli bir ReadyForQuery ile cycle'i tamamlamistir.
func (t *SimpleQueryTracker) IsIdle() bool {
	return t.phase == 0
}

// Handle, tek bir decode edilmis backend Message'i isler. m.Direction
// Backend olmalidir. Donen SimpleQueryResult, yalnizca hata nil oldugunda
// anlamlidir.
//
// Dogrulama/hata ONCELIGI (deterministik, mevcut BackendCorrelator
// disiplinini yansitir):
//
//  1. tracker su an bos (idle) ise: HICBIR mesaj incelenmeden
//     ErrSimpleResponseOrderingViolation (Handle, yalnizca Reset sonrasi
//     aktif bir cycle sirasinda cagrilmalidir).
//  2. m.Direction Backend degilse: ErrWrongBackendPhase.
//  3. decode edilmis mesajin en kucuk sekli (tag+length cercevesi,
//     len(m.Raw) >= 5) saglanmiyorsa: ErrMalformedBackendMessage.
//  4. eszamansiz (async) mesaj turleri icin (NoticeResponse/
//     ParameterStatus/NotificationResponse): govde SEKLI dogrulanir ve
//     Async=true ile faz gecisi UYGULANMADAN doner - BackendCorrelator ile
//     AYNI oncelik kurali (async, sira dogrulamasindan ONCE kontrol
//     edilir).
//  5. COPY yanit turleri (CopyInResponse/CopyOutResponse/CopyBothResponse)
//     icin: hicbir govde dogrulamasi yapilmadan, faz DEGISTIRILMEDEN,
//     ErrSimpleQueryCOPYUnsupported.
//  6. taninan sIradan backend mesajlari icin (RowDescription/DataRow/
//     CommandComplete/EmptyQueryResponse/ErrorResponse/ReadyForQuery):
//     govde, MEVCUT paket yardimcilariyla (bkz. asagidaki her isleyici)
//     TAMAMEN dogrulanir - bu dogrulama, mevcut fazdan BAGIMSIZDIR (yanlis
//     fazda gelen bozuk bir govde, sira ihlali degil, YAPISAL bir hata
//     olarak reddedilir).
//  7. YALNIZCA govde dogrulamasi basarili olduktan SONRA, faz/sira gecis
//     tablosu uygulanir - mevcut faz bu mesaji kabul etmiyorsa
//     ErrSimpleResponseOrderingViolation (faz DEGISMEZ).
//  8. baslangic/kimlik-dogrulama mesajlari (Authentication/BackendKeyData),
//     bilinmeyen turler ve Extended Query'ye ozel backend mesajlari
//     (ParseComplete/BindComplete/CloseComplete/ParameterDescription/
//     NoData/PortalSuspended) icin: adim 6'ya hic girilmeden, sabit bir
//     kategoriyle reddedilir (Authentication/BackendKeyData icin
//     ErrWrongBackendPhase - BackendCorrelator'in AYNI sinifllandirmasi;
//     digerleri icin ErrSimpleResponseOrderingViolation).
//
// Her basarisizlik durumunda: tracker fazinda HICBIR mutasyon olmaz, kismi
// meta veri iceren hicbir sonuc dondurulmez, hicbir payload saklanmaz,
// hicbir panic olusmaz - dogrulama TAMAMEN mutasyondan ONCE tamamlanir
// (atomiklik).
func (t *SimpleQueryTracker) Handle(m Message) (SimpleQueryResult, error) {
	if t.IsIdle() {
		return SimpleQueryResult{}, ErrSimpleResponseOrderingViolation
	}
	if m.Direction != Backend {
		return SimpleQueryResult{}, ErrWrongBackendPhase
	}
	if len(m.Raw) < 5 {
		return SimpleQueryResult{}, ErrMalformedBackendMessage
	}
	body := backendBody(m)

	switch m.Type {
	case MsgAuthentication, MsgBackendKeyData:
		// Bu tracker yalnizca Simple Query yanit akisi icindir; baslangic/
		// kimlik dogrulama mesajlari kapsam disidir - BackendCorrelator'in
		// AYNI sinifllandirmasi.
		return SimpleQueryResult{}, ErrWrongBackendPhase

	case MsgNoticeResponse, MsgParameterStatus, MsgNotificationResponse:
		return t.handleAsync(m.Type, body)

	case MsgCopyInResponse, MsgCopyOutResponse, MsgCopyBothResponse:
		// SentinelDB COPY protokolunu desteklemez; sabit, fail-closed bir
		// hata doner - hicbir faz mutasyonu yapilmaz, hicbir govde
		// dogrulamasi denenmez.
		return SimpleQueryResult{}, ErrSimpleQueryCOPYUnsupported

	case MsgRowDescription:
		if _, err := ParseRowDescription(body); err != nil {
			return SimpleQueryResult{}, ErrMalformedBackendMessage
		}
		return t.transitionOnRowDescription()

	case MsgDataRow:
		if _, err := ParseDataRow(body); err != nil {
			return SimpleQueryResult{}, ErrMalformedBackendMessage
		}
		return t.transitionOnDataRow()

	case MsgCommandComplete:
		if err := validateCommandCompleteTag(body); err != nil {
			return SimpleQueryResult{}, err
		}
		return t.transitionOnCommandComplete()

	case MsgEmptyQueryResponse:
		if err := validateEmptyBody(body); err != nil {
			return SimpleQueryResult{}, err
		}
		return t.transitionOnEmptyQueryResponse()

	case MsgErrorResponse:
		if err := validateFieldFraming(body); err != nil {
			return SimpleQueryResult{}, err
		}
		return t.transitionOnErrorResponse()

	case MsgReadyForQuery:
		if len(body) != 1 {
			return SimpleQueryResult{}, ErrMalformedBackendMessage
		}
		status := body[0]
		if status != TxStatusIdle && status != TxStatusInTransaction && status != TxStatusFailedTransaction {
			return SimpleQueryResult{}, ErrInvalidTransactionStatus
		}
		return t.transitionOnReadyForQuery(status)

	default:
		// PortalSuspended (Simple Query'de Execute satir-limiti kavrami
		// yoktur - yapisal olarak imkansizdir), ParseComplete/BindComplete/
		// CloseComplete/ParameterDescription/NoData (Extended Query'ye ozel
		// backend mesajlari) ve bilinmeyen her tur dahil - hepsi ayni
		// sabit, guvenli kategoriyle reddedilir; ErrImpossibleBackendOrdering'in
		// BackendCorrelator'daki mevcut muamelesini yansitir.
		return SimpleQueryResult{}, ErrSimpleResponseOrderingViolation
	}
}

// handleAsync, uc eszamansiz (async) backend mesaj turunu isler:
// NoticeResponse, ParameterStatus, NotificationResponse. Govde SEKLI
// (framing) BackendCorrelator.handleAsync ile AYNI paylasilan yardimcilarla
// dogrulanir - govde ICERIGI (bildirim metni, parametre adi/degeri, kanal
// adi, payload, PID) hicbir zaman okunup disari dondurulmez/saklanmaz.
// Basarili oldugunda faz DEGISMEZ.
func (t *SimpleQueryTracker) handleAsync(msgType MessageType, body []byte) (SimpleQueryResult, error) {
	var err error
	switch msgType {
	case MsgNoticeResponse:
		// NoticeResponse, ErrorResponse ile AYNI alan cercevelemesini
		// kullanir (bkz. extended_correlation.go, validateFieldFraming).
		err = validateFieldFraming(body)
	case MsgParameterStatus:
		err = validateParameterStatusFraming(body)
	case MsgNotificationResponse:
		err = validateNotificationResponseFraming(body)
	}
	if err != nil {
		return SimpleQueryResult{}, err
	}
	return SimpleQueryResult{MessageType: msgType, Async: true}, nil
}

// transitionOnRowDescription, GOVDESI ZATEN dogrulanmis bir RowDescription
// icin faz gecisini uygular. Yalnizca simplePhaseAwaitingFirstMessage ya da
// simplePhaseAwaitingGroupOrReady fazlarindan gecerlidir (yeni bir satir-
// dondurme grubu baslatir) -> simplePhaseInRows.
func (t *SimpleQueryTracker) transitionOnRowDescription() (SimpleQueryResult, error) {
	switch t.phase {
	case simplePhaseAwaitingFirstMessage, simplePhaseAwaitingGroupOrReady:
		t.phase = simplePhaseInRows
		return SimpleQueryResult{MessageType: MsgRowDescription}, nil
	default:
		// simplePhaseInRows: onceki grup CommandComplete ile kapatilmadan
		// ikinci bir RowDescription - imkansiz sira.
		// simplePhaseAwaitingReadyOnly: ErrorResponse/EmptyQueryResponse
		// sonrasi ReadyForQuery disinda hicbir sey gecerli degildir.
		return SimpleQueryResult{}, ErrSimpleResponseOrderingViolation
	}
}

// transitionOnDataRow, GOVDESI ZATEN dogrulanmis bir DataRow icin faz
// gecisini uygular. Yalnizca simplePhaseInRows icinde gecerlidir (kalir).
func (t *SimpleQueryTracker) transitionOnDataRow() (SimpleQueryResult, error) {
	if t.phase != simplePhaseInRows {
		return SimpleQueryResult{}, ErrSimpleResponseOrderingViolation
	}
	return SimpleQueryResult{MessageType: MsgDataRow}, nil
}

// transitionOnCommandComplete, GOVDESI ZATEN dogrulanmis (tek NUL-
// sonlandirmali etiket, etiket ICERIGI hic okunmadan) bir CommandComplete
// icin faz gecisini uygular. simplePhaseAwaitingFirstMessage/
// AwaitingGroupOrReady/InRows'un HERHANGI birinden gecerlidir (bir deyim-
// sonucu grubunu, satir dondurup dondurmedigine bakilmaksizin, kapatir) ->
// simplePhaseAwaitingGroupOrReady.
func (t *SimpleQueryTracker) transitionOnCommandComplete() (SimpleQueryResult, error) {
	switch t.phase {
	case simplePhaseAwaitingFirstMessage, simplePhaseAwaitingGroupOrReady, simplePhaseInRows:
		t.phase = simplePhaseAwaitingGroupOrReady
		return SimpleQueryResult{MessageType: MsgCommandComplete}, nil
	default:
		return SimpleQueryResult{}, ErrSimpleResponseOrderingViolation
	}
}

// transitionOnEmptyQueryResponse, GOVDESI ZATEN dogrulanmis (tamamen bos)
// bir EmptyQueryResponse icin faz gecisini uygular. YALNIZCA
// simplePhaseAwaitingFirstMessage'dan gecerlidir (bos/bosluk-yalnizca sorgu
// metni, HER ZAMAN ilk ve TEK mesajdir - bir grup sonrasi ya da satir-
// akisi ortasinda ASLA gorulmez) -> simplePhaseAwaitingReadyOnly.
func (t *SimpleQueryTracker) transitionOnEmptyQueryResponse() (SimpleQueryResult, error) {
	if t.phase != simplePhaseAwaitingFirstMessage {
		return SimpleQueryResult{}, ErrSimpleResponseOrderingViolation
	}
	t.phase = simplePhaseAwaitingReadyOnly
	return SimpleQueryResult{MessageType: MsgEmptyQueryResponse}, nil
}

// transitionOnErrorResponse, GOVDESI ZATEN dogrulanmis (alan cercevelemesi
// gecerli) bir ErrorResponse icin faz gecisini uygular.
// simplePhaseAwaitingFirstMessage/AwaitingGroupOrReady/InRows'un HERHANGI
// birinden gecerlidir (sorgu metninin ileri islenmesini durdurur) ->
// simplePhaseAwaitingReadyOnly. simplePhaseAwaitingReadyOnly'den (yinelenen
// ErrorResponse) GECERSIZDIR.
func (t *SimpleQueryTracker) transitionOnErrorResponse() (SimpleQueryResult, error) {
	switch t.phase {
	case simplePhaseAwaitingFirstMessage, simplePhaseAwaitingGroupOrReady, simplePhaseInRows:
		t.phase = simplePhaseAwaitingReadyOnly
		return SimpleQueryResult{MessageType: MsgErrorResponse}, nil
	default:
		return SimpleQueryResult{}, ErrSimpleResponseOrderingViolation
	}
}

// transitionOnReadyForQuery, GOVDESI VE DEGERI ZATEN dogrulanmis (tam
// olarak 1 bayt, 'I'/'T'/'E') bir ReadyForQuery icin faz gecisini uygular -
// bu, HER ZAMAN Simple Query cycle'ini SONLANDIRAN TERMINAL mesajdir.
// simplePhaseAwaitingGroupOrReady (normal tamamlanma) ya da
// simplePhaseAwaitingReadyOnly'den (bir ErrorResponse/EmptyQueryResponse
// sonrasi onaylama) gecerlidir. simplePhaseAwaitingFirstMessage'dan (cIplak
// ReadyForQuery, hicbir onceki mesaj olmadan - imkansiz) ya da
// simplePhaseInRows'tan (kapanmamis bir satir grubu - imkansiz)
// GECERSIZDIR. Basarili oldugunda tracker BOS (idle) durumuna doner.
func (t *SimpleQueryTracker) transitionOnReadyForQuery(status byte) (SimpleQueryResult, error) {
	switch t.phase {
	case simplePhaseAwaitingGroupOrReady, simplePhaseAwaitingReadyOnly:
		t.phase = 0 // idle - cycle tamamlandi
		return SimpleQueryResult{
			MessageType:         MsgReadyForQuery,
			CycleCompleted:      true,
			ReadyForQueryStatus: status,
		}, nil
	default:
		return SimpleQueryResult{}, ErrSimpleResponseOrderingViolation
	}
}

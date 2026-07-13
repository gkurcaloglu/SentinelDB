// Bu dosya, opt-in, steady-state (post-authentication) bir Extended Query
// Protocol frontend köprüsü (ExtendedFrontend) ve onu bir client
// bağlantısına bağlayan Gate.RunExtended giriş noktasını içerir.
//
// KAPSAM: bu, SentinelDB'nin ALTINCI Extended Query aşamasıdır (ve onun
// sertleştirme revizyonudur) - decode edilmiş steady-state frontend
// mesajlarını (Parse/Bind/Describe/Execute/Close/Flush/Sync/Terminate)
// tüketir, Parse-zamanlı politika denetimi uygular, izin verilen
// işlemleri internal/gateway.ExtendedRuntime aracılığıyla kaydedip
// upstream'e iletir, yerel reddetmelerde sentetik ErrorResponse üretir ve
// client-facing discard-until-Sync'i uygular.
//
// ÇERÇEVELEME/AYRIŞTIRMA AYRIMI (bkz. sertleştirme incelemesi): RunExtended
// artık protocol.NewSteadyStateFrontendFrameDecoder kullanır - bu decoder
// YALNIZCA normal tag+length çerçeveleme sınırlarını doğrular, HİÇBİR
// tipli Extended Query gövde ayrıştırıcısını çağırmaz. Bir mesajın gövdesi
// - kasıtlı olarak bozuk olsa bile - ExtendedFrontend kendi discard-until-
// Sync kararını vermeden ASLA ayrıştırılmaz: discard aktifken tamamen
// çerçevelenmiş bozuk bir gövde artık decoder düzeyinde kurtarılamaz bir
// hataya yol AÇMAZ, sessizce düşürülür (bkz. handle, gorev 3). Gövde
// ayrıştırması bu yüzden BURADA, her handleXxx fonksiyonunun kendisinde
// gerçekleşir (bkz. frontendPayload, gorev 2).
//
// Bu yol KESİNLİKLE opt-in ve test-only'dir: cmd/gateway hiçbir zaman
// Gate.RunExtended'i çağırmaz; canlı gateway akışı (Gate.Run) DEĞİŞMEDEN
// kalır ve Extended Query'yi hâlâ fail-closed reddeder (bkz. gate.go,
// isExtendedProtocolMessage/rejectExtendedProtocol). Startup/authentication
// yönlendirmesi, masking.Transformer entegrasyonu, Extended Query DataRow
// maskeleme, karma Simple/Extended Query desteği bu aşamanın KAPSAMI
// DIŞINDADIR (bkz. docs/design/0001-extended-query.md).
package firewall

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/gateway"
	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// --- Sabit hata kategorileri ------------------------------------------
//
// Hiçbiri ham baytlar, SQL metni, Bind parametre değerleri, statement/
// portal adları, sunucu hata metni, decoder/parser ayrıntıları, bildirilen
// uzunluklar ya da mesaj etiketleri İÇERMEZ (bkz. gorev 6) - RunExtended
// HER ZAMAN bu sabit kategorilerden birini döndürür, asla girdi-türevli
// ayrıntı EKLEMEZ.
var (
	// ErrNilExtendedRuntime, NewExtendedFrontend'e nil bir
	// *gateway.ExtendedRuntime verildiğinde döndürülür.
	ErrNilExtendedRuntime = errors.New("firewall: nil ExtendedRuntime saglanamaz")
	// ErrNilExtendedFrontend, Gate.RunExtended'e nil bir *ExtendedFrontend
	// verildiğinde döndürülür.
	ErrNilExtendedFrontend = errors.New("firewall: RunExtended icin nil ExtendedFrontend saglanamaz")
	// ErrExtendedFrontendUnsupportedMessage, opt-in Extended Query
	// yoluna Simple Query (MsgQuery), COPY frontend mesajlari ya da baska
	// herhangi bir taninmayan/desteklenmeyen steady-state frontend
	// mesaji ulastiginda kullanilir - bu yol Extended-Query-ONLY'dir
	// (bkz. gorev 13); karma Simple/Extended Query destegi ileriki,
	// ayrica kapsamlandirilmis bir asama gerektirir.
	ErrExtendedFrontendUnsupportedMessage = errors.New("firewall: opt-in Extended Query yolu bu steady-state mesaj turunu desteklemiyor")
	// ErrExtendedFrontendDecodeFailed, ExtendedFrontend'in kendi client
	// decoder'i (cerceveleme sinirlari) ya da EOF'ta Finalize kurtarilamaz
	// bir hata bildirdiginde kullanilir - HER ZAMAN fail-closed'dir. Hicbir
	// zaman altta yatan decoder hatasinin (bildirilen uzunluk, tag, vb.)
	// detaylarini ICERMEZ (bkz. gorev 6).
	ErrExtendedFrontendDecodeFailed = errors.New("firewall: Extended Query frontend cercevesi ayristirilamadi")
	// ErrExtendedFrontendReadFailed, RunExtended client baglantisindan
	// EOF-DISI bir hata ile karsilastiginda kullanilir.
	ErrExtendedFrontendReadFailed = errors.New("firewall: Extended Query frontend baglantisindan okuma basarisiz")
	// ErrExtendedFrontendMalformedFrame, Sync ya da Terminate govdesi
	// dogrulanamadiginda kullanilir - HER IKISI de protokolun senkronizasyon/
	// sonlandirma noktalaridir ve bozulmalari "yerel ret + discard" ile
	// KURTARILAMAZ (bkz. gorev 2, "Sync"/"Terminate") - runtime fail-closed
	// sonlandirilir, cerceve ASLA iletilmez, discard ASLA temizlenmez.
	ErrExtendedFrontendMalformedFrame = errors.New("firewall: Sync/Terminate cercevesi gecersiz, baglanti guvenlik icin sonlandirildi")
	// ErrSyncCycleMismatch, bir Sync kaydinin dondurdugu CycleID, bridge'in
	// kaydettigi engellenmis (blocked) cycle ile UYUSMADIGINDA kullanilir -
	// bu, imkansiz bir sahiplik/sira ihlalidir (bkz. gorev 11) ve HER
	// ZAMAN fail-closed sonlanir.
	ErrSyncCycleMismatch = errors.New("firewall: Sync kaydi, bridge'in engellenmis (blocked) cycle'i ile uyusmuyor")
)

// Sabit, guvenli SQLSTATE kodlari ve ret nedenleri (bkz. gorev 10). Hicbiri
// istemci tarafindan saglanan SQL/isim/deger icermez.
const (
	sqlStatePolicyBlocked = "42501" // insufficient_privilege (Gate.handle'in Simple Query blok koduyla AYNI)
	sqlStateProtocolError = "08P01" // protocol_violation (Gate.handleDecodeError'in koduyla AYNI)
	sqlStateInvalidRef    = "26000" // invalid_sql_statement_name

	reasonMalformedBody    = "SentinelDB policy: gecersiz Extended Query mesaj govdesi, baglanti guvenlik icin reddedildi"
	reasonUnknownReference = "SentinelDB policy: bilinmeyen ya da gecersiz Extended Query referansi"
)

// ExtendedFrontend, decode edilmis steady-state Extended Query frontend
// mesajlarini tuketen, govde ayristirmasindan discard kararini ONCELIKLI
// tutan (bkz. gorev 2-3), Parse-zamanli politika denetimi uygulayan ve
// izin verilen islemleri internal/gateway.ExtendedRuntime araciligiyla
// kaydedip upstream'e ileten opt-in bir koprudur (bkz. dosya basi yorumu).
//
// TEK GOROUTINE varsayimi: ExtendedFrontend, Gate.RunExtended'in TEK
// client-okuma goroutine'inden - decoder'in senkron handler geri
// cagirisi araciligiyla - cagirilmak uzere tasarlanmistir; hicbir dahili
// kilitleme yapmaz (bkz. gorev 11, "The bridge is single-threaded; no
// mutex is required for this state").
//
// ExtendedFrontend ASLA: istemciye yazmaz, Extended Query Raw cercevelerini
// dogrudan upstream'e yazmaz, protocol.State'i mutasyona ugratmaz,
// ResponseSequencer'i cagirmaz, backend baytlarini okumaz, Bind parametre
// degerlerini saklamaz, Raw cerceveleri runtime cagrisi dondukten sonra
// saklamaz (bkz. gorev 14).
type ExtendedFrontend struct {
	runtime  *gateway.ExtendedRuntime
	policy   Policy
	onDecide func(m protocol.Message, v Verdict, reason string, duration time.Duration)

	// discardCycle, bridge-yerel client-facing discard-until-Sync
	// durumudur (bkz. gorev 11): protocol.NoCycle ise discard AKTIF
	// DEGILDIR; aksi halde runtime tarafindan dondurulen, engellenmis
	// (blocked) TAM cycle degeridir.
	//
	// SAHIPLIK: bu alan MUNHASIRAN Gate.RunExtended'in TEK cagiran
	// goroutine'i tarafindan okunur/yazilir (dogrudan ya da handle/
	// rejectLocally/handleSync araciligiyla). BASKA HICBIR goroutine -
	// TEST GOROUTINE'I DAHIL - bu alani (ya da discarding() metodunu)
	// RunExtended calisirken DOGRUDAN okumamalidir; bu, senkronizasyonsuz
	// bir veri yarisidir (bkz. "fix: remove extended frontend test
	// races" - CI'nin Linux -race isi bunu tam olarak boyle yakaladi).
	// Testler bunun yerine GOZLEMLENEBILIR davranisi (iletilen/iletilmeyen
	// cerceveler, sentetik hata sayisi, policy cagri sayaci, ya da
	// asagidaki onLocalRejectionAccepted gibi ozel amacli, thread-safe
	// bir kanca) kullanmalidir - bkz. extended_frontend_test.go.
	discardCycle protocol.CycleID

	// err/terminated, ExtendedFrontend'in kalici olarak sonlandigini
	// (ve varsa RunExtended'in dondurecegi SABIT hatayi) kaydeder - Gate.
	// Run'in kendi g.err alaniyla AYNI desen (bkz. gate.go). discardCycle
	// ile AYNI sahiplik kurali gecerlidir: yalnizca RunExtended'in
	// cagiran goroutine'i (isTerminal/terminalError DAHIL, bkz. asagida)
	// dokunur - test goroutine'i ASLA dogrudan okumamalidir.
	err        error
	terminated bool

	// onLocalRejectionAccepted, YALNIZCA PAKET TESTLERI tarafindan
	// ayarlanan istege bagli bir kancadir (bkz. internal/gateway'deki
	// AYNI desen, ör. onFrontendEventAccepted/onWatcherShutdownBegun) -
	// rejectLocally basariyla discardCycle'i ayarladiktan HEMEN SONRA
	// cagrilir. Uretimde HER ZAMAN nil'dir ve hicbir etkisi yoktur.
	// Testlerin "discard tam olarak ne zaman basladi" sorusunu
	// discardCycle'i DOGRUDAN okumadan, zamanlamaya (sleep) basvurmadan
	// deterministik olarak cevaplamasini saglar - ör. bir cycle'in
	// backend'den bagimsiz sekilde ANINDA engellendigini kanitlamak icin
	// (bkz. gorev 12, "blocked-first"). Yalnizca RunExtended baslamadan
	// ONCE ayarlanmalidir (Go bellek modelinin goroutine-olusturma
	// happens-before garantisiyle veri yarisini onler); kancanin KENDISI
	// yalnizca thread-safe ilkeller (ör. bir kanali kapatmak) kullanmali,
	// ASLA ExtendedFrontend'in mutable alanlarini test goroutine'ine
	// sizdirmamalidir.
	onLocalRejectionAccepted func()
}

// NewExtendedFrontend, verilen runtime uzerinde calisan yeni bir
// ExtendedFrontend olusturur. runtime nil olamaz. policy nil olabilir (bu
// durumda TUM Parse islemleri Allow kabul edilir - Gate.Run'in nil-Policy
// davranisiyla AYNI kural). onDecide, her Parse politika kararinda (yalnizca
// Parse - bkz. gorev 8) cagirilir; nil olabilir.
func NewExtendedFrontend(
	runtime *gateway.ExtendedRuntime,
	policy Policy,
	onDecide func(m protocol.Message, v Verdict, reason string, duration time.Duration),
) (*ExtendedFrontend, error) {
	if runtime == nil {
		return nil, ErrNilExtendedRuntime
	}
	return &ExtendedFrontend{runtime: runtime, policy: policy, onDecide: onDecide}, nil
}

// RunExtended, client'tan EOF olana, kurtarilamaz bir hata olusana ya da
// bir Terminate basari ile iletilene kadar okur - opt-in, post-authentication
// Extended Query steady-state giris noktasidir (bkz. dosya basi yorumu,
// gorev 2).
//
// client, YALNIZCA authentication TAMAMLANDIKTAN sonraki steady-state
// baytlari saglamalidir - startup/authentication yonlendirmesi bu
// fonksiyonun kapsami DISINDADIR (bkz.
// protocol.NewSteadyStateFrontendFrameDecoder).
//
// Decoder YALNIZCA cerceveleme (framing) sinirlarini dogrular - govde
// ayrıştırması ExtendedFrontend'e AITTIR (bkz. gorev 1-2). client'tan EOF
// alindiginda, decoder.Finalize cagrilarak ARABELLEKTE hala cozumlenmemis
// bayt olup olmadigi kontrol edilir: varsa bu KESILMIS bir cerceve
// demektir ve temiz bir kapanis olarak RAPORLANMAZ (bkz. gorev 4).
//
// Donus semantigi Gate.Run ile AYNI kuralı izler: temiz bir client EOF ya
// da basarili bir client-baslatilan Terminate nil doner; okuma hatalari,
// decoder cerceveleme hatalari (kesilmis cerceveler dahil) ve
// desteklenmeyen steady-state mesajlari (bkz. gorev 13) kendi sabit,
// guvenli hatalarini dondurur. RunExtended KESINLIKLE istemciye bayt
// yazmaz - tum client-bound cerceveler MUNHASIRAN runtime'in event-loop
// yazicisi araciligiyla gider (bkz. gorev 14).
func (g *Gate) RunExtended(ctx context.Context, client io.Reader, frontend *ExtendedFrontend) error {
	if frontend == nil {
		return ErrNilExtendedFrontend
	}

	dec := protocol.NewSteadyStateFrontendFrameDecoder(
		func(m protocol.Message) { frontend.handle(ctx, m) },
		func(err error) { frontend.handleDecodeError(ctx, err) },
	)

	buf := make([]byte, 32*1024)
	for {
		n, readErr := client.Read(buf)
		if n > 0 {
			dec.Write(buf[:n])
			if frontend.isTerminal() {
				return frontend.terminalError()
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				if finalizeErr := dec.Finalize(); finalizeErr != nil {
					frontend.closeTruncated(ctx)
				} else {
					frontend.closeClean(ctx)
				}
			} else {
				frontend.closeReadError(ctx, readErr)
			}
			return frontend.terminalError()
		}
	}
}

// --- ExtendedFrontend ic durum yonetimi -----------------------------------
//
// UYARI: asagidaki uc yardimci (isTerminal/terminalError/discarding)
// YALNIZCA Gate.RunExtended'in TEK cagiran goroutine'i icinden
// cagirilmalidir (dogrudan RunExtended'den, ya da handle/rejectLocally/
// handleSync gibi AYNI goroutine icinde calisan yardimcilardan). Bu
// paketin kendi testleri DAHIL, hicbir kod bunlari BASKA bir goroutine'den
// (ör. RunExtended hala calisirken bir test goroutine'inden) cagirmamalidir -
// senkronize edilmemis bir okuma/yazma veri yarisi olusturur (bkz. "fix:
// remove extended frontend test races").

func (f *ExtendedFrontend) isTerminal() bool     { return f.terminated }
func (f *ExtendedFrontend) terminalError() error { return f.err }
func (f *ExtendedFrontend) discarding() bool     { return f.discardCycle != protocol.NoCycle }

// terminate, ExtendedFrontend'i KALICI olarak sonlandirir (TAM OLARAK BIR
// KEZ - sonraki cagrilar no-op'tur, ILK neden kazanir) ve runtime'i
// NotifyFrontendClosed araciligiyla haberdar eder (bkz. gorev 5, 7).
//
// NotifyFrontendClosed'in sonucu ARTIK yoksayilmaz (bkz. gorev 5, "Do not
// use `_ = NotifyFrontendClosed(...)` as the ordinary correctness path"):
// runtime'in KENDI Run() donene kadar BLOKE eder ve o KESIN sonucu
// GERCEKTEN INCELER (asagidaki errors.Is dali). RunExtended'in donus
// degeri (f.err) HER ZAMAN bridge'in KENDI sabit kategorisidir (cause,
// bkz. gorev 6) - runtime'in kendi sentinel kategorisi
// (gateway.ErrFrontendClosed/vb.) hicbir zaman disariya cig olarak
// sizdirilmaz. TEK anlamli inceleme dali: runtime Run() HIC
// BASLAMAMISSA (gateway.ErrNotRunning), bu bridge'in kendi cause'undan
// BAGIMSIZ, ayri bir gercek durumdur - yine de RunExtended ayni sabit
// kategoriyi (cause) dondurur, ancak bu dal testler icin ayirt edilebilir
// kalir (bkz. gorev 7 testleri).
func (f *ExtendedFrontend) terminate(ctx context.Context, reason gateway.FrontendCloseReason, cause error) {
	if f.terminated {
		return
	}
	f.terminated = true
	f.err = cause
	if runtimeErr := f.runtime.NotifyFrontendClosed(ctx, reason, cause); errors.Is(runtimeErr, gateway.ErrNotRunning) {
		// Runtime Run() hic baslamamisti - kapanma istegi hicbir event
		// loop'u etkilemedi (etkileyecek bir loop yoktu). Bridge'in kendi
		// sabit cause'u (f.err) zaten dogru, tek anlamli sonuctur.
		return
	}
}

// markTerminatedCleanly, ExtendedFrontend'i hata OLMADAN sonlandirir (ör.
// basarili bir client-baslatilan Terminate sonrasi - bkz. handleTerminate).
func (f *ExtendedFrontend) markTerminatedCleanly() {
	f.terminated = true
}

// closeClean, RunExtended'in client EOF + basarili Decoder.Finalize
// yolundan cagrilir (bkz. gorev 4). Gate.Run'in mevcut "temiz EOF -> nil"
// sozlesmesini korumak icin f.err KASITLI OLARAK nil birakilir - runtime'in
// kendi (beklenen) ErrFrontendClosed kapanma nedeni RunExtended'in donus
// degerini ETKILEMEZ. NotifyFrontendClosed'in sonucu yine de GERCEKTEN
// INCELENIR (bkz. gorev 5): runtime GERCEKTEN durana kadar burada bloke
// edilir VE runtime'in Run() hic baslamamis olma ihtimali (ErrNotRunning)
// ayirt edilir (temiz-EOF sonucu her iki durumda da nil kalir, ama dal
// testler icin ayirt edilebilir).
func (f *ExtendedFrontend) closeClean(ctx context.Context) {
	if f.terminated {
		return
	}
	f.terminated = true
	if runtimeErr := f.runtime.NotifyFrontendClosed(ctx, gateway.FrontendClosedEOF, nil); errors.Is(runtimeErr, gateway.ErrNotRunning) {
		// Runtime Run() hic baslamamisti - yine de temiz EOF Gate.Run'in
		// sozlesmesi geregi nil doner (f.err zaten nil).
		return
	}
}

// closeTruncated, RunExtended'in client EOF + BASARISIZ Decoder.Finalize
// (ErrTruncatedMessage) yolundan cagrilir (bkz. gorev 4): bu TEMIZ bir
// kapanis DEGILDIR - bir mesajin ortasinda kesilmis bir baglantidir,
// fail-closed olarak ele alinir. Hicbir arabellek/deklare edilen uzunluk/
// tag/govde degeri disariya SIZMAZ - yalnizca sabit ErrExtendedFrontendDecodeFailed
// kullanilir.
func (f *ExtendedFrontend) closeTruncated(ctx context.Context) {
	f.terminate(ctx, gateway.FrontendClosedProtocolError, ErrExtendedFrontendDecodeFailed)
}

// closeReadError, RunExtended'in client baglantisindan EOF-DISI bir okuma
// hatasi aldigi yoldan cagrilir. Alttaki G/C hatasinin (readErr) KENDISI
// asla RunExtended'in donus degerine SIZMAZ (bkz. gorev 6) - yalnizca
// sabit ErrExtendedFrontendReadFailed kategorisi kullanilir; readErr
// yalnizca runtime'a (zaten belgelenmis guvenli-sarma kuraliyla, bkz.
// gateway paketi) bilgilendirme amacli iletilir.
func (f *ExtendedFrontend) closeReadError(ctx context.Context, readErr error) {
	f.terminate(ctx, gateway.FrontendClosedReadError, ErrExtendedFrontendReadFailed)
}

// handleDecodeError, framing-only decoder'in kurtarilamaz bir cerceveleme
// hatasiyla (ör. gecersiz uzunluk alani) karsilastigini bildirir. Altta
// yatan decoder hatasi (bildirilen uzunluk, tag, vb. icerebilir) ASLA
// disariya sizdirilmaz (bkz. gorev 6) - yalnizca sabit
// ErrExtendedFrontendDecodeFailed kullanilir.
func (f *ExtendedFrontend) handleDecodeError(ctx context.Context, err error) {
	if f.terminated {
		return
	}
	f.terminate(ctx, gateway.FrontendClosedProtocolError, ErrExtendedFrontendDecodeFailed)
}

// rejectLocally, TEK bir sentetik ErrorResponse cercevesi insa eder
// (protocol.BuildErrorResponse - Gate.handle'in Simple Query blok yolunda
// KULLANDIGI AYNI yardimci), event-loop'un KENDI GUNCEL cycle'i icin
// runtime'a sunar (bkz. gorev 5, SubmitSyntheticErrorForCurrentCycle) ve
// basarili kabul uzerine client-facing discard-until-Sync'e girer (bkz.
// gorev 10-11). sqlState/reason HER ZAMAN sabit, guvenli degerlerdir -
// istemci tarafindan saglanan hicbir SQL/isim/deger asla bu cerceveye
// (policy blok nedeni HARIC - bu zaten client-facing/guvenli tasarlanmistir)
// girmez.
func (f *ExtendedFrontend) rejectLocally(ctx context.Context, sqlState, reason string) {
	frame := protocol.BuildErrorResponse("ERROR", sqlState, reason)
	cycle, err := f.runtime.SubmitSyntheticErrorForCurrentCycle(ctx, frame)
	if err != nil {
		f.terminate(ctx, gateway.FrontendClosedProtocolError, err)
		return
	}
	f.discardCycle = cycle
	if f.onLocalRejectionAccepted != nil {
		f.onLocalRejectionAccepted()
	}
}

// isFatalRegistrationError, RegisterAndForwardFrontendOperation/
// SubmitSyntheticErrorForCurrentCycle/ForwardFlush/ForwardTerminate'den
// donen bir hatanin runtime'i ZATEN KALICI olarak sonlandirdigini (ya da
// sonlandirdigini) - dolayisiyla bridge'in KENDI baska hicbir sey
// YAPMADAN kendi tarafini da sonlandirmasi gerektigini - belirler. Bunun
// DISINDAKI TUM hatalar mutasyonsuz/kurtarilabilir kabul edilir (bkz.
// gorev 10).
func isFatalRegistrationError(err error) bool {
	return errors.Is(err, gateway.ErrFrontendRegistrationDiverged) ||
		errors.Is(err, gateway.ErrBackendWriteFailed) ||
		errors.Is(err, gateway.ErrClientWriteFailed) ||
		errors.Is(err, gateway.ErrRuntimeStopped) ||
		errors.Is(err, gateway.ErrNotRunning)
}

// handleRegistrationOutcome, registerAndForward/handleSync'in BASARISIZ
// bir RegisterAndForwardFrontendOperation cagrisindan sonra izleyecegi
// ORTAK karar mantigidir (bkz. gorev 10).
func (f *ExtendedFrontend) handleRegistrationOutcome(ctx context.Context, err error) {
	if isFatalRegistrationError(err) {
		f.terminate(ctx, gateway.FrontendClosedProtocolError, err)
		return
	}
	if errors.Is(err, gateway.ErrInvalidFrontendFrame) || errors.Is(err, gateway.ErrFrontendFrameTooLarge) {
		f.rejectLocally(ctx, sqlStateProtocolError, reasonMalformedBody)
		return
	}
	// Geriye kalan tek kategori: State.Create* kendi sozlesmesi geregi
	// hicbir mutasyon uygulamadan reddetti (ör. bilinmeyen statement/
	// portal, nadir bir tanimlayici tukenmesi) - sabit, guvenli bir
	// nedenle yerel ret + discard.
	f.rejectLocally(ctx, sqlStateInvalidRef, reasonUnknownReference)
}

func (f *ExtendedFrontend) registerAndForward(ctx context.Context, req gateway.FrontendOperationRequest, m protocol.Message) {
	if _, err := f.runtime.RegisterAndForwardFrontendOperation(ctx, req, m.Raw); err != nil {
		f.handleRegistrationOutcome(ctx, err)
	}
}

// frontendPayload, m.Raw'dan (tag(1) + uzunluk(4) haric) govdeyi cikarir.
// m, protocol.NewSteadyStateFrontendFrameDecoder tarafindan uretildigi
// icin Raw HER ZAMAN en az 5 bayt uzunluktadir ve TAM OLARAK bir cerceveye
// karsilik gelir (bkz. protocol.consumeNormal) - bu fonksiyon yalnizca
// tag+length onekini atlar, hicbir ek dogrulama yapmaz (govde dogrulamasi
// cagiranin - ilgili protocol.ParseFrontendXxx fonksiyonunun - isidir).
func frontendPayload(m protocol.Message) []byte {
	if len(m.Raw) < 5 {
		return nil
	}
	return m.Raw[5:]
}

// --- Mesaj dagitimi (bkz. gorev 2, 3, 9, 11, 12, 13) ------------------------

// handle, protocol.NewSteadyStateFrontendFrameDecoder'in senkron handler
// geri cagirisidir - Gate.RunExtended'in TEK okuma goroutine'inden
// cagirilir. m yalnizca cerceveleme meta-verisi tasir (Type/Name/Length/
// Raw) - govde HENUZ ayristirilmamistir (bkz. gorev 1-2): discard karari
// HER ZAMAN govde ayristirmasindan ONCE verilir (bkz. gorev 3).
func (f *ExtendedFrontend) handle(ctx context.Context, m protocol.Message) {
	if f.terminated {
		return
	}

	// Sync/Terminate discard durumundan BAGIMSIZ HER ZAMAN islenir (bkz.
	// gorev 3, 11: "Still process: Sync, after validating its body;
	// Terminate, after validating its body").
	switch m.Type {
	case protocol.MsgSync:
		f.handleSync(ctx, m)
		return
	case protocol.MsgTerminate:
		f.handleTerminate(ctx, m)
		return
	}

	// Karma protokol kapsami: yalnizca Extended Query steady-state
	// mesajlari desteklenir - MsgQuery/COPY/taninmayan herhangi bir tur
	// discard durumundan BAGIMSIZ fail-closed reddedilir (bkz. gorev 3,
	// 13: "Unsupported or unknown message types remain terminal
	// fail-closed").
	switch m.Type {
	case protocol.MsgParse, protocol.MsgBind, protocol.MsgDescribe, protocol.MsgExecute, protocol.MsgClose, protocol.MsgFlush:
		// devam
	default:
		f.terminate(ctx, gateway.FrontendClosedProtocolError, ErrExtendedFrontendUnsupportedMessage)
		return
	}

	if f.discarding() {
		// bkz. gorev 3: discard sirasinda Parse/Bind/Describe/Execute/
		// Close/Flush - GOVDELERI KASITLI OLARAK BOZUK OLSA BILE -
		// hicbir isleme (ayristirma/politika/kayit/iletim) tabi
		// tutulmadan sessizce dusurulur. Govde ayristirmasi asagidaki
		// handleXxx fonksiyonlarinin icindedir - bu noktada ASLA
		// cagirilmazlar.
		return
	}

	switch m.Type {
	case protocol.MsgParse:
		f.handleParse(ctx, m)
	case protocol.MsgBind:
		f.handleBind(ctx, m)
	case protocol.MsgDescribe:
		f.handleDescribe(ctx, m)
	case protocol.MsgExecute:
		f.handleExecute(ctx, m)
	case protocol.MsgClose:
		f.handleClose(ctx, m)
	case protocol.MsgFlush:
		f.handleFlush(ctx, m)
	}
}

// handleParse, govdeyi BURADA ayristirir (bkz. gorev 2) ve TEK Parse-zamanli
// politika denetim noktasidir (bkz. gorev 8). Malformed govde, sentetik
// ErrorResponse + discard ile SONUCLANIR (fail-closed DEGIL) - bkz. gorev 2.
func (f *ExtendedFrontend) handleParse(ctx context.Context, m protocol.Message) {
	parsed, err := protocol.ParseFrontendParse(frontendPayload(m))
	if err != nil {
		f.rejectLocally(ctx, sqlStateProtocolError, reasonMalformedBody)
		return
	}

	policyMsg := protocol.Message{Direction: protocol.Frontend, Type: protocol.MsgParse, Name: "Parse", Query: parsed.Query}
	start := time.Now()
	verdict, reason := Allow, ""
	if f.policy != nil {
		verdict, reason = f.policy.Evaluate(policyMsg)
	}
	duration := time.Since(start)
	if f.onDecide != nil {
		// Sanitize edilmis metadata: Query/Raw ICERMEZ (bkz. gorev 8/17).
		f.onDecide(protocol.Message{Direction: protocol.Frontend, Type: protocol.MsgParse, Name: "Parse"}, verdict, reason, duration)
	}
	if verdict == Block {
		f.rejectLocally(ctx, sqlStatePolicyBlocked, reason)
		return
	}

	req := gateway.FrontendOperationRequest{
		Kind:          protocol.OpParse,
		StatementName: parsed.StatementName,
		Query:         parsed.Query,
		ParamOIDs:     parsed.ParamOIDs,
	}
	f.registerAndForward(ctx, req, m)
}

// handleBind, govdeyi BURADA ayristirir (bkz. gorev 2). Malformed govde,
// sentetik ErrorResponse + discard ile SONUCLANIR.
func (f *ExtendedFrontend) handleBind(ctx context.Context, m protocol.Message) {
	parsed, err := protocol.ParseFrontendBind(frontendPayload(m))
	if err != nil {
		f.rejectLocally(ctx, sqlStateProtocolError, reasonMalformedBody)
		return
	}
	req := gateway.FrontendOperationRequest{
		Kind:          protocol.OpBind,
		PortalName:    parsed.PortalName,
		StatementName: parsed.StatementName,
		ParamFormats:  parsed.ParamFormats,
		ParamNulls:    bindParamNulls(parsed.Params),
		ResultFormats: parsed.ResultFormats,
	}
	f.registerAndForward(ctx, req, m)
}

// bindParamNulls, Bind parametrelerinin YALNIZCA NULL bayraklarini
// cikarir - DEGERLER (bkz. protocol.BindParam.Value) hicbir zaman
// FrontendOperationRequest'e (dolayisiyla State'e) girmez (bkz. gorev 9,
// "Bind privacy").
func bindParamNulls(params []protocol.BindParam) []bool {
	nulls := make([]bool, len(params))
	for i, p := range params {
		nulls[i] = p.Null
	}
	return nulls
}

// handleDescribe, govdeyi BURADA ayristirir (bkz. gorev 2). Malformed
// govde, sentetik ErrorResponse + discard ile SONUCLANIR.
func (f *ExtendedFrontend) handleDescribe(ctx context.Context, m protocol.Message) {
	parsed, err := protocol.ParseFrontendDescribe(frontendPayload(m))
	if err != nil {
		f.rejectLocally(ctx, sqlStateProtocolError, reasonMalformedBody)
		return
	}
	req := gateway.FrontendOperationRequest{Kind: protocol.OpDescribeStatement}
	if parsed.Target == protocol.TargetPortal {
		req.Kind = protocol.OpDescribePortal
		req.PortalName = parsed.Name
	} else {
		req.StatementName = parsed.Name
	}
	f.registerAndForward(ctx, req, m)
}

// handleExecute, govdeyi BURADA ayristirir (bkz. gorev 2). Malformed
// govde, sentetik ErrorResponse + discard ile SONUCLANIR.
func (f *ExtendedFrontend) handleExecute(ctx context.Context, m protocol.Message) {
	parsed, err := protocol.ParseFrontendExecute(frontendPayload(m))
	if err != nil {
		f.rejectLocally(ctx, sqlStateProtocolError, reasonMalformedBody)
		return
	}
	req := gateway.FrontendOperationRequest{Kind: protocol.OpExecute, PortalName: parsed.PortalName}
	f.registerAndForward(ctx, req, m)
}

// handleClose, govdeyi BURADA ayristirir (bkz. gorev 2). Malformed govde,
// sentetik ErrorResponse + discard ile SONUCLANIR.
func (f *ExtendedFrontend) handleClose(ctx context.Context, m protocol.Message) {
	parsed, err := protocol.ParseFrontendClose(frontendPayload(m))
	if err != nil {
		f.rejectLocally(ctx, sqlStateProtocolError, reasonMalformedBody)
		return
	}
	req := gateway.FrontendOperationRequest{Kind: protocol.OpCloseStatement}
	if parsed.Target == protocol.TargetPortal {
		req.Kind = protocol.OpClosePortal
		req.PortalName = parsed.Name
	} else {
		req.StatementName = parsed.Name
	}
	f.registerAndForward(ctx, req, m)
}

// handleFlush, govdeyi BURADA ayristirir (bkz. gorev 2). Flush'in
// kavramsal bir "backend onayi" olmadigindan (bkz. gorev 6/9), malformed
// bir govde de digerleriyle AYNI sekilde ele alinir: yerel ret + discard
// (gorev 2'nin tercih edilen davranisi) - Flush ASLA upstream'e iletilmez.
// Gecerli bir govde icin hicbir State/sequencer mutasyonu yapilmadan
// ExtendedRuntime.ForwardFlush araciligiyla upstream'e iletilir.
func (f *ExtendedFrontend) handleFlush(ctx context.Context, m protocol.Message) {
	if err := protocol.ParseFrontendFlush(frontendPayload(m)); err != nil {
		f.rejectLocally(ctx, sqlStateProtocolError, reasonMalformedBody)
		return
	}
	if err := f.runtime.ForwardFlush(ctx, m.Raw); err != nil {
		f.terminate(ctx, gateway.FrontendClosedProtocolError, err)
	}
}

// handleTerminate, discard durumundan BAGIMSIZ HER ZAMAN cagrilir (bkz.
// gorev 2/6/11). Govde BURADA dogrulanir: malformed bir Terminate ASLA
// upstream'e iletilmez ve fail-closed sonlanir (bkz. gorev 2, "Terminate").
// Basarili iletimden SONRA bridge kendi tarafini HATASIZ (temiz) olarak
// sonlandirir - runtime'in KENDI ic sonlanma nedeni (bkz.
// ErrFrontendTerminateRequested) RunExtended'in donus degerini ETKILEMEZ;
// Gate.Run'in temiz-EOF sozlesmesiyle TUTARLI olarak RunExtended nil doner.
func (f *ExtendedFrontend) handleTerminate(ctx context.Context, m protocol.Message) {
	if f.terminated {
		return
	}
	if err := protocol.ParseFrontendTerminate(frontendPayload(m)); err != nil {
		f.terminate(ctx, gateway.FrontendClosedProtocolError, ErrExtendedFrontendMalformedFrame)
		return
	}
	if err := f.runtime.ForwardTerminate(ctx, m.Raw); err != nil {
		f.terminate(ctx, gateway.FrontendClosedProtocolError, err)
		return
	}
	f.markTerminatedCleanly()
}

// handleSync, discard durumundan BAGIMSIZ HER ZAMAN cagrilir (bkz. gorev
// 2/3/11, "Still honor: Sync"). Govde BURADA dogrulanir: Sync protokolun
// senkronizasyon noktasidir - malformed bir Sync ASLA discard'i temizlemez
// ve ASLA iletilmez; fail-closed sonlanir (bkz. gorev 2, "Sync" - "remain
// in discard and terminate fail-closed" secenegi). Bu, zaten engellenmis
// bir cycle icin IKINCI bir sentetik hata URETMEZ (rejectLocally hic
// cagirilmaz). Basarili kayit/iletimden sonra, eger bridge discard
// modundaysa, dondurulen CycleID'nin bridge'in kaydettigi engellenmis
// cycle ile TAM OLARAK eslesmesi GEREKIR - eslesmezse bu imkansiz bir
// sahiplik/sira ihlalidir ve fail-closed sonlanir.
func (f *ExtendedFrontend) handleSync(ctx context.Context, m protocol.Message) {
	if f.terminated {
		return
	}
	if err := protocol.ParseFrontendSync(frontendPayload(m)); err != nil {
		f.terminate(ctx, gateway.FrontendClosedProtocolError, ErrExtendedFrontendMalformedFrame)
		return
	}
	req := gateway.FrontendOperationRequest{Kind: protocol.OpSync}
	reg, err := f.runtime.RegisterAndForwardFrontendOperation(ctx, req, m.Raw)
	if err != nil {
		f.handleRegistrationOutcome(ctx, err)
		return
	}
	if f.discarding() {
		if reg.Operation.Cycle != f.discardCycle {
			f.terminate(ctx, gateway.FrontendClosedProtocolError, ErrSyncCycleMismatch)
			return
		}
		// bkz. gorev 11: discard, basarili Sync iletiminden SONRA HEMEN
		// temizlenir - gercek ReadyForQuery'nin gelmesi BEKLENMEZ; daha
		// sonraki cycle'a ait frontend mesajlari ANINDA kabul edilebilir
		// hale gelir.
		f.discardCycle = protocol.NoCycle
	}
}

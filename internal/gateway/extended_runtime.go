// Package gateway, Extended Query Protocol icin bağlantı-yerel,
// olay-güdümlü (event-driven) bir çalışma zamanı kabuğu içerir
// (ExtendedRuntime, bkz. extended_runtime.go).
//
// Paket konumu gerekçesi: internal/protocol, tüm Extended Query
// bileşenlerinde (extended_state.go, extended_correlation.go,
// extended_sequence.go) kasıtlı olarak G/Ç yapmayan, goroutine
// başlatmayan saf bir kütüphane olarak tutulmuştur - her biri bunu
// açıkça belgeler. ExtendedRuntime ise tanımı gereği goroutine'ler,
// kanallar ve gerçek net.Conn G/Ç'si kullanır; bunu doğrudan
// internal/protocol içine koymak o paketin kurulu "no I/O" sözleşmesini
// bozar. internal/firewall, internal/protocol'e bağımlıdır (tersi değil);
// bu paket de AYNI yönü izler ve firewall'a hiç dokunmaz. internal/masking'e
// olan bağımlılık ise BİLİNÇLİ ve TEK YÖNLÜDÜR (bkz. opt-in Extended Query
// yanıt maskelemesi, NewExtendedRuntimeWithMasking, internal/masking/extended.go) -
// internal/masking hiçbir zaman internal/gateway'e bağımlı değildir, bu
// yüzden döngüsel bir bağımlılık oluşmaz. "gateway" adı bu bileşenin
// cmd/gateway'in bağlantı işleme akışına bağlandığını yansıtır: opt-in
// protocol.extended_query_enabled=true modunda cmd/gateway/main.go'nun
// runExtendedConnection'ı, RunStartupHandoff başarıyla tamamlandıktan
// SONRA tam olarak bir ExtendedRuntime (gerekirse NewExtendedRuntimeWithMasking
// ile) oluşturur - varsayılan (false) modda hâlâ hiç kullanılmaz, mevcut
// Simple Query yolu (runSimpleConnection) değişmeden kalır.
package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/gkurcaloglu/sentineldb/internal/masking"
	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// BackendTransport, ExtendedRuntime'in gercek backend baglantisi uzerinde
// ihtiyac duydugu TAM G/C yuzeyidir: hem backend'den okuma (sunucu
// yanitlari) hem backend'e yazma (allowed frontend cercevelerinin upstream
// iletimi, bkz. RegisterAndForwardFrontendOperation/ForwardFlush/
// ForwardTerminate) hem de kapatma. Onceki asamada ExtendedRuntime yalnizca
// io.ReadCloser sahibiydi (upstream yazma sorumlulugu gelecekteki bir
// cagirana birakilmisti) - bu artik yeterli degil: kayit (State/sequencer)
// basarili olduktan SONRA cagiranin kendi upstream yazmasi, kismi bir yazma
// hatasinda runtime'in gercek sunucunun HICBIR ZAMAN gormedigi "canli" bir
// islem icermesine yol acabilirdi (bkz. gorev 3). Bu yuzden NewExtendedRuntime
// artik backend transport'un TAMAMINI (okuma+yazma+kapatma) sahiplenir; TEK
// event-loop goroutine'i hem okur (dolayli olarak, ayri okuyucu goroutine
// araciligiyla) hem de upstream'e yazar - iki farkli goroutine ASLA ayni
// anda backend'e erismez (okuyucu yalnizca Read cagirir, event-loop yalnizca
// Write cagirir).
type BackendTransport interface {
	io.Reader
	io.Writer
	io.Closer
}

// backendReadBufferSize, backend okuyucunun tek bir Read çağrısında
// kullandığı sabit boyutlu tampon boyutudur. internal/firewall/gate.go'nun
// mevcut 32 KiB tamponuyla tutarlıdır.
const backendReadBufferSize = 32 * 1024

// --- Sabit hata kategorileri ------------------------------------------
//
// Hiçbiri ham baytlar, SQL metni, Bind parametre değerleri, statement/
// portal adları, ErrorResponse alanları ya da CommandComplete etiketleri
// İÇERMEZ. Alttaki G/Ç hatası (%w ile sarılan) yalnızca bağlantı/aktarım
// düzeyinde metin taşır (ör. "broken pipe"), hiçbir zaman protokol yükü
// değil.
var (
	ErrNilState             = errors.New("extendedruntime: nil protocol.State saglanamaz")
	ErrNilBackend           = errors.New("extendedruntime: nil backend reader saglanamaz")
	ErrNilClient            = errors.New("extendedruntime: nil client writer saglanamaz")
	ErrInvalidRuntimeLimits = errors.New("extendedruntime: gecersiz runtime sinirlari (pozitif olmali)")

	// ErrAlreadyRunning, Run ikinci kez cagrildiginda donulur (Run
	// created -> running gecisini tam olarak bir kez yapabilir).
	ErrAlreadyRunning = errors.New("extendedruntime: Run zaten cagrildi")
	// ErrNotRunning, Run henuz hic cagrilmamisken bir submit metodu
	// cagrildiginda ANINDA (bloklamadan) donulur.
	ErrNotRunning = errors.New("extendedruntime: runtime henuz calismiyor (Run cagrilmadi)")
	// ErrRuntimeStopped, runtime kalici olarak sonlandiktan (ya da
	// sonlanma surecine girdikten) sonra herhangi bir submit ya da ikinci
	// bir Run cagrisinda donulur. AYNI zamanda, ZATEN kabul edilmis ve
	// tamamen islenmis (State/sequencer mutasyonu dahil) bir frontend
	// olayinin basarili ack'i, kapanma gozetmeninin dogrusallastirma
	// noktasini (bkz. beginWatcherShutdown, gorev 2) KAYBETTIGINDE de
	// donulur - bu durumda cagirana ASLA basarili bir
	// FrontendRegistration/nil sonuc verilmez.
	ErrRuntimeStopped = errors.New("extendedruntime: runtime kalici olarak durduruldu")

	// ErrTerminationRequested, Run'in birincil (primary) hatasi olarak,
	// ResponseSequencer bir OutputAction batch'i icinde
	// ActionTerminateConnection dondurdugunde kullanilir.
	ErrTerminationRequested = errors.New("extendedruntime: sequencer baglanti sonlandirmasini istedi")
	// ErrClientWriteFailed, istemciye yazma basarisiz oldugunda donulen
	// sarmalayici hatadir.
	ErrClientWriteFailed = errors.New("extendedruntime: istemciye yazma basarisiz")
	// ErrBackendProtocolFailure, ResponseSequencer.HandleBackendMessage
	// bir hata dondurdugunde (plan uyusmazligi, bozuk cerceve,
	// desteklenmeyen COPY, imkansiz siralama, sequencer zaten terminal)
	// kullanilir - gercek sunucuyla senkronizasyon artik guvenilir
	// olmadigindan bu HER ZAMAN runtime'i kalici olarak sonlandirir.
	ErrBackendProtocolFailure = errors.New("extendedruntime: backend mesaji sequencer tarafindan reddedildi")
	// ErrBackendReadFailed, backend'den okuma (decode hatasi dahil)
	// basarisiz oldugunda kullanilir.
	ErrBackendReadFailed = errors.New("extendedruntime: backend okuma/ayristirma basarisiz")
	// ErrBackendClosedUnexpectedly, backend hala cozumlenmemis
	// (HasPendingWork()==true) plan birimleri varken EOF ile
	// kapandiginda donulur.
	ErrBackendClosedUnexpectedly = errors.New("extendedruntime: backend, bekleyen sekans durumu varken beklenmedik sekilde kapandi")
	// ErrTruncatedBackendMessage, backend baglantisi bir mesajin
	// ortasinda (protocol.Decoder.Finalize'in tespit ettigi uzere)
	// kapandiginda kullanilir - "temiz" bir EOF DEGILDIR, fail-closed
	// bir backend protokol hatasidir.
	ErrTruncatedBackendMessage = errors.New("extendedruntime: backend baglantisi bir mesaj tam olarak alinmadan kapandi")
	// ErrNoProgress, bir Write cagrisi (0, nil) dondurdugunde - yani
	// hicbir hata bildirmeden hicbir ilerleme kaydetmediginde - kullanilir.
	ErrNoProgress = errors.New("extendedruntime: writer ilerleme kaydetmedi (0 bayt, hata yok)")

	// ErrInvalidOperationKind, FrontendOperationRequest.Kind taniniyor
	// bir OperationKind degilse donulur - hicbir State mutasyonu
	// denenmeden reddedilir.
	ErrInvalidOperationKind = errors.New("extendedruntime: gecersiz frontend islem turu")
	// ErrFrontendRegistrationDiverged, protocol.State.Create* BASARILI
	// oldugu (State zaten mutasyona ugradigi) ama sonraki
	// ResponseSequencer.AddForwardedOperation cagrisi BASARISIZ oldugunda
	// donulur. Bu noktada State kuyrugu ile sequencer plani artik
	// uyusmuyor demektir - runtime KALICI olarak sonlanir; State/
	// sequencer bir daha asla kullanilmaz ve hicbir spekulatif geri alma
	// (rollback) denenmez (tam, test edilmis bir State geri alma ilkeli
	// olmadan).
	ErrFrontendRegistrationDiverged = errors.New("extendedruntime: State islemi olusturuldu ama sequencer kaydi basarisiz oldu (uyusmazlik)")

	// --- Upstream iletim (bkz. gorev 3-7) ---------------------------------

	// ErrBackendWriteFailed, State/sequencer kaydi BASARILI olduktan SONRA
	// orijinal frontend cercevesinin backend'e (upstream) yazilmasi
	// basarisiz oldugunda donulur. Bu HER ZAMAN runtime'i kalici olarak
	// fail-closed sonlandirir: kayit zaten yapilmis olabilir (backend
	// kismen ya da hic almamis olabilir) - hicbir "guvenle yeniden
	// deneyebilirsin" varsayimi yapilamaz, hicbir State geri almasi
	// denenmez.
	ErrBackendWriteFailed = errors.New("extendedruntime: frontend cercevesinin backend'e (upstream) yazilmasi basarisiz")
	// ErrInvalidFrontendFrame, RegisterAndForwardFrontendOperation/
	// ForwardFlush/ForwardTerminate'e verilen frame, istenen islem turu
	// icin tam, tek, dogru etiketli bir normal-protokol frontend cercevesi
	// OLMADIGINDA donulur (bkz. gorev 4: eksik baslik, uzunluk uyusmazligi,
	// fazla/artik bayt, yanlis tag, Describe/Close hedef secici
	// uyusmazligi, govde tipi ayristiricinin reddi). Hicbir mutasyon
	// (State/sequencer) denenmeden reddedilir - runtime saglikli kalir.
	ErrInvalidFrontendFrame = errors.New("extendedruntime: gecersiz ya da istenen islemle uyusmayan frontend cercevesi")
	// ErrFrontendFrameTooLarge, verilen frame RuntimeLimits.MaxFrontendFrameBytes'i
	// astiginda donulur - hicbir mutasyon denenmeden reddedilir.
	ErrFrontendFrameTooLarge = errors.New("extendedruntime: frontend cercevesi izin verilen en fazla boyutu asiyor")
	// ErrFrontendTerminateRequested, istemci gecerli bir Terminate
	// cercevesi gonderdiginde ve bu cerceve basari ile upstream'e
	// iletildiginde, Run'in birincil (primary) hatasi olarak kullanilir -
	// runtime bu noktadan sonra kalici olarak sonlanir (bkz.
	// ForwardTerminate). Bu, ForwardTerminate'in cagirana dondurdugu
	// (basarili iletimi onaylayan, nil) sonuctan BAGIMSIZDIR.
	ErrFrontendTerminateRequested = errors.New("extendedruntime: istemci Terminate gonderdi, baglanti kalici olarak sonlandiriliyor")
	// ErrFrontendClosed, frontend ureticisinin (bkz. NotifyFrontendClosed)
	// client baglantisinda TEMIZ bir EOF gozlemleyip artik daha fazla
	// frontend olayi gondermeyecegini bildirdiginde Run'in birincil hatasi
	// olarak kullanilir.
	ErrFrontendClosed = errors.New("extendedruntime: frontend ureticisi baglantiyi temiz sekilde kapatti (EOF)")
	// ErrFrontendReadFailed, frontend ureticisi client baglantisindan
	// okurken EOF-DISI bir hata ile karsilastigini bildirdiginde kullanilir.
	ErrFrontendReadFailed = errors.New("extendedruntime: frontend baglantisindan okuma basarisiz")
	// ErrFrontendProtocolFailure, frontend ureticisi kendi decoder/
	// cerceveleme katmaninda kurtarilamaz bir hata (ör. bozuk cerceve,
	// desteklenmeyen steady-state mesaji) bildirdiginde kullanilir - bu
	// HER ZAMAN fail-closed'dir.
	ErrFrontendProtocolFailure = errors.New("extendedruntime: frontend decoder/cerceveleme hatasi")

	// --- Extended maskeleme (bkz. gorev 9-13, opt-in) ---------------------

	// ErrNilMasker, NewExtendedRuntimeWithMasking'e maskingConfig.Enabled
	// true iken nil bir masking.Masker verildiginde donulur.
	ErrNilMasker = errors.New("extendedruntime: maskeleme etkinken nil Masker saglanamaz")
	// ErrExtendedMaskingPreflightRejected, bir Execute icin maskeleme
	// on-kontrolu (preflight) - HICBIR State/sequencer mutasyonu
	// uygulanmadan - basarisiz oldugunda donulen SABIT, KURTARILABILIR
	// (recoverable) ret kategorisidir (bilinmeyen sonuc sekli, ikili
	// maskeleme hedefi, tutarsiz/gecersiz format meta verisi, ya da
	// sekil kapasitesi asimi). Cagiran (bkz. internal/firewall.ExtendedFrontend)
	// bunu digerleri gibi yerel bir ret (rejectLocally + discard-until-Sync)
	// olarak islemelidir - runtime'i SONLANDIRMAZ.
	ErrExtendedMaskingPreflightRejected = errors.New("extendedruntime: Execute maskeleme on-kontrolunden gecemedi")
	// ErrExtendedMaskingFailed, GERCEK bir backend yaniti (Describe sekli
	// gozlemi ya da DataRow donusumu) islenirken kurtarilamaz bir hataya
	// (bozuk RowDescription/DataRow, taahhut edilmis plan eksik, ikili
	// hedef sutun, Masker hatasi, sekil kapasitesi asimi) rastlandiginda
	// donulen SABIT birincil hatadir - runtime'i KALICI olarak fail-closed
	// sonlandirir. Bu, ResponseSequencer'dan GECMEZ (yerel bir sentetik ret
	// DEGILDIR) - zaten client'a girmis/girmekte olan gercek bir backend
	// yanitinin guvenlik hatasidir. Hicbir SQL/isim/deger/ham cerceve
	// icermez.
	ErrExtendedMaskingFailed = errors.New("extendedruntime: yanit maskelenirken kurtarilamaz bir hata olustu, baglanti guvenlik icin kapatildi")
	// ErrNoCommittedMaskPlan, bir Execute'a ait DataRow icin ExtendedTracker'da
	// TAAHHUT EDILMIS bir effective maskeleme plani bulunamadiginda donulur
	// (bkz. gorev 12: "fail closed if masking is enabled and no plan
	// exists") - HER ZAMAN ErrExtendedMaskingFailed'e sarilarak kullanilir,
	// hicbir SQL/isim/deger icermez.
	ErrNoCommittedMaskPlan = errors.New("extendedruntime: DataRow icin taahhut edilmis maskeleme plani yok")
)

// Extended maskeleme hatasi FATAL ErrorResponse'u icin SABIT, guvenli
// SQLSTATE/reason (bkz. gorev 13 - "The FATAL frame must be built from
// constants only"). masking.Transformer'in kendi failClosed'inin
// kullandigi "58030" (veri koruma/isleme hatasi) kategorisiyle tutarlidir.
const (
	sqlStateExtendedMaskingFailed = "58030"
	reasonExtendedMaskingFailed   = "SentinelDB: yanit maskelenirken bir hata olustu, baglanti guvenlik icin kapatildi"
)

// RuntimeLimits, ExtendedRuntime'in olay kanallari icin pozitif, sinirli
// kapasiteler tanimlar. Sifir ya da negatif bir alan yapiciyi basarisiz
// kilar.
type RuntimeLimits struct {
	// FrontendEventBuffer, RegisterFrontendOperation/SubmitSyntheticError
	// tarafindan gonderilen olaylar icin arabellek kapasitesidir.
	FrontendEventBuffer int
	// BackendEventBuffer, backend okuyucu tarafindan gonderilen
	// (mesaj/hata/EOF) olaylar icin arabellek kapasitesidir.
	BackendEventBuffer int
	// MaxFrontendFrameBytes, RegisterAndForwardFrontendOperation/
	// ForwardFlush/ForwardTerminate'e verilen TEK bir frontend
	// cercevesinin (tag + 4 baytlik uzunluk + govde dahil TOPLAM) izin
	// verilen en fazla bayt boyutudur (bkz. gorev 16). Pozitif olmalidir;
	// bu sinir asildiginda cagri hicbir mutasyon denenmeden
	// ErrFrontendFrameTooLarge ile reddedilir.
	MaxFrontendFrameBytes int
}

func (l RuntimeLimits) validate() error {
	if l.FrontendEventBuffer <= 0 || l.BackendEventBuffer <= 0 || l.MaxFrontendFrameBytes <= 0 {
		return ErrInvalidRuntimeLimits
	}
	return nil
}

// DefaultRuntimeLimits, uretim amacli makul, pozitif varsayilan
// RuntimeLimits dondurur (bkz. gorev 13 - cmd/gateway'in opt-in Extended
// Query yolunda dagilmis "sihirli sayilar" yerine kullanilmasi icin).
// MaxFrontendFrameBytes, internal/protocol'un kendi maxMessageLength
// sinirtiyla (1 MiB) tutarlidir.
func DefaultRuntimeLimits() RuntimeLimits {
	return RuntimeLimits{
		FrontendEventBuffer:   64,
		BackendEventBuffer:    64,
		MaxFrontendFrameBytes: 1 << 20,
	}
}

// lifecycleState, ExtendedRuntime'in yasam dongusu asamalaridir.
type lifecycleState int32

const (
	lifecycleCreated lifecycleState = iota
	lifecycleRunning
	lifecycleStopping
	lifecycleStopped
)

// --- Frontend istek modeli ------------------------------------------------
//
// State artik SADECE event-loop goroutine'i tarafindan olusturulur/
// mutasyona ugratilir. Dis (gelecekteki frontend) cagiranlar State'e
// DOGRUDAN erisemez - yalnizca bu guvenli, deger-turunde istegi
// gonderirler; State.Create* cagrisinin KENDISI event-loop icinde
// gerceklesir (bkz. RegisterFrontendOperation).

// FrontendOperationRequest, bir Extended Query frontend islemini State
// uzerinde olusturmak icin gereken - VE YALNIZCA gereken - guvenli
// bilgiyi tasir. Bind PARAMETRE DEGERLERI (gercek sorgu parametre
// baytlari) bu yapida KESINLIKLE YOKTUR ve hicbir zaman runtime durumuna
// girmez - yalnizca format kodlari/null bayraklari/OID'ler (protokol
// metadata'si, deger degil) tasinir.
type FrontendOperationRequest struct {
	Kind protocol.OperationKind

	// Yalnizca secilen Kind tarafindan kullanilan alanlar anlamlidir;
	// digerleri yoksayilir.
	StatementName string
	PortalName    string
	Query         string
	ParamOIDs     []uint32
	ParamFormats  []int16
	ParamNulls    []bool
	ResultFormats []int16
}

// copy, cagirandan BAGIMSIZ, kanal sinirini guvenle gecebilecek bir
// kopya dondurur - tum slice alanlari da dahil (bkz. gorev 1: "All slice
// fields in the request must be copied before crossing the channel
// boundary").
func (req FrontendOperationRequest) copy() FrontendOperationRequest {
	return FrontendOperationRequest{
		Kind:          req.Kind,
		StatementName: req.StatementName,
		PortalName:    req.PortalName,
		Query:         req.Query,
		ParamOIDs:     append([]uint32(nil), req.ParamOIDs...),
		ParamFormats:  append([]int16(nil), req.ParamFormats...),
		ParamNulls:    append([]bool(nil), req.ParamNulls...),
		ResultFormats: append([]int16(nil), req.ResultFormats...),
	}
}

// FrontendRegistration, basarili bir RegisterFrontendOperation
// cagrisinin sonucudur: State.Create* + ResponseSequencer kaydi + ani
// cikti eylemlerinin TAMAMI basari ile tamamlandiktan sonraki degismez
// islem goruntusudur.
//
// Operation, protocol.PendingOperation DEGIL, protocol.CorrelatedOperation
// turundedir - protocol.PendingOperation'in TargetName alani (istemci
// tarafindan verilen statement/portal adi) hicbir zaman runtime API'sinden
// disariya sizmaz; yalnizca ID/Cycle/Kind/TargetGeneration gibi sayisal,
// guvenli metadata dondurulur (bkz. createStateOperation/sanitizeOperation).
type FrontendRegistration struct {
	Operation protocol.CorrelatedOperation
}

// sanitizeOperation, bir State.Create* cagrisindan donen tam
// protocol.PendingOperation goruntusunu, TargetName'i (istemci tarafindan
// verilen ad) ATIP yalnizca sayisal/guvenli alanlari tasiyan bir
// protocol.CorrelatedOperation'a donusturur. Bu, runtime API'sinin
// disariya asla bir isim ACIGA CIKARMAMASINI saglayan TEK gecis
// noktasidir.
func sanitizeOperation(op protocol.PendingOperation) protocol.CorrelatedOperation {
	return protocol.CorrelatedOperation{
		ID:               op.ID,
		Cycle:            op.Cycle,
		Kind:             op.Kind,
		TargetGeneration: op.TargetGeneration,
	}
}

// --- Olay modeli --------------------------------------------------------

type frontendEventKind int

const (
	frontendEventRegister frontendEventKind = iota + 1
	frontendEventRegisterAndForward
	frontendEventSynthetic
	frontendEventSyntheticCurrentCycle
	frontendEventFlush
	frontendEventTerminate
)

// FrontendCloseReason, frontend ureticisinin (bkz. NotifyFrontendClosed)
// client-okuma dongusunun HANGI nedenle sona erdigini bildirdigini
// belirtir.
type FrontendCloseReason int

const (
	// FrontendClosedEOF, client baglantisinda TEMIZ bir EOF gozlemlendigini
	// belirtir - client baglantiyi normal sekilde kapatmistir.
	FrontendClosedEOF FrontendCloseReason = iota + 1
	// FrontendClosedReadError, client baglantisindan EOF-DISI bir okuma
	// hatasi olustugunu belirtir.
	FrontendClosedReadError
	// FrontendClosedProtocolError, frontend ureticisinin kendi decoder/
	// cerceveleme katmaninda (ör. bozuk cerceve, desteklenmeyen
	// steady-state mesaji) kurtarilamaz bir hata ile karsilastigini
	// belirtir - HER ZAMAN fail-closed'dir.
	FrontendClosedProtocolError
)

// frontendEvent, RegisterFrontendOperation/RegisterAndForwardFrontendOperation/
// SubmitSyntheticError/SubmitSyntheticErrorForCurrentCycle/ForwardFlush/
// ForwardTerminate tarafindan olusturulan, degismez bir istek goruntusudur.
// ack, kapasitesi 1 olan tamponlu bir kanaldir: cagiranin ctx'i olay kabul
// edildikten SONRA ama sonuc alinmadan ONCE iptal edilirse, olay isleyici
// goroutine'inin (event loop) gonderim sirasinda asla bloklanmamasini
// (dolayisiyla sizinti olusmamasini) saglar.
//
// NotifyFrontendClosed BURAYA DAHIL DEGILDIR (bkz. gorev 5): frontend
// kapanmasi artik frontendEvents kanalindan/event-loop'tan GECMEZ - event
// loop backend.Write/client.Write icinde bloklu olsa BILE isleyebilecek
// AYRI, bagimsiz bir kapanma-istegi yolu kullanir (bkz.
// frontendShutdownRequest, beginFrontendShutdown).
type frontendEvent struct {
	kind frontendEventKind
	req  FrontendOperationRequest // yalnizca frontendEventRegister/RegisterAndForward icin
	// frame, cagirandan BAGIMSIZ bir kopyadir: frontendEventRegisterAndForward
	// (orijinal frontend cercevesi), frontendEventSynthetic/SyntheticCurrentCycle
	// (sentetik ErrorResponse cercevesi) ve frontendEventFlush/Terminate
	// (orijinal Flush/Terminate cercevesi) tarafindan kullanilir.
	frame []byte
	cycle protocol.CycleID // yalnizca frontendEventSynthetic icin (acik cycle)

	ack chan frontendAck
}

type frontendAck struct {
	reg   FrontendRegistration
	cycle protocol.CycleID // yalnizca frontendEventSyntheticCurrentCycle basarisinda anlamli
	err   error
}

type backendEventKind int

const (
	backendEventMessage backendEventKind = iota + 1
	backendEventDecodeError
	backendEventEOF
	backendEventReadError
)

// backendEvent, backend okuyucu goroutine'inden event loop'a gonderilen
// tek bir olaydir.
type backendEvent struct {
	kind backendEventKind
	msg  protocol.Message // yalnizca backendEventMessage icin
	err  error            // decode/read hatalari icin
}

// ExtendedRuntime, tek bir baglanti icin calisan, olay-güdümlü Extended
// Query Protocol calisma zamanidir.
//
// State sahiplik modeli: NewExtendedRuntime, dependency-injection amacli
// yeni olusturulmus bir *protocol.State kabul eder - ANCAK Run
// baslatildigi andan itibaren State'in SAHIBI VE TEK MUTASYONA
// UGRATICISI munhasiran (exclusively) event-loop goroutine'idir. Dis
// (gelecekteki frontend) cagiranlar State'e hicbir zaman dogrudan
// erisemez; yalnizca FrontendOperationRequest degerleri gonderirler ve
// State.Create* cagrisi event-loop icinde, sequencer kaydiyla AYNI
// event-loop turunda gerceklesir. ExtendedRuntime, sahip oldugu *State'i
// hicbir public accessor uzerinden disariya sizdirmaz.
//
// Tam olarak bir protocol.ResponseSequencer'a sahiptir; Run icindeki TEK
// event-loop goroutine'i hem State'i hem sequencer'i dokunan, istemciye
// yazan TEK bileşendir; ayri bir backend-okuyucu goroutine'i sinirli
// (bounded) kanallar araciligiyla olay besler.
//
// ExtendedRuntime hicbir global degiskenli durum tutmaz, log yazmaz ve
// hicbir donen hata/olay SQL, Bind degeri, statement/portal adi ya da
// sunucu hata metni ACIGA CIKARMAZ.
//
// cmd/gateway/main.go'nun opt-in runExtendedConnection'i, basarili bir
// startup/authentication devrinden (bkz. RunStartupHandoff) SONRA tam
// olarak bir ExtendedRuntime olusturup Run'ini baslatir - varsayilan
// (protocol.extended_query_enabled=false) modda bu TAMAMEN devre disidir.
type ExtendedRuntime struct {
	state *protocol.State
	seq   *protocol.ResponseSequencer

	backend BackendTransport
	client  io.WriteCloser

	limits RuntimeLimits

	frontendEvents chan frontendEvent
	backendEvents  chan backendEvent

	lifecycle atomic.Int32

	// terminalRequested, yalnizca event-loop goroutine'i tarafindan
	// okunur/yazilir (baska hicbir goroutine dokunmaz) - bu yuzden adi
	// gecen goroutine icin sira disi bir senkronizasyona ihtiyac yoktur.
	terminalRequested bool

	// started, Run'in basarili CAS'inin hemen ardindan TAM OLARAK BIR KEZ
	// kapatilir. Yalnizca testlerin "Run baslamis mi" durumunu uykuya
	// (sleep) basvurmadan, uygun bir senkronizasyon ilkeliyle
	// bekleyebilmesi icindir; disariya (paket disina) YOK.
	started chan struct{}
	// stopped, runtime kalici olarak durduktan sonra TAM OLARAK BIR KEZ
	// kapatilir; submit() cagrilarinin - olay zaten kabul edilmisse dahi -
	// event-loop artik calismiyor olsa bile sonsuza kadar bloklanmamasini
	// saglayan tek kacis noktasidir.
	stopped chan struct{}

	closeOnce sync.Once

	// shutdownCause, kapanmayi hangi tetikleyicinin BASLATTIGINI (bkz.
	// shutdownCause turu) kayit altina alan tek seferlik bir
	// atomic.CompareAndSwap hedefidir - Run'in dondugu birincil hatanin
	// nedensellik (causality) belirlenimi icin kullanilir. ARTIK
	// yalnizca Run donduğunde DEGIL, event-loop'un (loop) HER terminal
	// donus noktasinda VE kapanma gozetmeninde, ilgili nedenin TAM
	// OLARAK belirlendigi anda yazilir (bkz. markInternalShutdown/
	// markParentShutdown, gorev 1).
	shutdownCause atomic.Int32

	// ackGate, basarili bir frontend ack'inin (bkz. sendFrontendSuccess)
	// kapanma gozetmeninin "basari kabulunu kalici olarak kapatma"
	// gecisine (bkz. beginWatcherShutdown) karsi TEK dogrusallastirma
	// (linearization) noktasidir - gorev 2. Bir mutex + duz bir bool
	// kullanilir (kanal DEGIL): hem watcher'in hem event-loop'un
	// birbirini asla bloklamadan, tek bir atomik gecis noktasinda
	// karar vermesini saglar.
	ackGate sync.Mutex
	// ackGateClosed, YALNIZCA ackGate altinda okunur/yazilir.
	// beginWatcherShutdown tarafindan true'ya cevrildikten SONRA
	// sendFrontendSuccess bir daha ASLA basarili bir ack gonderemez -
	// yalnizca sabit ErrRuntimeStopped donebilir.
	ackGateClosed bool

	// frontendShutdownCh, NotifyFrontendClosed'in (bkz. gorev 5) event
	// loop'tan TAMAMEN BAGIMSIZ kapanma-istegi yoludur - kapasitesi 1,
	// yalnizca kapanma gozetmeni tarafindan gozlemlenir. Bunun frontendEvents
	// KANALINDAN GECMEMESI KRITIKTIR: event loop backend.Write/client.Write
	// icinde bloklu olsa BILE, gozetmen bu kanali BAGIMSIZ olarak
	// gozlemleyip baglantilari kapatabilir.
	frontendShutdownCh chan frontendShutdownRequest
	// frontendShutdownOnce, NotifyFrontendClosed'in frontendShutdownCh'e
	// TAM OLARAK BIR KEZ gonderim yapmasini saglar - art arda cagrilar
	// (ör. testler, ya da savunma amacli ikinci bir cagiran) kanalin
	// TEK GOZLEMCISI (gozetmen, TEK SEFERLIK select) tarafindan zaten
	// tuketilmis olsa bile guvenle sonuc bekleyebilir (bkz. asagida
	// finalErr/stopped).
	frontendShutdownOnce sync.Once
	// frontendCloseErr, beginFrontendShutdown TARAFINDAN, shutdownCause
	// CAS'i shutdownCauseFrontendClosed'i BASARIYLA kaydettiginde (yani
	// frontend kapanmasi GERCEKTEN birincil neden olduğunda) yazilir;
	// Run bunu primaryErr olarak kullanir. Gozetmen goroutine'i icinde,
	// ackGate altinda yazilir; Run tarafindan yalnizca wg.Wait() sonrasi
	// (gozetmen KESIN olarak bitmisken) okunur - ek senkronizasyona
	// gerek yoktur.
	frontendCloseErr error
	// finalErr, Run'in dondurdugu KESIN birincil hatanin (varsa nil)
	// bir kopyasidir - close(stopped)'DAN HEMEN ONCE tam olarak bir kez
	// yazilir. NotifyFrontendClosed (ve gelecekte benzer "runtime'in
	// KESIN sonucunu bilmek isteyen" cagiranlar), <-stopped'i
	// gozlemledikten SONRA bu alani okur - Go bellek modelinin
	// close(kanal) -> alma happens-before garantisi, ek kilitlemeye
	// gerek kalmadan guvenli okumayi saglar.
	finalErr error

	// onFrontendEventEnqueued/onFrontendEventAccepted/onLoopReturned/
	// onBeforeAckLinearization/onWatcherShutdownBegun, YALNIZCA PAKET
	// TESTLERI tarafindan ayarlanan isteğe bagli kancalardir (hooks).
	// Uretimde HER ZAMAN nil'dir ve hicbir etkisi yoktur - yalnizca
	// zamanlamaya (sleep) basvurmadan deterministik nedensellik/
	// dogrusallastirma testleri yazabilmek icindir:
	//   - onFrontendEventEnqueued, submit() icinde bir olay kanala
	//     basari ile YERLESTIRILDIGI aninda (cagiran goroutine'de, ack
	//     beklemeden ONCE) cagrilir.
	//   - onFrontendEventAccepted, event-loop bir olayi kanaldan
	//     ALDIGI aninda (islemeye baslamadan ONCE) cagrilir.
	//   - onLoopReturned, r.loop() Run icinde DONDUKTEN HEMEN SONRA,
	//     kapanma temizligine (cancelRun/wg.Wait) devam etmeden ONCE
	//     cagrilir - ic nedensellik (gorev 1) testleri icindir.
	//   - onBeforeAckLinearization, sendFrontendSuccess ackGate'i
	//     kilitlemeden HEMEN ONCE cagrilir - basarili-ack
	//     dogrusallastirma (gorev 2) testleri icindir.
	//   - onWatcherShutdownBegun, beginWatcherShutdown YA DA
	//     beginFrontendShutdown ackGate'i BIRAKTIKTAN hemen sonra
	//     cagrilir - testlerin gozetmenin gecisini (parent ctx iptali
	//     YA DA frontend kapanma istegi tetiklemis olsun) GERCEKTEN
	//     tamamladigini uykuya basvurmadan bilebilmesi icindir.
	// Bu alanlarin yalnizca Run baslamadan ONCE ayarlanmasi (ya da -
	// mevcut kod tabaninda oldugu gibi - kendi olayinin kanal gonderimi
	// ONCESINDE, ayni cagiran goroutine icinde AYARLANMASI) gerekir; bu,
	// Go bellek modelinin kanal/goroutine-olusturma happens-before
	// garantileriyle veri yarisini onler.
	onFrontendEventEnqueued  func()
	onFrontendEventAccepted  func()
	onLoopReturned           func()
	onBeforeAckLinearization func()
	onWatcherShutdownBegun   func()

	// --- Extended maskeleme (opt-in, bkz. NewExtendedRuntimeWithMasking) --
	//
	// masker/maskTracker/maskHooks, YALNIZCA event-loop goroutine'i
	// tarafindan okunur/cagirilir - hicbir baska goroutine erismez ve
	// hicbir public accessor bunlari disariya sizdirmaz. maskTracker nil
	// ise (varsayilan - bkz. NewExtendedRuntime) maskeleme TAMAMEN devre
	// disidir ve asagidaki tum masking-farkindaligi kod yollari no-op'tur;
	// bu, onceki (maskeleme-oncesi) davranisla BIREBIR aynidir.
	masker      masking.Masker
	maskTracker *masking.ExtendedTracker
	maskHooks   masking.Hooks

	// runCtx, Run() icinde TAM OLARAK BIR KEZ, loop() cagrilmadan HEMEN
	// ONCE, AYNI (Run'in kendi) goroutine'i icinde yazilir - loop() da
	// DOGRUDAN (ayri bir goroutine olmadan) AYNI goroutine icinde
	// cagrildigindan (bkz. Run doc yorumu), yazan ve okuyan HER ZAMAN AYNI
	// goroutine'dir; ek senkronizasyona gerek yoktur. Yalnizca Masker
	// cagrilarina (bkz. masking.MaskDataRow) baglanti/kapatma iptalini
	// (parent ctx iptali VE frontend kapanmasi/runtime sonlandirmasi
	// DAHIL, ikisi de runCtx'i iptal eder) tasimak icin kullanilir.
	runCtx context.Context
}

// NewExtendedRuntime, verilen State uzerinde calisan yeni bir
// ExtendedRuntime olusturur. state/backend/client nil olamaz;
// runtimeLimits'in tum alanlari pozitif olmalidir; sequencerLimits,
// protocol.NewResponseSequencer'in kendi dogrulama kurallarina tabidir.
//
// state, yalnizca bagimlilik enjeksiyonu (dependency injection) icin
// disaridan kabul edilir - cagiran Run baslatmadan ONCE state uzerinde
// baska hicbir sey yapmamalidir (ör. onceden Create* cagirmak). Run
// baslatildigi andan itibaren state'in SAHIBI munhasiran bu
// ExtendedRuntime'dir; cagiran bir daha ASLA state'e dogrudan
// erismemelidir.
func NewExtendedRuntime(
	state *protocol.State,
	backend BackendTransport,
	client io.WriteCloser,
	sequencerLimits protocol.SequencerLimits,
	runtimeLimits RuntimeLimits,
) (*ExtendedRuntime, error) {
	if state == nil {
		return nil, ErrNilState
	}
	if backend == nil {
		return nil, ErrNilBackend
	}
	if client == nil {
		return nil, ErrNilClient
	}
	if err := runtimeLimits.validate(); err != nil {
		return nil, err
	}
	seq, err := protocol.NewResponseSequencer(state, sequencerLimits)
	if err != nil {
		return nil, err
	}
	return &ExtendedRuntime{
		state:              state,
		seq:                seq,
		backend:            backend,
		client:             client,
		limits:             runtimeLimits,
		frontendEvents:     make(chan frontendEvent, runtimeLimits.FrontendEventBuffer),
		backendEvents:      make(chan backendEvent, runtimeLimits.BackendEventBuffer),
		frontendShutdownCh: make(chan frontendShutdownRequest, 1),
		started:            make(chan struct{}),
		stopped:            make(chan struct{}),
	}, nil
}

// NewExtendedRuntimeWithMasking, NewExtendedRuntime ile TAMAMEN AYNI
// kurulumu yapar, ANCAK ek olarak opt-in Extended Query yanit
// maskelemesini (bkz. internal/masking.ExtendedTracker) etkinlestirir.
//
// maskingConfig.Enabled false ise masker HIC KULLANILMAZ/SAKLANMAZ (nil
// olabilir - "masking disabled may use nil Masker safely") ve donen
// ExtendedRuntime, NewExtendedRuntime ile OLUSTURULMUS biriyle DAVRANISSAL
// olarak BIREBIR aynidir (maskTracker nil kalir, hicbir masking-farkindaligi
// kod yolu tetiklenmez). maskingConfig.Enabled true ise masker NIL OLAMAZ
// (ErrNilMasker).
//
// cmd/gateway/main.go'nun runExtendedConnection'i, maskCfg.Enabled true
// oldugunda TAM OLARAK bu constructor'i cagirir (aksi halde duz
// NewExtendedRuntime kullanilir) - bkz. paket basi doc yorumu.
func NewExtendedRuntimeWithMasking(
	state *protocol.State,
	backend BackendTransport,
	client io.WriteCloser,
	sequencerLimits protocol.SequencerLimits,
	runtimeLimits RuntimeLimits,
	maskingConfig masking.Config,
	masker masking.Masker,
	maskingLimits masking.ExtendedLimits,
	maskingHooks masking.Hooks,
) (*ExtendedRuntime, error) {
	if maskingConfig.Enabled && masker == nil {
		return nil, ErrNilMasker
	}
	r, err := NewExtendedRuntime(state, backend, client, sequencerLimits, runtimeLimits)
	if err != nil {
		return nil, err
	}
	if !maskingConfig.Enabled {
		return r, nil
	}
	tracker, err := masking.NewExtendedTracker(maskingConfig, maskingLimits)
	if err != nil {
		return nil, err
	}
	r.masker = masker
	r.maskTracker = tracker
	r.maskHooks = maskingHooks
	return r, nil
}

// shutdownCause, hangi tetikleyicinin baglanti kapatmayi/sonlandirmayi
// BASLATTIGINI (birincil neden olarak) kayit altina alir - bkz. gorev 2
// "Preserve deterministic primary-error causality". Tek seferlik bir
// atomic.CompareAndSwap ile yazilir: hangi taraf ONCE yazarsa o kalici
// olarak gecerli olur.
type shutdownCause int32

const (
	shutdownCauseNone shutdownCause = iota
	// shutdownCauseParentCtx, Run'a verilen UST (parent) ctx'in iptal/
	// deadline nedeniyle sona erdigini ve bunun baglanti kapatmayi
	// (dolayisiyla olay dongusunun olasi bir bloklu client.Write/backend
	// Read cagrisinin kesilmesini) BASLATTIGINI belirtir. Bu isaretliyse,
	// Run'in birincil hatasi loop()'un kendi donus degerinden BAGIMSIZ
	// olarak parent ctx.Err() olur - cunku loop()'un donus degeri o
	// noktada yalnizca bu ZORLA kapatmanin bir SEMPTOMU olabilir (ör.
	// ErrClientWriteFailed, Write yalnizca BU YUZDEN basarisiz oldugu
	// icin).
	shutdownCauseParentCtx
	// shutdownCauseInternal, olay dongusunun KENDI ic nedeniyle
	// (sequencer sonlandirma eylemi, backend protokol hatasi, gercek bir
	// istemci yazma hatasi, vb.) durdugunu ve bunun baglanti kapatmayi
	// BASLATTIGINI belirtir - bu durumda loop()'un kendi donus degeri
	// birincil hata olarak KORUNUR.
	shutdownCauseInternal
	// shutdownCauseFrontendClosed, frontend ureticisinin (bkz.
	// NotifyFrontendClosed, gorev 5) client-okuma dongusunun sona
	// erdigini (temiz EOF, okuma hatasi ya da kurtarilamaz bir
	// cerceveleme hatasi) BASLATTIGINI belirtir. Bu istek event loop'tan
	// TAMAMEN BAGIMSIZ, kapanma gozetmeni araciligiyla islenir (bkz.
	// beginFrontendShutdown) - boylece event loop backend.Write/
	// client.Write icinde bloklu olsa BILE bu neden kaydedilebilir. Bu
	// isaretliyse, Run'in birincil hatasi r.frontendCloseErr'dur -
	// loop()'un kendi donus degeri (varsa) yalnizca bu ZORLA kapatmanin
	// bir SEMPTOMU olabilir (ör. baglantilar kapatildigi icin basarisiz
	// olan bir ErrBackendWriteFailed/ErrClientWriteFailed).
	shutdownCauseFrontendClosed
)

// markInternalShutdown, kapanmayi BASLATAN nedenin event-loop'un KENDI ic
// nedeni (sequencer sonlandirma istegi, backend protokol/okuma hatasi,
// gercek bir istemci yazma hatasi, bekleyen is yokken temiz EOF, vb.)
// oldugunu kayit altina alir. Yalnizca event-loop goroutine'i (r.loop)
// icinden, ilgili terminal donus noktasinin TAM OLARAK aninda - Run'a
// kontrolu geri vermeden ONCE - cagrilir (bkz. gorev 1). Tek seferlik bir
// CompareAndSwap oldugundan, daha once baska bir neden (ozellikle
// shutdownCauseParentCtx) zaten kaydedilmisse bu cagri sessizce no-op'tur;
// boylece GERCEKTEN daha once gerceklesen ic hata, SONRA gelen bir parent
// ctx iptalinin CAS'i tarafindan asla ustune yazilamaz. Donen bool, BU
// cagrinin CAS'i KAZANIP KAZANMADIGINI bildirir - emitMaskingFailureFatal
// (bkz. gorev 5) bunu, olasi bloklu bir FATAL yazimindan ONCE nedenselligi
// dogrusallastirmak icin kullanir.
func (r *ExtendedRuntime) markInternalShutdown() bool {
	return r.shutdownCause.CompareAndSwap(int32(shutdownCauseNone), int32(shutdownCauseInternal))
}

// markParentShutdown, kapanmayi BASLATAN nedenin ust (parent) ctx'in
// iptal/deadline'i oldugunu kayit altina alir. Hem event-loop'un kendi
// ctx.Done() dalindan (bkz. loop) hem kapanma gozetmeninden (bkz.
// beginWatcherShutdown) cagrilabilir - hangisi ONCE kosarsa CAS'i o
// kazanir, digeri no-op olur; ikisi de AYNI nedeni kaydettigi icin sonuc
// farketmez.
func (r *ExtendedRuntime) markParentShutdown() {
	r.shutdownCause.CompareAndSwap(int32(shutdownCauseNone), int32(shutdownCauseParentCtx))
}

// beginWatcherShutdown, kapanma gozetmeninin basarili-ack kabulune karsi
// TEK dogrusallastirma (linearization) noktasidir (bkz. gorev 2). ackGate
// altinda, ATOMIK olarak (a) parent nedenini (varsa) kayit altina alir VE
// (b) event-loop'un bir daha ASLA basarili bir ack gonderemeyecegi
// sekilde ackGateClosed'i true yapar. Bu ikisinin AYNI kilit altinda
// yapilmasi ZORUNLUDUR: aksi halde event-loop, parent nedeni HENUZ
// kaydedilmeden ama ackGateClosed HENUZ true olmadan once basarili bir
// ack gonderebilirdi - onlenmek istenen tam olarak bu yaris durumudur.
// Baglanti kapatma cagrilarindan ONCE (r.closeOnce.Do) cagrilir; State/
// ResponseSequencer'a ASLA dokunmaz, istemciye bayt yazmaz.
func (r *ExtendedRuntime) beginWatcherShutdown(parentCanceled bool) {
	r.ackGate.Lock()
	if parentCanceled {
		r.markParentShutdown()
	}
	r.ackGateClosed = true
	r.ackGate.Unlock()
	if r.onWatcherShutdownBegun != nil {
		r.onWatcherShutdownBegun()
	}
}

// frontendShutdownRequest, NotifyFrontendClosed'in kapanma gozetmenine
// gonderdigi TEK, degismez istektir (bkz. gorev 5).
type frontendShutdownRequest struct {
	reason FrontendCloseReason
	cause  error
}

// frontendCloseFixedError, bir FrontendCloseReason'i (ve varsa guvenli bir
// alt nedeni) Run'in birincil hatasi olarak kullanilacak sabit, guvenli bir
// hataya cevirir. cause yalnizca reponun ANLAMLI oldugu durumlarda
// (FrontendClosedEOF haric) sarilir - ve YALNIZCA zaten belgelenmis
// guvenli-sarma kuralina tabi, baglanti/aktarim duzeyinde bir hata
// olmasi beklenir (bkz. gorev 6 - cagiran, ExtendedFrontend, artik
// kendi decoder/parser hatalarini buraya asla cig sekilde iletmez;
// yalnizca kendi sabit kategorilerini gonderir).
func frontendCloseFixedError(reason FrontendCloseReason, cause error) error {
	switch reason {
	case FrontendClosedReadError:
		if cause != nil {
			return fmt.Errorf("%w: %w", ErrFrontendReadFailed, cause)
		}
		return ErrFrontendReadFailed
	case FrontendClosedProtocolError:
		if cause != nil {
			return fmt.Errorf("%w: %w", ErrFrontendProtocolFailure, cause)
		}
		return ErrFrontendProtocolFailure
	default: // FrontendClosedEOF ve taninmayan degerler
		return ErrFrontendClosed
	}
}

// beginFrontendShutdown, kapanma gozetmeninin frontend-kapanma-istegi
// TETIKLEYICISI icin dogrusallastirma noktasidir (bkz. gorev 5) -
// beginWatcherShutdown'in parent-ctx tetikleyicisiyle TAM SIMETRIK bir
// eslenigidir, AYNI ackGate kritik bolgesini kullanir. shutdownCause CAS'i
// BASARILI olursa (yani frontend kapanmasi GERCEKTEN once dogrusallastiysa)
// r.frontendCloseErr'i de kaydeder - boylece Run bu degeri primaryErr
// olarak kullanabilir. CAS BASARISIZ olursa (baska bir neden zaten
// kaydedilmisse) frontendCloseErr KASITLI OLARAK yazilmaz - bu, "ONCE
// dogrusallasan neden kazanir" ilkesini korur (bkz. gorev 5, "Deterministic
// error precedence"). State/ResponseSequencer'a ASLA dokunmaz, istemciye
// bayt yazmaz.
func (r *ExtendedRuntime) beginFrontendShutdown(req frontendShutdownRequest) {
	r.ackGate.Lock()
	if r.shutdownCause.CompareAndSwap(int32(shutdownCauseNone), int32(shutdownCauseFrontendClosed)) {
		r.frontendCloseErr = frontendCloseFixedError(req.reason, req.cause)
	}
	r.ackGateClosed = true
	r.ackGate.Unlock()
	if r.onWatcherShutdownBegun != nil {
		r.onWatcherShutdownBegun()
	}
}

// sendFrontendSuccess, bir frontend olayinin (RegisterFrontendOperation ya
// da SubmitSyntheticError) BASARILI sonucunu ev.ack'e gondermenin TEK
// gecis noktasidir (bkz. gorev 2). ackGate altinda: kapanma HENUZ
// baslamadiysa basari kabul edilip gonderilir - bu, basarinin sonraki
// herhangi bir iptalden ONCE dogrusallastigi anlamina gelir. Kapanma
// ZATEN basladiysa (ackGateClosed==true), basari YERINE sabit bir
// ErrRuntimeStopped gonderilir/dondurulur - cagiran hicbir zaman
// "iletim guvenli" sinyalini kapanma BASLADIKTAN SONRA almaz. ev.ack
// kapasite-1 tamponlu bir kanal oldugundan (yalnizca event-loop
// gonderir, cagiran yalnizca alir) gonderim asla bloklamaz - bu yuzden
// kilit tutulurken gonderim yapmak guvenlidir ve gozetmenin ackGate'i
// almasini asla geciktirmez.
func (r *ExtendedRuntime) sendFrontendSuccess(ack chan<- frontendAck, success frontendAck) error {
	if r.onBeforeAckLinearization != nil {
		r.onBeforeAckLinearization()
	}
	r.ackGate.Lock()
	if r.ackGateClosed {
		r.ackGate.Unlock()
		ack <- frontendAck{err: ErrRuntimeStopped}
		return ErrRuntimeStopped
	}
	ack <- success
	r.ackGate.Unlock()
	return nil
}

// Run, olay dongusunu baslatir ve ictegi cagirir (blocking). TAM OLARAK
// BIR KEZ cagrilabilir - ikinci bir cagri aninda ErrAlreadyRunning
// dondurur. Run donduğunde: backend-okuyucu ve kapanma gozetmeni
// (shutdown watcher) goroutine'leri katilmis (joined), her iki baglanti
// (backend, client) kapatilmis ve runtime kalici olarak "stopped"
// durumundadir.
//
// Baglanti kapatma, bloklu bir net.Conn Read/Write cagrisini gercekten
// KESEBILEN TEK mekanizmadir - context iptali TEK BASINA keyfi bir
// io.Reader/io.Writer cagrisini kesemez. Ancak TEK event-loop
// goroutine'i (r.loop), sequencer'in urettigi bir OutputAction'i
// islerken client.Write icinde bloklanmis olabilir - bu durumda hicbir
// context'i GOZLEMLEYEMEZ ve Run'in "loop donene kadar bekle, SONRA
// baglantilari kapat" seklinde sirali bir tasarimi, kilitlenmeye
// (deadlock) yol acardi: Run, baglantilari kapatan koda ASLA ulasamazdi.
//
// Bu yuzden Run, loop()'u cagirmadan ONCE, loop() ile ESZAMANLI calisan
// AYRI bir "kapanma gozetmeni" (shutdown watcher) goroutine'i baslatir.
// Bu gozetmen, runCtx (parent ctx'in cocugu) sona erdigi ANDA - loop()
// bloklu olsa BILE - her iki baglantiyi da kapatir; boylece bloklu
// Write/Read cagrisi HER ZAMAN kesilebilir. Gozetmen KESINLIKLE istemciye
// bayt yazmaz ve State/ResponseSequencer'a DOKUNMAZ - yalnizca baglanti
// kapatma eylemini gerceklestirir.
func (r *ExtendedRuntime) Run(ctx context.Context) error {
	if !r.lifecycle.CompareAndSwap(int32(lifecycleCreated), int32(lifecycleRunning)) {
		return ErrAlreadyRunning
	}
	close(r.started)

	runCtx, cancelRun := context.WithCancel(ctx)
	// bkz. runCtx alaninin doc yorumu: bu, Run'in kendi goroutine'i
	// icinde, loop() cagrilmadan (AYNI goroutine icinde, dogrudan)
	// ONCE yazilir - baska hicbir goroutine erismeden once.
	r.runCtx = runCtx

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		r.runBackendReader(runCtx)
	}()

	// Kapanma gozetmeni: runCtx sona erdiginde (parent ctx iptali/
	// deadline'i YA DA Run'in kendisinin asagida cagiracagi cancelRun()
	// nedeniyle) YA DA bagimsiz bir frontend-kapanma istegi (bkz.
	// NotifyFrontendClosed, gorev 5) geldiginde HER IKI baglantiyi da
	// kapatir. Bu TEK SEFERLIK select, ikisinden HANGISI ONCE hazir
	// olursa o dali isler:
	//
	//   - runCtx.Done(): parent ctx'in GERCEKTEN sona erip ermedigini
	//     (yalnizca Run'in kendi ic cancelRun() cagrisindan degil) ayirt
	//     etmek icin runCtx.Err() DEGIL, DOGRUDAN ctx.Err() kontrol
	//     edilir - boylece "kim once bitirdi" sorusu hatasiz cevaplanir
	//     (bkz. shutdownCause). beginWatcherShutdown, parent nedeni
	//     kaydetmeyi VE basarili-ack kabulunu kapatmayi TEK bir ackGate
	//     kritik bolgesinde atomik yapar (bkz. gorev 2).
	//   - frontendShutdownCh: event loop backend.Write/client.Write
	//     icinde bloklu OLSA BILE isleyebilecek, TAMAMEN bagimsiz bir
	//     kapanma tetikleyicisidir (bkz. gorev 5). beginFrontendShutdown
	//     AYNI ackGate dogrusallastirmasini kullanir VE runCtx'i de
	//     KENDISI iptal eder (cancelRun()) - boylece backend-okuyucu
	//     goroutine'i ve (varsa) event-loop'un kendi ctx.Done() dali da
	//     GECIKMEDEN serbest kalir; Run'in kendi post-loop cancelRun()
	//     cagrisini beklemek, event loop TAM DA bu yuzden bloklu kalmis
	//     olabilecegi icin bir kilitlenmeye (deadlock) yol acardi.
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-runCtx.Done():
			r.beginWatcherShutdown(ctx.Err() != nil)
		case req := <-r.frontendShutdownCh:
			r.beginFrontendShutdown(req)
			cancelRun()
		}
		r.closeOnce.Do(func() {
			_ = r.backend.Close()
			_ = r.client.Close()
		})
	}()

	// r.loop DOGRUDAN (ayri bir goroutine olmadan) cagrilir - Run'in
	// kendi goroutine'i buna bloklu kalsa bile, YUKARIDAKI bagimsiz
	// gozetmen goroutine'i baglantilari kapatmaya devam edebilir (runCtx
	// zaten baslamis, kendi ayri goroutine'inde calisiyor). loop() bloklu
	// bir Write'tan ancak gozetmen baglantiyi kapattiktan SONRA doner.
	loopErr := r.loop(runCtx)

	if r.onLoopReturned != nil {
		r.onLoopReturned()
	}

	// loop()'un KENDISI, her terminal donus noktasinda (bkz.
	// markInternalShutdown/markParentShutdown cagrilari icinde loop())
	// ilgili nedeni ARTIK ONCEDEN kaydetmis olmalidir - bu yuzden
	// asagidaki CAS, olagan calismada shutdownCause'u DEGISTIRMEZ
	// (ULASILAMAZ/unreachable); yalnizca, teorik olarak loop()'un
	// KENDI icinde nedenini kaydetmeden dondugu beklenmedik bir yol
	// olursa diye birakilan bir savunma (defensive) yedegidir - gercek
	// nedensellik belirlenimi ARTIK bu satira degil, loop()'un ic
	// isaretlemesine dayanir (bkz. gorev 1).
	r.markInternalShutdown()

	r.lifecycle.Store(int32(lifecycleStopping))
	cancelRun() // gozetmenin de kesin olarak calisip baglantilari kapatmasini/cikmasini saglar (parent ctx HENUZ iptal edilmediyse)

	wg.Wait() // backend-okuyucu VE kapanma gozetmeni Run donmeden once katilmis olmalidir

	primaryErr := loopErr
	switch shutdownCause(r.shutdownCause.Load()) {
	case shutdownCauseParentCtx:
		// Parent ctx'in sona ermesi kapanmayi BASLATTI - loop()'un donus
		// degeri (varsa) yalnizca bu ZORLA kapatmanin bir semptomu
		// olabilir (ör. bloklu bir Write'in kesilmesinden kaynaklanan
		// ErrClientWriteFailed) - bu yuzden gercek nedeni (context.Canceled
		// ya da context.DeadlineExceeded) rapor ederiz.
		primaryErr = ctx.Err()
	case shutdownCauseFrontendClosed:
		// Frontend kapanmasi kapanmayi BASLATTI - loop()'un donus degeri
		// (varsa) yalnizca baglantilarin bu yuzden kapatilmasinin bir
		// semptomu olabilir (ör. ErrBackendWriteFailed/ErrClientWriteFailed) -
		// bu yuzden gercek nedeni (bkz. beginFrontendShutdown'in kaydettigi
		// sabit, guvenli hata) rapor ederiz.
		primaryErr = r.frontendCloseErr
	}

	// finalErr, close(stopped)'DAN ONCE yazilir - NotifyFrontendClosed
	// (ve <-stopped'i gozlemleyen benzer cagiranlar) Go bellek modelinin
	// close(kanal) -> alma happens-before garantisiyle bunu guvenle
	// okuyabilir (bkz. gorev 5).
	r.finalErr = primaryErr

	r.lifecycle.Store(int32(lifecycleStopped))
	close(r.stopped)

	return primaryErr
}

// WaitStarted, Run BASARIYLA baslayip olay dongusunu kabul etmeye hazir
// hale gelene (r.started kapanana) kadar bloklanir - cagiranin (bkz.
// cmd/gateway'in opt-in Extended Query yolu) Gate.RunExtended'i
// baslatmadan ONCE runtime'in frontend olaylarini gercekten kabul
// edebilecegini POLLING/SLEEP olmadan, deterministik bir sekilde
// bilmesini saglar (bkz. gorev 12).
//
// Mevcut started/stopped kanallarindan baska hicbir State/mutable runtime
// ic durumu ACIGA CIKARILMAZ. Runtime, kullanilabilir hale gelmeden ONCE
// dururssa (ör. Run hic cagrilmadan baska bir olay stopped'i tetikleseydi -
// pratikte erisilemez, ama savunma amacli) ya da ctx iptal edilirse
// deterministik olarak doner; hicbir durumda sonsuza kadar bloklanmaz.
func (r *ExtendedRuntime) WaitStarted(ctx context.Context) error {
	// stopped ONCELIKLI kontrol edilir: started/stopped ikisi de kapanmis
	// olabilecegi (runtime baslayip cok hizli durmus olabilecegi) bir
	// select'te Go'nun rastgele dal secimine birakmak yerine, "zaten
	// durdu" durumunu HER ZAMAN acikca rapor ederiz.
	select {
	case <-r.stopped:
		return ErrRuntimeStopped
	default:
	}
	select {
	case <-r.started:
		return nil
	case <-r.stopped:
		return ErrRuntimeStopped
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RegisterFrontendOperation, req'te tanimlanan Extended Query islemini
// - State.Create* cagrisi DAHIL - munhasiran event-loop goroutine'i
// icinde olusturur, ardindan AYNI event-loop turunda
// ResponseSequencer'in response-plan'ina kaydeder. Yalnizca Run aktifken
// gecerlidir; Run'dan once cagrilirsa ANINDA ErrNotRunning, runtime
// durduktan/durma surecindeyken cagrilirsa ErrRuntimeStopped doner -
// hicbir durumda sonsuza kadar bloklanmaz.
//
// Basari yalnizca su ADIMLARIN TUMU tamamlandiktan sonra bildirilir: (1)
// event loop istegi kabul etti, (2) State.Create* islemi olusturdu, (3)
// ResponseSequencer islemi kabul etti, (4) o kabulun ANINDA urettigi tum
// OutputAction'lar tam olarak islendi (istemciye yazildi). Gelecekteki
// bir frontend cagiran, ancak bu basari donduktan SONRA orijinal
// frontend baytlarini upstream'e yazmalidir (kayit-once-iletim
// sozlesmesi).
//
// Iki FARKLI reddetme/hata kategorisi vardir:
//
//   - State.Create* KENDISI basarisiz olursa (ör. bilinmeyen statement,
//     kimlik tukenmesi): bu, State'in kendi "reddet-once-mutasyona-
//     ugrat" sozlesmesi geregi HICBIR mutasyon uygulanmadigi anlamina
//     gelir - runtime saglikli kalir, hata oldugu gibi cagirana
//     dondurulur.
//   - State.Create* BASARILI olur ama sonraki
//     ResponseSequencer.AddForwardedOperation BASARISIZ olursa: State
//     zaten mutasyona ugramistir ama sequencer plani bunu yansitmiyor -
//     bu bir UYUSMAZLIKTIR (bkz. ErrFrontendRegistrationDiverged) ve
//     runtime KALICI olarak sonlanir; State/sequencer bir daha asla
//     kullanilmaz, hicbir spekulatif geri alma denenmez.
//
// Cagiran, ikinci kategoride "guvenle yeniden deneyebilecegini ya da
// cerceveyi iletebilecegini" ASLA varsaymamalidir.
func (r *ExtendedRuntime) RegisterFrontendOperation(ctx context.Context, req FrontendOperationRequest) (FrontendRegistration, error) {
	ack := make(chan frontendAck, 1)
	result, err := r.submit(ctx, frontendEvent{kind: frontendEventRegister, req: req.copy(), ack: ack})
	return result.reg, err
}

// SubmitSyntheticError, backend'e hic iletilmemis bir ErrorResponse
// cercevesini belirtilen cycle icin sequencer'a sunar. frame, cagirandan
// BAGIMSIZ bir kopya olarak saklanir (cagiran, gonderdikten sonra kendi
// slice'ini guvenle mutasyona ugratabilir). Dondurme/hata semantikleri
// RegisterFrontendOperation ile birebir aynidir.
func (r *ExtendedRuntime) SubmitSyntheticError(ctx context.Context, cycle protocol.CycleID, frame []byte) error {
	ack := make(chan frontendAck, 1)
	copied := append([]byte(nil), frame...)
	_, err := r.submit(ctx, frontendEvent{kind: frontendEventSynthetic, cycle: cycle, frame: copied, ack: ack})
	return err
}

// RegisterAndForwardFrontendOperation, req'te tanimlanan Extended Query
// islemini - State.Create* + ResponseSequencer kaydi + orijinal frontend
// cercevesinin upstream'e (backend'e) YAZILMASI DAHIL - munhasiran
// event-loop goroutine'i icinde, TEK bir olay turunda gerceklestirir (bkz.
// gorev 3). frame, cagirandan BAGIMSIZ bir kopya olarak saklanir ve
// tam olarak istenen req.Kind'a karsilik gelen, tek, tam bir normal-
// protokol frontend cercevesi olmalidir (bkz. gorev 4) - aksi halde
// ErrInvalidFrontendFrame ile, hicbir mutasyon denenmeden reddedilir.
//
// Kayit-once-iletim degismezi MUTLAKTIR ve event-loop icinde bu SIRAYLA
// uygulanir: (1) cerceve dogrulanir, (2) State.Create* cagirilir, (3)
// ResponseSequencer'a kaydedilir, (4) ANCAK BUNDAN SONRA orijinal cerceve
// backend'e yazilir, (5) basari YALNIZCA tam yazim tamamlandiktan sonra
// bildirilir. Boylece cagiran (ör. internal/firewall.ExtendedFrontend)
// basari aldiginda, gercek sunucunun ilgili islemi ZATEN aldigini bilir -
// kismi bir upstream yazma hatasi runtime'i "gercek sunucunun gormedigi
// canli bir islem" durumunda birakamaz (bkz. ErrBackendWriteFailed: boyle
// bir hata HER ZAMAN runtime'i kalici olarak fail-closed sonlandirir,
// hicbir State geri almasi denenmez).
//
// Uc FARKLI reddetme/hata kategorisi vardir:
//
//   - Cerceve dogrulamasi BASARISIZ olursa (ErrInvalidFrontendFrame/
//     ErrFrontendFrameTooLarge) ya da State.Create* KENDISI basarisiz
//     olursa: hicbir mutasyon uygulanmadi - runtime saglikli kalir, hata
//     oldugu gibi cagirana dondurulur, hicbir upstream yazma denenmez.
//   - State.Create* BASARILI olur ama ResponseSequencer.AddForwardedOperation
//     BASARISIZ olursa: ErrFrontendRegistrationDiverged (mevcut davranis,
//     bkz. RegisterFrontendOperation) - runtime KALICI olarak sonlanir,
//     hicbir upstream yazma denenmez.
//   - State/sequencer kaydi BASARILI olur ama upstream yazma BASARISIZ
//     olursa: ErrBackendWriteFailed - runtime KALICI olarak fail-closed
//     sonlanir; cagirana ASLA "iletim guvenli/basarili" sinyali verilmez.
//
// Basari ayrica gorev 2'nin ackGate dogrusallastirmasina tabidir (bkz.
// sendFrontendSuccess): parent-runtime kapanmasi basari ack'inden ONCE
// dogrusallasirsa, cagiran basari YERINE sabit ErrRuntimeStopped alir.
func (r *ExtendedRuntime) RegisterAndForwardFrontendOperation(ctx context.Context, req FrontendOperationRequest, frame []byte) (FrontendRegistration, error) {
	ack := make(chan frontendAck, 1)
	copiedFrame := append([]byte(nil), frame...)
	result, err := r.submit(ctx, frontendEvent{kind: frontendEventRegisterAndForward, req: req.copy(), frame: copiedFrame, ack: ack})
	return result.reg, err
}

// SubmitSyntheticErrorForCurrentCycle, backend'e hic iletilmemis bir
// ErrorResponse cercevesini, event-loop'un KENDISININ State'ten okudugu
// GUNCEL (mevcut) cycle icin sequencer'a sunar (bkz. gorev 5). Cagiran
// (ör. internal/firewall.ExtendedFrontend) State'e hicbir zaman dogrudan
// erisemedigi ve dolayisiyla dogru CycleID'yi TAHMIN EDEMEYECEGI icin bu,
// frontend koprusunun yerel ret senaryolarinda kullanmasi gereken TEK
// sentetik-hata giris noktasidir - dusuk seviyeli SubmitSyntheticError
// (acik cycle parametreli) yalnizca mevcut testler/ic cagiranlar icin
// korunur.
//
// Basari yalnizca sentetik birim ResponseSequencer tarafindan KABUL
// EDILDIKTEN (ve varsa ani cikti eylemleri tam islendikten) SONRA
// bildirilir; bu durumda kullanilan GERCEK CycleID (sanitize edilmis,
// sayisal) dondurulur - cagiran bunu, kendi discard-until-Sync durumunun
// "engellenmis cycle" degeri olarak saklamalidir.
func (r *ExtendedRuntime) SubmitSyntheticErrorForCurrentCycle(ctx context.Context, frame []byte) (protocol.CycleID, error) {
	ack := make(chan frontendAck, 1)
	copied := append([]byte(nil), frame...)
	result, err := r.submit(ctx, frontendEvent{kind: frontendEventSyntheticCurrentCycle, frame: copied, ack: ack})
	return result.cycle, err
}

// ForwardFlush, tam ve gecerli bir Flush ('H') cercevesini upstream'e
// (backend'e) TAM OLARAK BIR KEZ yazar (bkz. gorev 6). Flush'in gercek
// protokolde karsilik gelen bir backend onayi yoktur - bu yuzden hicbir
// State islemi olusturulmaz, hicbir ResponseSequencer plan birimi
// eklenmez. Basari yalnizca tam yazim tamamlandiktan sonra bildirilir
// (ackGate dogrusallastirmasina tabidir, bkz. sendFrontendSuccess).
// Gecersiz/uyumsuz bir cerceve hicbir mutasyon/yazma denenmeden
// ErrInvalidFrontendFrame ile reddedilir; upstream yazma basarisiz
// olursa runtime KALICI olarak fail-closed sonlanir (ErrBackendWriteFailed).
func (r *ExtendedRuntime) ForwardFlush(ctx context.Context, frame []byte) error {
	ack := make(chan frontendAck, 1)
	copied := append([]byte(nil), frame...)
	_, err := r.submit(ctx, frontendEvent{kind: frontendEventFlush, frame: copied, ack: ack})
	return err
}

// ForwardTerminate, tam ve gecerli bir Terminate ('X') cercevesini
// upstream'e (backend'e) TAM OLARAK BIR KEZ yazar (bkz. gorev 6). Flush
// gibi hicbir State islemi/sequencer plan birimi olusturmaz. Yazim
// BASARILI olursa cagirana nil (iletim onaylandi) dondurulur - ANCAK
// runtime bu noktadan itibaren KALICI olarak sonlanma surecine girer: hicbir
// ReadyForQuery beklenmez, hicbir sonraki is kabul edilmez, her iki
// baglanti da kapatilir (bkz. Run'in ErrFrontendTerminateRequested
// birincil hatasi - bu, ForwardTerminate'in cagirana dondurdugu basarili
// sonuctan BAGIMSIZDIR). Gecersiz bir cerceve hicbir mutasyon/yazma
// denenmeden reddedilir; upstream yazma basarisiz olursa runtime KALICI
// olarak fail-closed sonlanir.
func (r *ExtendedRuntime) ForwardTerminate(ctx context.Context, frame []byte) error {
	ack := make(chan frontendAck, 1)
	copied := append([]byte(nil), frame...)
	_, err := r.submit(ctx, frontendEvent{kind: frontendEventTerminate, frame: copied, ack: ack})
	return err
}

// NotifyFrontendClosed, frontend ureticisinin (ör.
// internal/firewall.ExtendedFrontend/Gate.RunExtended) kendi client-okuma
// dongusunun SONA ERDIGINI - ve dolayisiyla runtime'in ARTIK hicbir yeni
// frontend olayi beklememesi gerektigini - bildirir (bkz. gorev 7, gorev 5).
// reason, sona erme nedenini (temiz EOF/okuma hatasi/decoder-cerceveleme
// hatasi) belirtir; cause yalnizca EOF-DISI nedenlerde anlamlidir ve
// baglanti/aktarim duzeyinde GUVENLI bir hata olmalidir (SQL/isim/deger
// ICERMEMELIDIR - mevcut ErrClientWriteFailed/ErrBackendReadFailed
// sarmalama kuralindaki AYNI sozlesme; ExtendedFrontend artik kendi
// decoder/parser hatalarini buraya cig sekilde ILETMEZ, bkz. gorev 6).
//
// KRITIK: bu cagri frontendEvents kanalindan/event-loop'tan GECMEZ (bkz.
// gorev 5) - event loop backend.Write/client.Write icinde bloklu OLSA
// BILE, bu bildirim kapanma gozetmeni tarafindan BAGIMSIZ olarak islenir
// ve HER IKI baglantiyi da hemen kapatir. Bu, "no frontend close request
// is silently dropped or treated as best effort" gereksinimini karsilar:
// cagiran, runtime KESIN olarak durana kadar bloklanir ve Run'in
// DONDURECEGI (ya da zaten dondurdugu) AYNI birincil hatayi alir - asla
// bir "en iyi çaba" (best-effort) sinyali degildir.
//
// Run henuz hic baslamadiysa (ErrNotRunning) ANINDA doner - aksi halde
// runtime'in tamamen durmasini (Run donene kadar) bekler. Birden fazla
// cagri guvenlidir: yalnizca ILK cagri gercek bir kapanma istegi gonderir
// (bkz. frontendShutdownOnce), sonraki cagrilar da AYNI kesin sonucu
// bekleyip dondurur.
func (r *ExtendedRuntime) NotifyFrontendClosed(ctx context.Context, reason FrontendCloseReason, cause error) error {
	if lifecycleState(r.lifecycle.Load()) == lifecycleCreated {
		return ErrNotRunning
	}
	r.frontendShutdownOnce.Do(func() {
		r.frontendShutdownCh <- frontendShutdownRequest{reason: reason, cause: cause}
	})
	<-r.stopped
	return r.finalErr
}

// submit, hem RegisterFrontendOperation hem SubmitSyntheticError
// tarafindan paylasilan gonderim/geri-bildirim mantigidir. Kanal
// tukenmesi karsisinda geri basinc uygular: kapasite acilana, cagiranin
// ctx'i iptal edilene ya da runtime sonlanana kadar bloklar.
//
// Kabul (accept) sinirlarinin net sozlesmesi: cagiranin ctx'i yalnizca
// olay HENUZ runtime'a ait kanala YERLESTIRILMEDEN once iptal edilirse
// gonderimi iptal edebilir. Bu gonderim BASARILI oldugu anda, olayin
// sahipligi runtime'a gecer ve cagiran KESIN (definitive) bir sonuc
// alir: ya event-loop'un onayi (ack), ya da runtime'in sonlanmasi
// (ErrRuntimeStopped). Kabulden SONRAKI bir ctx iptali ARTIK
// danisilmaz - boylece cagiran, "islem gercekten oldu mu olmadi mi"
// belirsizligine asla dusmez (bkz. gorev 3). Kabul edilmis bir olay
// GERI CEKILMEYE calisilmaz.
//
// Eger runtime, olay ZATEN islenmisken (ack gonderilmisken) ama cagiran
// henuz onu almadan sonlanirsa, ErrRuntimeStopped donmeden once
// ack'in ZATEN hazir olup olmadigi kontrol edilir - boylece gercekten
// islenmis, spesifik bir sonuc, jenerik bir "durduruldu" hatasiyla
// gereksiz yere kaybedilmez.
//
// Public metotlar HICBIR ZAMAN runtime'a ait kanallari kapatmaz.
func (r *ExtendedRuntime) submit(ctx context.Context, ev frontendEvent) (frontendAck, error) {
	switch lifecycleState(r.lifecycle.Load()) {
	case lifecycleCreated:
		return frontendAck{}, ErrNotRunning
	case lifecycleStopping, lifecycleStopped:
		return frontendAck{}, ErrRuntimeStopped
	}

	// Bkz. gorev 5: asagidaki select, kanal gonderimi HAZIR oldugunda
	// (ör. bos bir kanal) ctx ZATEN iptal edilmis olsa bile Go'nun
	// select semantigi geregi (birden fazla hazir dal arasinda
	// psödorastgele secim) yanlislikla gonderim dalini secebilirdi - bu,
	// gonderimden ONCE iptal edilmis bir istegin kabul edilmesine yol
	// acardi. Bu yuzden, kanala erismeden ONCE ctx.Err() ACIKCA kontrol
	// edilir; ancak bundan SONRA context-farkli enqueue select'i yapilir.
	// Bir onceki kontrolden SONRA ama gonderim tamamlanmadan once bir
	// iptal yarisirsa, BASARILI gonderim kabul sinirini belirler ve
	// mevcut kesin-onay sozlesmesi gecerli olmaya devam eder.
	if err := ctx.Err(); err != nil {
		return frontendAck{}, err
	}

	select {
	case r.frontendEvents <- ev:
		if r.onFrontendEventEnqueued != nil {
			r.onFrontendEventEnqueued()
		}
	case <-ctx.Done():
		return frontendAck{}, ctx.Err()
	case <-r.stopped:
		return frontendAck{}, ErrRuntimeStopped
	}

	// Kabul edildi: artik yalnizca kesin event-loop sonucunu ya da
	// runtime sonlanmasini bekleriz - cagiran ctx'i bir daha
	// danisilmaz.
	select {
	case ack := <-ev.ack:
		return ack, ack.err
	case <-r.stopped:
		select {
		case ack := <-ev.ack:
			return ack, ack.err
		default:
			return frontendAck{}, ErrRuntimeStopped
		}
	}
}

// --- Backend okuyucu ------------------------------------------------------

// runBackendReader, backend'den okur, protocol.NewServerDecoder ile
// cozumler ve her decode edilen protocol.Message'i backendEvents'e
// gonderir. Tek bir sabit boyutlu okuma tamponu kullanir (mesaj basina
// goroutine YOKTUR), istemciye asla yazmaz, ResponseSequencer'i asla
// dogrudan cagirmaz ve protocol.State'i asla dogrudan mutasyona
// ugratmaz.
//
// EOF'ta, decoder.Finalize() cagirilarak tamponda hala cozumlenmemis
// (eksik) bayt kalip kalmadigi kontrol edilir: varsa bu "temiz" bir EOF
// degildir, bir backendEventDecodeError (ErrTruncatedBackendMessage)
// gonderilir - ASLA hem decode-error hem clean-EOF AYNI okuma sonu icin
// gonderilmez.
//
// Gelecekteki canli entegrasyon notu: startup/authentication mesajlari bu
// runtime uzerinden YENIDEN yonlendirilmez - bu bileşen yalnizca
// authentication ele gecmesi TAMAMLANDIKTAN sonra, mevcut (degismemis)
// Gate/Transformer akisinin devrettigi noktadan itibaren calismak uzere
// tasarlanmistir. Eger bu decoder'a (beklenmedik bicimde) bir
// Authentication/BackendKeyData mesaji ulasirsa, BackendCorrelator bunu
// zaten ErrWrongBackendPhase ile fail-closed reddeder - bu runtime ek
// bir ozel durum eklemez.
func (r *ExtendedRuntime) runBackendReader(ctx context.Context) {
	decodeFailed := false
	dec := protocol.NewServerDecoder(
		func(m protocol.Message) {
			// m.Raw, protocol.Decoder.consumeNormal icinde mesaj basina
			// tazee tahsis edilir (append([]byte(nil), d.buf[0:total]...)) -
			// bu yuzden decoder'in kendi ic tamponundan bagimsizdir ve
			// goroutine/kanal sinirini guvenle gecebilir.
			r.sendBackendEvent(ctx, backendEvent{kind: backendEventMessage, msg: m})
		},
		func(err error) {
			decodeFailed = true
			r.sendBackendEvent(ctx, backendEvent{kind: backendEventDecodeError, err: err})
		},
	)

	buf := make([]byte, backendReadBufferSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, readErr := r.backend.Read(buf)
		if n > 0 {
			dec.Write(buf[:n])
			if decodeFailed {
				return
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if finalizeErr := dec.Finalize(); finalizeErr != nil {
					r.sendBackendEvent(ctx, backendEvent{kind: backendEventDecodeError, err: finalizeErr})
				} else {
					r.sendBackendEvent(ctx, backendEvent{kind: backendEventEOF})
				}
			} else {
				r.sendBackendEvent(ctx, backendEvent{kind: backendEventReadError, err: readErr})
			}
			return
		}
	}
}

// sendBackendEvent, backendEvents'e sinirli/geri-basincli bir gonderim
// yapar: kapasite acilana ya da ctx iptal edilene kadar bloklar. ctx iptal
// edilirse olay sessizce dusurulur - ama bu YALNIZCA runtime zaten baska
// bir nedenle kapaniyorken olusabilir (bkz. Run'in kapanma sirasi), bu
// yuzden "hicbir olay sessizce dusurulmez" ilkesini normal calisma
// altinda ihlal etmez.
func (r *ExtendedRuntime) sendBackendEvent(ctx context.Context, ev backendEvent) {
	select {
	case r.backendEvents <- ev:
	case <-ctx.Done():
	}
}

// --- Tek event loop -------------------------------------------------------

// loop, TEK event-loop goroutine'idir: frontendEvents, backendEvents ve
// ctx.Done() uzerinde secim yapar. State'e ve ResponseSequencer'a
// erisim MUNHASIRAN bu goroutine icinde gerceklesir - hicbir zaman
// eszamanli (concurrent) degildir. Her olay tam olarak islenene kadar
// bir sonrakine gecilmez.
func (r *ExtendedRuntime) loop(ctx context.Context) error {
	for {
		select {
		case ev := <-r.frontendEvents:
			if r.onFrontendEventAccepted != nil {
				r.onFrontendEventAccepted()
			}
			if err := r.handleFrontendEvent(ev); err != nil {
				// Bkz. gorev 1: bu ic nedeni, Run'a kontrol geri
				// donmeden ONCE, tam da belirlendigi anda kaydeder -
				// SONRA gelebilecek bir parent ctx iptali bu nedenin
				// yerini asla alamaz.
				r.markInternalShutdown()
				return err
			}
		case ev := <-r.backendEvents:
			stop, err := r.handleBackendEvent(ev)
			if err != nil {
				r.markInternalShutdown()
				return err
			}
			if stop {
				r.markInternalShutdown()
				return nil
			}
		case <-ctx.Done():
			// Bu dal yalnizca GERCEK bir parent ctx iptali/deadline'i
			// ile tetiklenebilir - Run'in kendi cancelRun() cagrisi
			// loop() dondukten SONRA yapilir (bkz. Run), dolayisiyla
			// loop() hala calisirken bu select dalinin secilmesinin
			// TEK nedeni parent ctx'in gercekten sona ermis olmasidir.
			// Gozetmen HENUZ calismamis olsa bile neden burada hemen
			// kaydedilir.
			r.markParentShutdown()
			return ctx.Err()
		}
		// bkz. gorev 15: her olay basari ile islendikten sonra, State'in
		// ARTIK tanimadigi (kapatilmis/basarisiz/degistirilmis) statement/
		// portal generation'lara ait tum maskeleme sekli/plan meta
		// verisini temizler. maskTracker nil ise (maskeleme devre disi)
		// no-op'tur.
		r.reconcileMaskingLifecycle()
		if r.terminalRequested {
			r.markInternalShutdown()
			return ErrTerminationRequested
		}
	}
}

func (r *ExtendedRuntime) handleFrontendEvent(ev frontendEvent) error {
	switch ev.kind {
	case frontendEventRegister:
		return r.handleFrontendRegister(ev)
	case frontendEventRegisterAndForward:
		return r.handleFrontendRegisterAndForward(ev)
	case frontendEventSynthetic:
		return r.handleFrontendSynthetic(ev)
	case frontendEventSyntheticCurrentCycle:
		return r.handleFrontendSyntheticCurrentCycle(ev)
	case frontendEventFlush:
		return r.handleFrontendFlush(ev)
	case frontendEventTerminate:
		return r.handleFrontendTerminate(ev)
	default:
		return nil
	}
}

// handleFrontendRegister, State.Create* cagrisini ve sequencer kaydini
// AYNI event-loop turunda, sirayla uygular (bkz. RegisterFrontendOperation
// doc yorumu icin tam davranis sozlesmesi).
func (r *ExtendedRuntime) handleFrontendRegister(ev frontendEvent) error {
	op, createErr := r.createStateOperation(ev.req)
	if createErr != nil {
		// State kendi sozlesmesi geregi HICBIR mutasyon uygulamadi -
		// sıradan bir ret, runtime saglikli kalir.
		ev.ack <- frontendAck{err: createErr}
		return nil
	}

	actions, seqErr := r.seq.AddForwardedOperation(op)
	if seqErr != nil {
		// UYUSMAZLIK: State zaten mutasyona ugradi ama sequencer
		// islemi reddetti. Devam etmek fail-closed garantisini ihlal
		// eder - runtime KALICI olarak sonlanir, State/sequencer bir
		// daha asla kullanilmaz, hicbir geri alma denenmez.
		divergedErr := fmt.Errorf("%w: %w", ErrFrontendRegistrationDiverged, seqErr)
		ev.ack <- frontendAck{err: divergedErr}
		return divergedErr
	}

	if procErr := r.processActions(actions); procErr != nil {
		ev.ack <- frontendAck{err: procErr}
		return procErr
	}

	// Bkz. gorev 2: basari, kapanmanin (henuz baslamadiysa)
	// dogrusallastirma noktasidir - sendFrontendSuccess, kapanma ZATEN
	// basladiysa basari YERINE sabit ErrRuntimeStopped'i gonderir/dondurur.
	return r.sendFrontendSuccess(ev.ack, frontendAck{reg: FrontendRegistration{Operation: sanitizeOperation(op)}})
}

func (r *ExtendedRuntime) handleFrontendSynthetic(ev frontendEvent) error {
	actions, seqErr := r.seq.AddSyntheticError(ev.cycle, ev.frame)
	if seqErr != nil {
		ev.ack <- frontendAck{err: seqErr}
		return nil
	}
	if procErr := r.processActions(actions); procErr != nil {
		ev.ack <- frontendAck{err: procErr}
		return procErr
	}
	return r.sendFrontendSuccess(ev.ack, frontendAck{})
}

// handleFrontendRegisterAndForward, RegisterAndForwardFrontendOperation'in
// tam davranis sozlesmesini (bkz. dogum yeri doc yorumu) TEK bir event-loop
// turunda uygular: cerceve dogrulama -> State.Create* -> sequencer kaydi ->
// upstream yazma -> basari ack'i - tam bu sirayla.
func (r *ExtendedRuntime) handleFrontendRegisterAndForward(ev frontendEvent) error {
	if err := validateFrontendOperationFrame(ev.frame, ev.req, r.limits.MaxFrontendFrameBytes); err != nil {
		ev.ack <- frontendAck{err: err}
		return nil
	}

	// --- Extended maskeleme on-kontrolu (preflight, bkz. gorev 9) --------
	//
	// YALNIZCA OpExecute icin VE maskeleme etkinken (maskTracker != nil)
	// uygulanir. Sira KESINLIKLE su sekildedir: preflight -> State.
	// CreateExecute -> sequencer kaydi -> effective plan commit -> upstream
	// yazma -> basari ack'i. Preflight, HICBIR State/sequencer mutasyonu
	// uygulanmadan calisir - reddi (varsa) her zaman kurtarilabilir bir
	// yerel rettir (bkz. ErrExtendedMaskingPreflightRejected), asla
	// runtime'i sonlandirmaz.
	var (
		maskPlan      masking.RowMaskPlan
		maskPortalGen protocol.GenerationID
		applyMaskPlan bool
	)
	if r.maskTracker != nil && ev.req.Kind == protocol.OpExecute {
		if portal, ok := r.state.ResolvePortal(ev.req.PortalName); ok {
			// Portal COZUMLENDI: gercek Execute preflight'i uygula. Portal
			// cozumlenemezse (bilinmeyen ad) preflight KASITLI OLARAK
			// atlanir - createStateOperation asagida ZATEN AYNI durumu
			// (ErrUnknownPortal, hicbir mutasyon uygulanmadan) reddedecektir;
			// maskeleme bunun uzerine YENI bir kategori eklemez.
			plan, planErr := r.maskTracker.ResolveExecutePlan(portal.ID, portal.StatementID, portal.ResultFormats)
			if planErr != nil {
				wrapped := fmt.Errorf("%w: %w", ErrExtendedMaskingPreflightRejected, planErr)
				ev.ack <- frontendAck{err: wrapped}
				return nil
			}
			if r.maskTracker.WouldExceedPortalPlanCapacity(portal.ID) {
				wrapped := fmt.Errorf("%w: %w", ErrExtendedMaskingPreflightRejected, masking.ErrExtendedCapacityExceeded)
				ev.ack <- frontendAck{err: wrapped}
				return nil
			}
			maskPlan = plan
			maskPortalGen = portal.ID
			applyMaskPlan = true
		}
	}

	op, createErr := r.createStateOperation(ev.req)
	if createErr != nil {
		// State kendi sozlesmesi geregi HICBIR mutasyon uygulamadi -
		// sıradan bir ret, runtime saglikli kalir, hicbir upstream yazma
		// denenmez.
		ev.ack <- frontendAck{err: createErr}
		return nil
	}

	actions, seqErr := r.seq.AddForwardedOperation(op)
	if seqErr != nil {
		divergedErr := fmt.Errorf("%w: %w", ErrFrontendRegistrationDiverged, seqErr)
		ev.ack <- frontendAck{err: divergedErr}
		return divergedErr
	}

	if applyMaskPlan {
		// Preflight sirasinda WouldExceedPortalPlanCapacity ZATEN
		// dogrulandigi ve bu noktaya kadar (tek-goroutine, senkron cagri
		// zinciri icinde) baska HICBIR sey maskTracker'in kapasitesini
		// degistiremeyecegi icin bu cagri PRATIKTE asla basarisiz olmaz -
		// yine de savunma amacli ele alinir: basarisiz olursa State/
		// sequencer ZATEN mutasyona ugramistir, bu bir UYUSMAZLIKTIR (aynen
		// AddForwardedOperation basarisizligi gibi) ve runtime KALICI
		// olarak sonlanir.
		if commitErr := r.maskTracker.CommitExecutePlan(maskPortalGen, maskPlan); commitErr != nil {
			divergedErr := fmt.Errorf("%w: %w", ErrFrontendRegistrationDiverged, commitErr)
			ev.ack <- frontendAck{err: divergedErr}
			return divergedErr
		}
	}

	if procErr := r.processActions(actions); procErr != nil {
		// actions, AddForwardedOperation'in basarili durumunda HER ZAMAN
		// nil'dir (bkz. o metodun dokumantasyonu) - bu cagri yalnizca
		// simetri/savunma icindir. Boyle bir hata (varsayimsal bir CLIENT
		// yazma basarisizligi) upstream yazmadan BAGIMSIZDIR.
		ev.ack <- frontendAck{err: procErr}
		return procErr
	}

	// Kayit-once-iletim degismezi: State + sequencer kaydi (+ varsa
	// maskeleme plani taahhudu) ARTIK tamamlandi - orijinal cerceve ANCAK
	// SIMDI upstream'e yazilir.
	if err := writeAll(r.backend, ev.frame); err != nil {
		wrapped := fmt.Errorf("%w: %w", ErrBackendWriteFailed, err)
		ev.ack <- frontendAck{err: wrapped}
		return wrapped
	}

	return r.sendFrontendSuccess(ev.ack, frontendAck{reg: FrontendRegistration{Operation: sanitizeOperation(op)}})
}

// handleFrontendSyntheticCurrentCycle, SubmitSyntheticErrorForCurrentCycle'in
// tam davranis sozlesmesini uygular: event-loop KENDISI State.CurrentCycle()'i
// okur (cagiran hicbir zaman bir cycle tahmin etmez/saglamaz), ardindan
// AddSyntheticError'i bu tam cycle icin cagirir.
func (r *ExtendedRuntime) handleFrontendSyntheticCurrentCycle(ev frontendEvent) error {
	cycle := r.state.CurrentCycle()
	actions, seqErr := r.seq.AddSyntheticError(cycle, ev.frame)
	if seqErr != nil {
		ev.ack <- frontendAck{err: seqErr}
		return nil
	}
	if procErr := r.processActions(actions); procErr != nil {
		ev.ack <- frontendAck{err: procErr}
		return procErr
	}
	return r.sendFrontendSuccess(ev.ack, frontendAck{cycle: cycle})
}

// handleFrontendFlush, ForwardFlush'in tam davranis sozlesmesini uygular
// (bkz. gorev 6): hicbir State/sequencer mutasyonu yapilmaz, cerceve
// dogrulanip TAM OLARAK BIR KEZ upstream'e yazilir.
func (r *ExtendedRuntime) handleFrontendFlush(ev frontendEvent) error {
	if err := validateNoBodyFrontendFrame(ev.frame, protocol.MsgFlush, protocol.ParseFrontendFlush, r.limits.MaxFrontendFrameBytes); err != nil {
		ev.ack <- frontendAck{err: err}
		return nil
	}
	if err := writeAll(r.backend, ev.frame); err != nil {
		wrapped := fmt.Errorf("%w: %w", ErrBackendWriteFailed, err)
		ev.ack <- frontendAck{err: wrapped}
		return wrapped
	}
	return r.sendFrontendSuccess(ev.ack, frontendAck{})
}

// handleFrontendTerminate, ForwardTerminate'in tam davranis sozlesmesini
// uygular (bkz. gorev 6): hicbir State/sequencer mutasyonu yapilmaz,
// cerceve dogrulanip TAM OLARAK BIR KEZ upstream'e yazilir; basarili
// yazimdan SONRA cagirana basari (nil) ack'lenir VE runtime'in KALICI
// olarak sonlanmasi icin ErrFrontendTerminateRequested dondurulur.
func (r *ExtendedRuntime) handleFrontendTerminate(ev frontendEvent) error {
	if err := validateNoBodyFrontendFrame(ev.frame, protocol.MsgTerminate, protocol.ParseFrontendTerminate, r.limits.MaxFrontendFrameBytes); err != nil {
		ev.ack <- frontendAck{err: err}
		return nil
	}
	if err := writeAll(r.backend, ev.frame); err != nil {
		wrapped := fmt.Errorf("%w: %w", ErrBackendWriteFailed, err)
		ev.ack <- frontendAck{err: wrapped}
		return wrapped
	}
	if err := r.sendFrontendSuccess(ev.ack, frontendAck{}); err != nil {
		// ackGate ZATEN kapanmisti (parent kapanma once dogrusallasti) -
		// bu, kendi (parent-kaynakli) nedenselligiyle zaten loop()'u
		// sonlandiracaktir; ErrFrontendTerminateRequested'i UZERINE
		// yazmaya gerek yok.
		return err
	}
	return ErrFrontendTerminateRequested
}

// createStateOperation, req.Kind'a gore DOGRU State.Create* metodunu
// cagirir. Bu, State'e erisen TEK yerdir ve yalnizca event-loop
// goroutine'i icinden cagirilir.
func (r *ExtendedRuntime) createStateOperation(req FrontendOperationRequest) (protocol.PendingOperation, error) {
	switch req.Kind {
	case protocol.OpParse:
		op, _, err := r.state.CreateParse(req.StatementName, req.Query, req.ParamOIDs)
		return op, err
	case protocol.OpBind:
		op, _, err := r.state.CreateBind(req.PortalName, req.StatementName, req.ParamFormats, req.ParamNulls, req.ResultFormats)
		return op, err
	case protocol.OpDescribeStatement:
		return r.state.CreateDescribeStatement(req.StatementName)
	case protocol.OpDescribePortal:
		return r.state.CreateDescribePortal(req.PortalName)
	case protocol.OpExecute:
		return r.state.CreateExecute(req.PortalName)
	case protocol.OpCloseStatement:
		return r.state.CreateCloseStatement(req.StatementName)
	case protocol.OpClosePortal:
		return r.state.CreateClosePortal(req.PortalName)
	case protocol.OpSync:
		return r.state.CreateSync()
	default:
		return protocol.PendingOperation{}, ErrInvalidOperationKind
	}
}

func (r *ExtendedRuntime) handleBackendEvent(ev backendEvent) (stop bool, err error) {
	switch ev.kind {
	case backendEventMessage:
		actions, seqErr := r.seq.HandleBackendMessage(ev.msg)
		if seqErr != nil {
			return false, fmt.Errorf("%w: %w", ErrBackendProtocolFailure, seqErr)
		}
		return false, r.processActions(actions)
	case backendEventDecodeError:
		if errors.Is(ev.err, protocol.ErrTruncatedMessage) {
			return false, fmt.Errorf("%w: %w", ErrTruncatedBackendMessage, ev.err)
		}
		return false, fmt.Errorf("%w: %w", ErrBackendReadFailed, ev.err)
	case backendEventReadError:
		return false, fmt.Errorf("%w: %w", ErrBackendReadFailed, ev.err)
	case backendEventEOF:
		if r.seq.HasPendingWork() {
			return false, ErrBackendClosedUnexpectedly
		}
		return true, nil
	default:
		return false, nil
	}
}

// --- OutputAction isleme ---------------------------------------------

// processActions, verilen eylem grubunu SIRAYLA isler. Bir yazma
// basarisiz olursa, bu batch icinde ondan sonraki hicbir eylem islenmez.
// ActionTerminateConnection gorulur gorulmez terminalRequested set edilir
// ve isleme aninda durur (bu eylemden SONRA hicbir eylem islenmez -
// zaten sequencer sozlesmesi geregi bu her zaman batch'in son elemanidir,
// ama bu fonksiyon buna guvenmez).
func (r *ExtendedRuntime) processActions(actions []protocol.OutputAction) error {
	for _, a := range actions {
		switch a.Kind {
		case protocol.ActionEmitBackendFrame, protocol.ActionEmitSyntheticFrame:
			out := a.Bytes
			if r.maskTracker != nil && a.Kind == protocol.ActionEmitBackendFrame {
				masked, maskErr := r.applyMasking(a)
				if maskErr != nil {
					return r.emitMaskingFailureFatal(maskErr)
				}
				out = masked
			}
			if err := writeAll(r.client, out); err != nil {
				return fmt.Errorf("%w: %w", ErrClientWriteFailed, err)
			}
		case protocol.ActionTerminateConnection:
			r.terminalRequested = true
			return nil
		}
	}
	return nil
}

// --- Extended maskeleme: backend yaniti gozlemi/donusumu (bkz. gorev 11-13) -
//
// Asagidaki yardimcilar YALNIZCA processActions (dolayisiyla YALNIZCA
// event-loop goroutine'i) tarafindan cagirilir. r.maskTracker nil ise
// processActions bunlari hic cagirmaz (bkz. yukarida).

// applyMasking, TEK bir ActionEmitBackendFrame icin maskeleme-farkindaligi
// donusumunu uygular: statement/portal Describe RowDescription/NoData
// yanitlari GOZLEMLENIR (sekil onbellege alinir) ama HER ZAMAN degismeden
// iletilir; Execute'a ait DataRow'lar taahhut edilmis effective plana gore
// MASKELENIR; digerleri (ParseComplete/BindComplete/CommandComplete/
// ReadyForQuery/async mesajlar/vb.) DOKUNULMADAN gecer.
func (r *ExtendedRuntime) applyMasking(a protocol.OutputAction) ([]byte, error) {
	switch {
	case (a.MessageType == protocol.MsgRowDescription || a.MessageType == protocol.MsgNoData) &&
		(a.OperationKind == protocol.OpDescribeStatement || a.OperationKind == protocol.OpDescribePortal):
		if err := r.observeDescribeAction(a); err != nil {
			return nil, err
		}
		return a.Bytes, nil
	case a.MessageType == protocol.MsgDataRow && a.OperationKind == protocol.OpExecute:
		return r.transformDataRowAction(a)
	default:
		return a.Bytes, nil
	}
}

// observeDescribeAction, gercek bir statement/portal Describe yanitindan
// (RowDescription ya da NoData) sekil meta verisini gozlemleyip
// ExtendedTracker'a kaydeder. a.Bytes HER ZAMAN tag(1)+uzunluk(4)+govde
// bicimindedir (bkz. ActionEmitBackendFrame.Bytes dokumantasyonu) - govde
// a.Bytes[5:]'tir.
func (r *ExtendedRuntime) observeDescribeAction(a protocol.OutputAction) error {
	body := a.Bytes[5:]
	switch a.OperationKind {
	case protocol.OpDescribeStatement:
		if a.MessageType == protocol.MsgNoData {
			return r.maskTracker.ObserveStatementDescribeNoData(a.TargetGeneration)
		}
		return r.maskTracker.ObserveStatementDescribeRowDescription(a.TargetGeneration, body)
	case protocol.OpDescribePortal:
		if a.MessageType == protocol.MsgNoData {
			return r.maskTracker.ObservePortalDescribeNoData(a.TargetGeneration)
		}
		return r.maskTracker.ObservePortalDescribeRowDescription(a.TargetGeneration, body, r.portalResultFormatsForMasking(a.TargetGeneration))
	}
	return nil
}

// portalResultFormatsForMasking, a.TargetGeneration'a karsilik gelen
// portalin Bind'ta ISTENEN sonuc format kodlarini State'ten okur (salt-
// okunur). Portal artik State'te bulunamazsa (beklenmedik/savunma amacli)
// nil doner - ExpandResultFormats bunu "tumu metin beklenir" olarak ele
// alir, bu da gercek bir ikili uyumsuzlugu GUVENLI sekilde (fail-closed)
// yakalar.
func (r *ExtendedRuntime) portalResultFormatsForMasking(gen protocol.GenerationID) []int16 {
	p, ok := r.state.Portal(gen)
	if !ok {
		return nil
	}
	return p.ResultFormats
}

// transformDataRowAction, a.TargetGeneration (portal generation) icin
// taahhut edilmis effective plani bulup gercek, I/O icermeyen maskeleme
// cekirdegini (bkz. masking.MaskDataRow) cagirir. Taahhut edilmis bir plan
// yoksa (bkz. gorev 12: "fail closed if masking is enabled and no plan
// exists") ya da cekirdek hata dondururse, orijinal (maskelenmemis) baytlar
// ASLA dondurulmez.
func (r *ExtendedRuntime) transformDataRowAction(a protocol.OutputAction) ([]byte, error) {
	plan, ok := r.maskTracker.LookupExecutePlan(a.TargetGeneration)
	if !ok {
		return nil, ErrNoCommittedMaskPlan
	}
	ctx := r.runCtx
	if ctx == nil {
		ctx = context.Background()
	}
	out, _, err := masking.MaskDataRow(ctx, r.masker, plan, a.Bytes, r.maskHooks)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// emitMaskingFailureFatal, gercek bir backend yaniti islenirken olusan bir
// maskeleme hatasindan sonra client'a EN FAZLA BIR KEZ, TAM, SABIT bir
// FATAL ErrorResponse yazmaya calisir ve maskeleme hatasini (cause SARILMIS
// olarak) Run'in birincil hatasi olarak dondurur (bkz. gorev 13). Bu,
// ResponseSequencer'dan GECMEZ (yerel bir sentetik ret DEGILDIR).
//
// Nedensellik dogrusallastirmasi (bkz. gorev 5): FATAL yazimi (Bloklu
// olabilir - client baglantisi yavas/durmus olabilir) DENENMEDEN ONCE,
// r.markInternalShutdown() cagrilir - bu, bu maskeleme hatasinin
// shutdownCause'u KAZANIP KAZANMADIGINI (yani GERCEKTEN birincil neden
// olup olmadigini) ATOMIK olarak belirler:
//
//   - CAS KAZANILIRSA: bu maskeleme hatasi GERCEKTEN ilk (birincil) nedendir
//   - nedeni dogrusallastirdiktan HEMEN SONRA FATAL yazimi denenir. Bu
//     noktadan sonra baslayan (ör. blokli yazim sirasinda araya giren) bir
//     parent ctx iptali/frontend kapanmasi, shutdownCause ZATEN Internal
//     oldugundan kendi CAS'ini KAYBEDER - ErrExtendedMaskingFailed asla
//     ustune yazilmaz.
//   - CAS KAYBEDILIRSE: baska bir neden (parent ctx iptali ya da frontend
//     kapanmasi) BU cagridan ONCE ZATEN dogrusallasmis demektir - o ERKEN
//     nedenin GERCEK birincil neden olarak KALMASI icin FATAL yazimi HIC
//     DENENMEZ (baglanti zaten BASKA bir nedenle kapatma surecinde) ve
//     alttaki writeAll cagrisi atlanir.
//
// Her iki durumda da donen primary, YALNIZCA bu cagrinin KENDI donus
// degeridir - Run()'un kesin birincil hatayi hangi shutdownCause'un
// KAZANDIGINA gore (bkz. Run, "primaryErr := loopErr; switch
// shutdownCause...") COZMESI zaten mevcut, degismeyen mekanizmadir; bu
// fonksiyon o mekanizmayi ATLAMAZ, yalnizca YARIS PENCERESINI kapatir.
func (r *ExtendedRuntime) emitMaskingFailureFatal(cause error) error {
	primary := fmt.Errorf("%w: %w", ErrExtendedMaskingFailed, cause)
	if !r.markInternalShutdown() {
		// Baska bir neden (parent ctx / frontend kapanmasi) BU maskeleme
		// hatasindan ONCE zaten dogrusallasti - o erken nedenin birincil
		// olarak KALMASI icin FATAL yazimini hic denemeden dogrudan
		// donuyoruz (bkz. yukaridaki doc yorumu).
		return primary
	}
	frame := protocol.BuildErrorResponse("FATAL", sqlStateExtendedMaskingFailed, reasonExtendedMaskingFailed)
	_ = writeAll(r.client, frame)
	return primary
}

// reconcileMaskingLifecycle, ExtendedTracker'daki (bkz. gorev 15) statement/
// portal sekli/plan girdilerini, State'in ARTIK taniMADIGI (silinmis ya da
// LifecycleFailed) generation'lar icin temizler. Isim yerine YALNIZCA
// generation kimligine dayanir; State ile ExtendedTracker arasindaki tek
// mutabakat (reconciliation) noktasidir - her olay basari ile islendikten
// sonra (bkz. loop) cagrilir.
func (r *ExtendedRuntime) reconcileMaskingLifecycle() {
	if r.maskTracker == nil {
		return
	}
	for _, gen := range r.maskTracker.StatementGenerations() {
		g, ok := r.state.Statement(gen)
		if !ok || g.State == protocol.LifecycleFailed {
			r.maskTracker.RetireStatement(gen)
		}
	}
	for _, gen := range r.maskTracker.PortalGenerations() {
		g, ok := r.state.Portal(gen)
		if !ok || g.State == protocol.LifecycleFailed {
			r.maskTracker.RetirePortal(gen)
		}
	}
}

// writeAll, p'nin TUMUNUN yazildigindan emin olana kadar tekrar tekrar
// Write cagirir - tek bir Write cagrisinin butun baytlari yazacagini
// VARSAYMAZ. (0, nil) donen bir Write, ilerleme kaydedilmedigi icin bir
// hata olarak ele alinir (ErrNoProgress). action.Bytes hicbir zaman
// mutasyona ugratilmaz (yalnizca okunur).
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return fmt.Errorf("extendedruntime: writer gecersiz sayida bayt bildirdi (n=%d, len=%d)", n, len(p))
		}
		if n == 0 && err == nil {
			return ErrNoProgress
		}
		p = p[n:]
		if err != nil {
			return err
		}
	}
	return nil
}

// --- Frontend cerceve dogrulamasi (bkz. gorev 4) ---------------------------
//
// Bu bolumdeki yardimcilar, RegisterAndForwardFrontendOperation/ForwardFlush/
// ForwardTerminate'e verilen HAM cercevenin upstream'e yazilmadan ONCE tam,
// tek, dogru etiketli bir normal-protokol frontend cercevesi oldugunu
// dogrudan (protocol.Decoder'in akis-durumlu, TEK GECIS ayristirmasindan
// BAGIMSIZ olarak) yeniden dogrular - savunma amaclidir (cagiran, ör.
// internal/firewall.ExtendedFrontend, kendi decoder'i araciligiyla zaten
// dogrulamis olsa bile). Hicbir donen hata ham baytlar/SQL/isim/deger
// icermez.

// frontendFrameRequirements, req.Kind icin BEKLENEN frontend mesaj tipini
// ve (yalnizca Describe/Close icin) hedef seciciyi dondurur. wantTarget
// sifir (gecersiz TargetType) ise hedef secici dogrulamasi atlanir.
func frontendFrameRequirements(kind protocol.OperationKind) (msgType protocol.MessageType, wantTarget protocol.TargetType, err error) {
	switch kind {
	case protocol.OpParse:
		return protocol.MsgParse, 0, nil
	case protocol.OpBind:
		return protocol.MsgBind, 0, nil
	case protocol.OpDescribeStatement:
		return protocol.MsgDescribe, protocol.TargetStatement, nil
	case protocol.OpDescribePortal:
		return protocol.MsgDescribe, protocol.TargetPortal, nil
	case protocol.OpExecute:
		return protocol.MsgExecute, 0, nil
	case protocol.OpCloseStatement:
		return protocol.MsgClose, protocol.TargetStatement, nil
	case protocol.OpClosePortal:
		return protocol.MsgClose, protocol.TargetPortal, nil
	case protocol.OpSync:
		return protocol.MsgSync, 0, nil
	default:
		return 0, 0, ErrInvalidOperationKind
	}
}

// validateFrontendFrameHeader, frame'in gecerli bir normal-protokol
// cercevesi (tag(1) + uzunluk(4) + govde) oldugunu dogrular: verilen
// maxFrame sinirini asmadigini, tag'in wantType ile eslestigini, uzunluk
// alaninin en az 4 oldugunu ve TAM OLARAK frame'in geri kalanina denk
// geldigini (ne eksik ne fazla/artik bayt) kontrol eder. Basarili olursa
// govdeyi (payload) dondurur.
func validateFrontendFrameHeader(frame []byte, wantType protocol.MessageType, maxFrame int) ([]byte, error) {
	if maxFrame > 0 && len(frame) > maxFrame {
		return nil, ErrFrontendFrameTooLarge
	}
	if len(frame) < 5 {
		return nil, fmt.Errorf("%w: cerceve basligi (tag+uzunluk) eksik", ErrInvalidFrontendFrame)
	}
	if protocol.MessageType(frame[0]) != wantType {
		return nil, fmt.Errorf("%w: mesaj tipi istenen islemle uyusmuyor", ErrInvalidFrontendFrame)
	}
	length := int(binary.BigEndian.Uint32(frame[1:5]))
	if length < 4 {
		return nil, fmt.Errorf("%w: gecersiz uzunluk alani", ErrInvalidFrontendFrame)
	}
	total := 1 + length
	if total != len(frame) {
		return nil, fmt.Errorf("%w: uzunluk alani cerceve boyutuyla uyusmuyor (eksik ya da artik bayt)", ErrInvalidFrontendFrame)
	}
	return frame[5:total], nil
}

// validateFrontendOperationFrame, RegisterAndForwardFrontendOperation icin
// TAM cerceve dogrulamasini uygular: baslik dogrulamasi + req.Kind icin
// dogru tipli govde ayristiricisinin cagrilmasi + (Describe/Close icin)
// hedef secicinin req.Kind ile uyusmasi.
func validateFrontendOperationFrame(frame []byte, req FrontendOperationRequest, maxFrame int) error {
	msgType, wantTarget, err := frontendFrameRequirements(req.Kind)
	if err != nil {
		return err
	}
	payload, err := validateFrontendFrameHeader(frame, msgType, maxFrame)
	if err != nil {
		return err
	}
	switch req.Kind {
	case protocol.OpParse:
		if _, perr := protocol.ParseFrontendParse(payload); perr != nil {
			return fmt.Errorf("%w: %w", ErrInvalidFrontendFrame, perr)
		}
	case protocol.OpBind:
		if _, perr := protocol.ParseFrontendBind(payload); perr != nil {
			return fmt.Errorf("%w: %w", ErrInvalidFrontendFrame, perr)
		}
	case protocol.OpDescribeStatement, protocol.OpDescribePortal:
		d, perr := protocol.ParseFrontendDescribe(payload)
		if perr != nil {
			return fmt.Errorf("%w: %w", ErrInvalidFrontendFrame, perr)
		}
		if wantTarget != 0 && d.Target != wantTarget {
			return fmt.Errorf("%w: describe hedef secici istenen islem turuyle uyusmuyor", ErrInvalidFrontendFrame)
		}
	case protocol.OpExecute:
		if _, perr := protocol.ParseFrontendExecute(payload); perr != nil {
			return fmt.Errorf("%w: %w", ErrInvalidFrontendFrame, perr)
		}
	case protocol.OpCloseStatement, protocol.OpClosePortal:
		c, perr := protocol.ParseFrontendClose(payload)
		if perr != nil {
			return fmt.Errorf("%w: %w", ErrInvalidFrontendFrame, perr)
		}
		if wantTarget != 0 && c.Target != wantTarget {
			return fmt.Errorf("%w: close hedef secici istenen islem turuyle uyusmuyor", ErrInvalidFrontendFrame)
		}
	case protocol.OpSync:
		if perr := protocol.ParseFrontendSync(payload); perr != nil {
			return fmt.Errorf("%w: %w", ErrInvalidFrontendFrame, perr)
		}
	}
	return nil
}

// validateNoBodyFrontendFrame, Flush/Terminate gibi hicbir alani olmayan
// mesajlar icin baslik dogrulamasi + govde-bos kontrolunu (verilen parse
// fonksiyonu araciligiyla) uygular.
func validateNoBodyFrontendFrame(frame []byte, wantType protocol.MessageType, parse func([]byte) error, maxFrame int) error {
	payload, err := validateFrontendFrameHeader(frame, wantType, maxFrame)
	if err != nil {
		return err
	}
	if perr := parse(payload); perr != nil {
		return fmt.Errorf("%w: %w", ErrInvalidFrontendFrame, perr)
	}
	return nil
}

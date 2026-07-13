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
// bozar. internal/firewall ve internal/masking, internal/protocol'e
// bağımlıdır (tersi değil) - bu paket de aynı bağımlılık yönünü izler:
// yalnızca internal/protocol'e bağımlıdır, ne firewall ne masking
// paketine dokunur. "gateway" adı, bu bileşenin nihai olarak
// cmd/gateway'in bağlantı işleme akışına bağlanacağı ileriki bir
// aşamayı öngörür; bu AŞAMADA ise hiçbir canlı çağrı noktası yoktur
// (bkz. paket testleri dışında hiçbir yerden import edilmez).
package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

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
}

func (l RuntimeLimits) validate() error {
	if l.FrontendEventBuffer <= 0 || l.BackendEventBuffer <= 0 {
		return ErrInvalidRuntimeLimits
	}
	return nil
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
	frontendEventSynthetic
)

// frontendEvent, RegisterFrontendOperation/SubmitSyntheticError
// tarafindan olusturulan, degismez bir istek goruntusudur. ack, kapasitesi
// 1 olan tamponlu bir kanaldir: cagiranin ctx'i olay kabul edildikten
// SONRA ama sonuc alinmadan ONCE iptal edilirse, olay isleyici
// goroutine'inin (event loop) gonderim sirasinda asla bloklanmamasini
// (dolayisiyla sizinti olusmamasini) saglar.
type frontendEvent struct {
	kind  frontendEventKind
	req   FrontendOperationRequest // yalnizca frontendEventRegister icin
	cycle protocol.CycleID         // yalnizca frontendEventSynthetic icin
	frame []byte                   // yalnizca frontendEventSynthetic icin, cagirandan bagimsiz kopya
	ack   chan frontendAck
}

type frontendAck struct {
	reg FrontendRegistration
	err error
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
// Bu asamada HENUZ hicbir canli gateway/firewall/masking baglantisi
// yoktur - ExtendedRuntime yalniz kendi testleri disinda hicbir yerden
// kullanilmaz.
type ExtendedRuntime struct {
	state *protocol.State
	seq   *protocol.ResponseSequencer

	backend io.ReadCloser
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
	//   - onWatcherShutdownBegun, beginWatcherShutdown ackGate'i
	//     BIRAKTIKTAN hemen sonra cagrilir - testlerin watcher'in
	//     gecisini GERCEKTEN tamamladigini uykuya basvurmadan
	//     bilebilmesi icindir.
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
	backend io.ReadCloser,
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
		state:          state,
		seq:            seq,
		backend:        backend,
		client:         client,
		limits:         runtimeLimits,
		frontendEvents: make(chan frontendEvent, runtimeLimits.FrontendEventBuffer),
		backendEvents:  make(chan backendEvent, runtimeLimits.BackendEventBuffer),
		started:        make(chan struct{}),
		stopped:        make(chan struct{}),
	}, nil
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
// ctx iptalinin CAS'i tarafindan asla ustune yazilamaz.
func (r *ExtendedRuntime) markInternalShutdown() {
	r.shutdownCause.CompareAndSwap(int32(shutdownCauseNone), int32(shutdownCauseInternal))
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

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		r.runBackendReader(runCtx)
	}()

	// Kapanma gozetmeni: runCtx sona erdiginde (parent ctx iptali/
	// deadline'i YA DA Run'in kendisinin asagida cagiracagi cancelRun()
	// nedeniyle) HER IKI baglantiyi da kapatir. parent ctx'in GERCEKTEN
	// sona erip ermedigini (yalnizca Run'in kendi ic cancelRun()
	// cagrisindan degil) ayirt etmek icin runCtx.Err() DEGIL, DOGRUDAN
	// ctx.Err() kontrol edilir - boylece "kim once bitirdi" sorusu
	// hatasiz cevaplanir (bkz. shutdownCause). beginWatcherShutdown,
	// parent nedeni kaydetmeyi VE basarili-ack kabulunu kapatmayi TEK
	// bir ackGate kritik bolgesinde atomik yapar (bkz. gorev 2) -
	// boylece event loop, parent nedeni kaydedilmeden once ama
	// baglantilar kapanmadan sonraki bir anda yanlislikla basarili bir
	// ack gonderemez.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-runCtx.Done()
		r.beginWatcherShutdown(ctx.Err() != nil)
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

	r.lifecycle.Store(int32(lifecycleStopped))
	close(r.stopped)

	primaryErr := loopErr
	if shutdownCause(r.shutdownCause.Load()) == shutdownCauseParentCtx {
		// Parent ctx'in sona ermesi kapanmayi BASLATTI - loop()'un donus
		// degeri (varsa) yalnizca bu ZORLA kapatmanin bir semptomu
		// olabilir (ör. bloklu bir Write'in kesilmesinden kaynaklanan
		// ErrClientWriteFailed) - bu yuzden gercek nedeni (context.Canceled
		// ya da context.DeadlineExceeded) rapor ederiz.
		primaryErr = ctx.Err()
	}

	return primaryErr
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
	case frontendEventSynthetic:
		return r.handleFrontendSynthetic(ev)
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
			if err := writeAll(r.client, a.Bytes); err != nil {
				return fmt.Errorf("%w: %w", ErrClientWriteFailed, err)
			}
		case protocol.ActionTerminateConnection:
			r.terminalRequested = true
			return nil
		}
	}
	return nil
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

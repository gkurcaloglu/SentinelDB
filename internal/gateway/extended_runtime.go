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
	// bir Run cagrisinda donulur.
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
type FrontendRegistration struct {
	Operation protocol.PendingOperation
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

	// onFrontendEventEnqueued/onFrontendEventAccepted, YALNIZCA PAKET
	// TESTLERI tarafindan ayarlanan isteğe bagli kancalardir (hooks).
	// Uretimde HER ZAMAN nil'dir ve hicbir etkisi yoktur - yalnizca
	// "kabul edilmis ama henuz islenmemis olay" senaryolarini uykuya
	// (sleep) basvurmadan deterministik olarak test edebilmek icindir:
	//   - onFrontendEventEnqueued, submit() icinde bir olay kanala
	//     basari ile YERLESTIRILDIGI aninda (cagiran goroutine'de, ack
	//     beklemeden ONCE) cagrilir.
	//   - onFrontendEventAccepted, event-loop bir olayi kanaldan
	//     ALDIGI aninda (islemeye baslamadan ONCE) cagrilir.
	// Her iki alan da yalnizca Run baslamadan ONCE ayarlanmalidir (test
	// kodunda) - bu, Go bellek modelinin goroutine-olusturma
	// happens-before garantisiyle veri yarisini onler.
	onFrontendEventEnqueued func()
	onFrontendEventAccepted func()
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

// Run, olay dongusunu baslatir ve ictegi cagirir (blocking). TAM OLARAK
// BIR KEZ cagrilabilir - ikinci bir cagri aninda ErrAlreadyRunning
// dondurur. Run donduğunde: backend-okuyucu goroutine'i katilmis
// (joined), her iki baglanti (backend, client) kapatilmis ve runtime
// kalici olarak "stopped" durumundadir.
//
// Baglanti kapatma, bloklu bir net.Conn Read/Write cagrisini gercekten
// KESEBILEN TEK mekanizmadir - context iptali TEK BASINA keyfi bir
// io.Reader/io.Writer cagrisini kesemez. Bu yuzden Run, hem ctx
// iptalinde hem de kendi ic hata yollarinda, geri donmeden once
// backend/client'i acikca kapatir.
func (r *ExtendedRuntime) Run(ctx context.Context) error {
	if !r.lifecycle.CompareAndSwap(int32(lifecycleCreated), int32(lifecycleRunning)) {
		return ErrAlreadyRunning
	}
	close(r.started)

	runCtx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.runBackendReader(runCtx)
	}()

	primaryErr := r.loop(runCtx)

	// Sonlandirma sirasi: once yeni gonderimleri reddetmeye basla (bkz.
	// submit), sonra ic context'i iptal et (ctx.Done() uzerinde bekleyen
	// her seyi - ozellikle backend okuyucunun olay-gonderim select'ini -
	// aninda uyandirir), sonra HER IKI sahip olunan baglantiyi kapat
	// (bloklu bir Read/Write cagrisini gercekten kesen tek sey budur).
	r.lifecycle.Store(int32(lifecycleStopping))
	cancel()
	r.closeOnce.Do(func() {
		_ = r.backend.Close()
		_ = r.client.Close()
	})

	wg.Wait() // backend-okuyucu Run donmeden once katilmis olmalidir

	r.lifecycle.Store(int32(lifecycleStopped))
	close(r.stopped)

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
				return err
			}
		case ev := <-r.backendEvents:
			stop, err := r.handleBackendEvent(ev)
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
		if r.terminalRequested {
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

	ev.ack <- frontendAck{reg: FrontendRegistration{Operation: op}}
	return nil
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
	ev.ack <- frontendAck{err: nil}
	return nil
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

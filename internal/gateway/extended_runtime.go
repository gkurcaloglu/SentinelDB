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
// kullandığı sabit boyutlu tampon boyutudur (bkz. gorev 5: "use a bounded
// fixed-size read buffer"). internal/firewall/gate.go'nun mevcut 32 KiB
// tamponuyla tutarlıdır.
const backendReadBufferSize = 32 * 1024

// --- Sabit hata kategorileri ------------------------------------------
//
// Hiçbiri ham baytlar, SQL metni, Bind parametre değerleri, statement/
// portal adları, ErrorResponse alanları ya da CommandComplete etiketleri
// İÇERMEZ (bkz. gorev 9). Alttaki G/Ç hatası (%w ile sarılan) yalnızca
// bağlantı/aktarım düzeyinde metin taşır (ör. "broken pipe"), hiçbir
// zaman protokol yükü değil.
var (
	ErrNilState             = errors.New("extendedruntime: nil protocol.State saglanamaz")
	ErrNilBackend           = errors.New("extendedruntime: nil backend reader saglanamaz")
	ErrNilClient            = errors.New("extendedruntime: nil client writer saglanamaz")
	ErrInvalidRuntimeLimits = errors.New("extendedruntime: gecersiz runtime sinirlari (pozitif olmali)")

	// ErrAlreadyRunning, Run ikinci kez cagrildiginda donulur (bkz. gorev
	// 8: "Run can transition created -> running exactly once").
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
	// ActionTerminateConnection dondurdugunde kullanilir (bkz. gorev 9,
	// oncelik #1).
	ErrTerminationRequested = errors.New("extendedruntime: sequencer baglanti sonlandirmasini istedi")
	// ErrClientWriteFailed, istemciye yazma basarisiz oldugunda (bkz.
	// gorev 9, oncelik #2) donulen sarmalayici hatadir.
	ErrClientWriteFailed = errors.New("extendedruntime: istemciye yazma basarisiz")
	// ErrBackendProtocolFailure, ResponseSequencer.HandleBackendMessage
	// bir hata dondurdugunde (plan uyusmazligi, bozuk cerceve,
	// desteklenmeyen COPY, imkansiz siralama, sequencer zaten terminal)
	// kullanilir - gercek sunucuyla senkronizasyon artik guvenilir
	// olmadigindan bu HER ZAMAN runtime'i kalici olarak sonlandirir
	// (bkz. gorev 12).
	ErrBackendProtocolFailure = errors.New("extendedruntime: backend mesaji sequencer tarafindan reddedildi")
	// ErrBackendReadFailed, backend'den okuma (decode hatasi dahil)
	// basarisiz oldugunda kullanilir (bkz. gorev 9, oncelik #3/#4).
	ErrBackendReadFailed = errors.New("extendedruntime: backend okuma/ayristirma basarisiz")
	// ErrBackendClosedUnexpectedly, backend hala cozumlenmemis
	// (HasPendingWork()==true) plan birimleri varken EOF ile
	// kapandiginda donulur (bkz. gorev 9, oncelik #5).
	ErrBackendClosedUnexpectedly = errors.New("extendedruntime: backend, bekleyen sekans durumu varken beklenmedik sekilde kapandi")
	// ErrNoProgress, bir Write cagrisi (0, nil) dondurdugunde - yani
	// hicbir hata bildirmeden hicbir ilerleme kaydetmediginde - kullanilir
	// (bkz. gorev 7: "treat (0, nil) as no progress and fail closed").
	ErrNoProgress = errors.New("extendedruntime: writer ilerleme kaydetmedi (0 bayt, hata yok)")
)

// RuntimeLimits, ExtendedRuntime'in olay kanallari icin pozitif, sinirli
// kapasiteler tanimlar. Sifir ya da negatif bir alan yapiciyi basarisiz
// kilar (bkz. gorev 10).
type RuntimeLimits struct {
	// FrontendEventBuffer, RegisterForwardedOperation/SubmitSyntheticError
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

// lifecycleState, ExtendedRuntime'in yasam dongusu asamalaridir (bkz.
// gorev 8).
type lifecycleState int32

const (
	lifecycleCreated lifecycleState = iota
	lifecycleRunning
	lifecycleStopping
	lifecycleStopped
)

// --- Olay modeli --------------------------------------------------------

type frontendEventKind int

const (
	frontendEventRegister frontendEventKind = iota + 1
	frontendEventSynthetic
)

// frontendEvent, RegisterForwardedOperation/SubmitSyntheticError
// tarafindan olusturulan, degismez bir istek goruntusudur. ack, kapasitesi
// 1 olan tamponlu bir kanaldir: cagiranin ctx'i olay kabul edildikten
// SONRA ama sonuc alinmadan ONCE iptal edilirse, olay isleyici
// goroutine'inin (event loop) gonderim sirasinda asla bloklanmamasini
// (dolayisiyla sizinti olusmamasini) saglar (bkz. gorev 4).
type frontendEvent struct {
	kind  frontendEventKind
	op    protocol.PendingOperation // yalnizca frontendEventRegister icin
	cycle protocol.CycleID          // yalnizca frontendEventSynthetic icin
	frame []byte                    // yalnizca frontendEventSynthetic icin, cagirandan bagimsiz kopya
	ack   chan frontendAck
}

type frontendAck struct {
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
// Query Protocol calisma zamanidir. Tam olarak bir
// protocol.ResponseSequencer'a sahiptir; Run icindeki TEK event-loop
// goroutine'i istemciye yazan TEK bileşendir; ayri bir backend-okuyucu
// goroutine'i sinirli (bounded) kanallar araciligiyla olay besler.
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
}

// NewExtendedRuntime, verilen State uzerinde calisan yeni bir
// ExtendedRuntime olusturur. state/backend/client nil olamaz;
// runtimeLimits'in tum alanlari pozitif olmalidir; sequencerLimits,
// protocol.NewResponseSequencer'in kendi dogrulama kurallarina tabidir.
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
// io.Reader/io.Writer cagrisini kesemez (bkz. gorev 8). Bu yuzden Run,
// hem ctx iptalinde hem de kendi ic hata yollarinda, geri donmeden once
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

// RegisterForwardedOperation, State uzerinde onceden olusturulmus bir
// islemi sequencer'in response-plan'ina kaydeder. Yalnizca Run
// aktifken gecerlidir; Run'dan once cagrilirsa ANINDA ErrNotRunning,
// runtime durduktan/durma surecindeyken cagrilirsa ErrRuntimeStopped
// doner - hicbir durumda sonsuza kadar bloklanmaz.
//
// Basari yalnizca su ADIMLARIN TUMU tamamlandiktan sonra bildirilir: (1)
// event loop istegi kabul etti, (2) ResponseSequencer islemi kabul etti,
// (3) o kabulun ANINDA urettigi tum OutputAction'lar tam olarak
// islendi (istemciye yazildi). Gelecekteki bir frontend cagiran, ancak bu
// basari donduktan SONRA orijinal frontend baytlarini upstream'e
// yazmalidir (kayit-once-iletim sozlesmesi).
//
// Sequencer'in kendisi islemi REDDEDERSE (ör. yinelenen kayit, engellenmis
// cycle, kaynak siniri) bu, sequencer'in KENDI sozlesmesi geregi HICBIR
// mutasyon uygulanmadigi anlamina gelir - runtime saglikli kalir, hata
// oldugu gibi cagirana dondurulur ve cagiran (gelecekteki entegrasyonda)
// frontend baytlarini KESINLIKLE upstream'e YAZMAMALIDIR. Bu, backend'den
// gelen bir mesajin sequencer tarafindan reddedilmesinden (bkz.
// ErrBackendProtocolFailure, HER ZAMAN runtime'i kalici olarak sonlandirir)
// BILINCLI olarak farklidir: oradaki hata gercek sunucuyla senkronizasyonun
// artik guvenilir olmadigini gosterirken, buradaki hata yalnizca yerel bir
// kayit isteginin reddidir.
func (r *ExtendedRuntime) RegisterForwardedOperation(ctx context.Context, op protocol.PendingOperation) error {
	ack := make(chan frontendAck, 1)
	return r.submit(ctx, frontendEvent{kind: frontendEventRegister, op: op, ack: ack})
}

// SubmitSyntheticError, backend'e hic iletilmemis bir ErrorResponse
// cercevesini belirtilen cycle icin sequencer'a sunar. frame, cagirandan
// BAGIMSIZ bir kopya olarak saklanir (cagiran, gonderdikten sonra kendi
// slice'ini guvenle mutasyona ugratabilir). Dondurme/hata semantikleri
// RegisterForwardedOperation ile birebir aynidir.
func (r *ExtendedRuntime) SubmitSyntheticError(ctx context.Context, cycle protocol.CycleID, frame []byte) error {
	ack := make(chan frontendAck, 1)
	copied := append([]byte(nil), frame...)
	return r.submit(ctx, frontendEvent{kind: frontendEventSynthetic, cycle: cycle, frame: copied, ack: ack})
}

// submit, hem RegisterForwardedOperation hem SubmitSyntheticError
// tarafindan paylasilan gonderim/geri-bildirim mantigidir. Kanal
// tukenmesi karsisinda geri basinc uygular: kapasite acilana, cagiranin
// ctx'i iptal edilene ya da runtime sonlanana kadar bloklar (bkz. gorev
// 4). Public metotlar HICBIR ZAMAN runtime'a ait kanallari kapatmaz.
func (r *ExtendedRuntime) submit(ctx context.Context, ev frontendEvent) error {
	switch lifecycleState(r.lifecycle.Load()) {
	case lifecycleCreated:
		return ErrNotRunning
	case lifecycleStopping, lifecycleStopped:
		return ErrRuntimeStopped
	}

	select {
	case r.frontendEvents <- ev:
	case <-ctx.Done():
		return ctx.Err()
	case <-r.stopped:
		return ErrRuntimeStopped
	}

	select {
	case ack := <-ev.ack:
		return ack.err
	case <-ctx.Done():
		return ctx.Err()
	case <-r.stopped:
		return ErrRuntimeStopped
	}
}

// --- Backend okuyucu ------------------------------------------------------

// runBackendReader, backend'den okur, protocol.NewServerDecoder ile
// cozumler ve her decode edilen protocol.Message'i backendEvents'e
// gonderir (bkz. gorev 5). Tek bir sabit boyutlu okuma tamponu kullanir
// (mesaj basina goroutine YOKTUR), istemciye asla yazmaz,
// ResponseSequencer'i asla dogrudan cagirmaz ve protocol.State'i asla
// dogrudan mutasyona ugratmaz.
//
// Gelecekteki canli entegrasyon notu: startup/authentication mesajlari bu
// runtime uzerinden YENIDEN yonlendirilmez - bu bileşen yalnizca
// authentication ele gecmesi TAMAMLANDIKTAN sonra, mevcut (degismemis)
// Gate/Transformer akisinin devrettigi noktadan itibaren calismak uzere
// tasarlanmistir. Eger bu decoder'a (beklenmedik bicimde) bir
// Authentication/BackendKeyData mesaji ulasirsa, BackendCorrelator bunu
// zaten ErrWrongBackendPhase ile fail-closed reddeder (bkz.
// extended_correlation.go) - bu runtime ek bir ozel durum eklemez.
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
				r.sendBackendEvent(ctx, backendEvent{kind: backendEventEOF})
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
// ctx.Done() uzerinde secim yapar. ResponseSequencer'i ASLA eszamanli
// (concurrent) cagirmaz - her olay tam olarak islenene kadar bir
// sonrakine gecilmez.
func (r *ExtendedRuntime) loop(ctx context.Context) error {
	for {
		select {
		case ev := <-r.frontendEvents:
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
	var actions []protocol.OutputAction
	var seqErr error
	switch ev.kind {
	case frontendEventRegister:
		actions, seqErr = r.seq.AddForwardedOperation(ev.op)
	case frontendEventSynthetic:
		actions, seqErr = r.seq.AddSyntheticError(ev.cycle, ev.frame)
	}
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

func (r *ExtendedRuntime) handleBackendEvent(ev backendEvent) (stop bool, err error) {
	switch ev.kind {
	case backendEventMessage:
		actions, seqErr := r.seq.HandleBackendMessage(ev.msg)
		if seqErr != nil {
			return false, fmt.Errorf("%w: %w", ErrBackendProtocolFailure, seqErr)
		}
		return false, r.processActions(actions)
	case backendEventDecodeError:
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
// VARSAYMAZ (bkz. gorev 7). (0, nil) donen bir Write, ilerleme
// kaydedilmedigi icin bir hata olarak ele alinir (ErrNoProgress).
// action.Bytes hicbir zaman mutasyona ugratilmaz (yalnizca okunur).
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

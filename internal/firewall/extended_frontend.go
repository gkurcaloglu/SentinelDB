// Bu dosya, opt-in, steady-state (post-authentication) bir Extended Query
// Protocol frontend köprüsü (ExtendedFrontend) ve onu bir client
// bağlantısına bağlayan Gate.RunExtended giriş noktasını içerir.
//
// KAPSAM: bu, SentinelDB'nin ALTINCI Extended Query aşamasıdır - decode
// edilmiş steady-state frontend mesajlarını (Parse/Bind/Describe/Execute/
// Close/Flush/Sync/Terminate) tüketir, Parse-zamanlı politika denetimi
// uygular, izin verilen işlemleri internal/gateway.ExtendedRuntime
// aracılığıyla kaydedip upstream'e iletir, yerel reddetmelerde sentetik
// ErrorResponse üretir ve client-facing discard-until-Sync'i uygular.
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
	"fmt"
	"io"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/gateway"
	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// --- Sabit hata kategorileri ------------------------------------------
//
// Hiçbiri ham baytlar, SQL metni, Bind parametre değerleri, statement/
// portal adları ya da sunucu hata metni İÇERMEZ.
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
	// decoder'i kurtarilamaz bir cerceveleme hatasiyla karsilastiginda
	// kullanilir - HER ZAMAN fail-closed'dir.
	ErrExtendedFrontendDecodeFailed = errors.New("firewall: Extended Query frontend cercevesi ayristirilamadi")
	// ErrExtendedFrontendReadFailed, RunExtended client baglantisindan
	// EOF-DISI bir hata ile karsilastiginda kullanilir.
	ErrExtendedFrontendReadFailed = errors.New("firewall: Extended Query frontend baglantisindan okuma basarisiz")
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
// mesajlarini tuketen, Parse-zamanli politika denetimi uygulayan ve izin
// verilen islemleri internal/gateway.ExtendedRuntime araciligiyla kaydedip
// upstream'e ileten opt-in bir koprudur (bkz. dosya basi yorumu).
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
	discardCycle protocol.CycleID

	// err/terminated, ExtendedFrontend'in kalici olarak sonlandigini
	// (ve varsa nedenini) kaydeder - Gate.Run'in kendi g.err alaniyla
	// AYNI desen (bkz. gate.go). TEK goroutine tarafindan erisildigi icin
	// senkronizasyona ihtiyac yoktur.
	err        error
	terminated bool
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
// fonksiyonun kapsami DISINDADIR (bkz. protocol.NewSteadyStateClientDecoder).
//
// Donus semantigi Gate.Run ile AYNI kuralı izler: temiz bir client EOF ya
// da basarili bir client-baslatilan Terminate nil doner; okuma hatalari,
// decoder cerceveleme hatalari ve desteklenmeyen steady-state mesajlari
// (bkz. gorev 13) kendi sabit, guvenli hatalarini dondurur. RunExtended
// KESINLIKLE istemciye bayt yazmaz - tum client-bound cerceveler
// MUNHASIRAN runtime'in event-loop yazicisi araciligiyla gider (bkz.
// gorev 14).
func (g *Gate) RunExtended(ctx context.Context, client io.Reader, frontend *ExtendedFrontend) error {
	if frontend == nil {
		return ErrNilExtendedFrontend
	}

	dec := protocol.NewSteadyStateClientDecoder(
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
				frontend.closeClean(ctx)
			} else {
				frontend.closeReadError(ctx, readErr)
			}
			return frontend.terminalError()
		}
	}
}

// --- ExtendedFrontend ic durum yonetimi -----------------------------------

func (f *ExtendedFrontend) isTerminal() bool     { return f.terminated }
func (f *ExtendedFrontend) terminalError() error { return f.err }
func (f *ExtendedFrontend) discarding() bool     { return f.discardCycle != protocol.NoCycle }

// terminate, ExtendedFrontend'i KALICI olarak sonlandirir (TAM OLARAK BIR
// KEZ - sonraki cagrilar no-op'tur, ILK neden kazanir) ve runtime'i
// NotifyFrontendClosed araciligiyla haberdar eder (bkz. gorev 7) - boylece
// runtime sonsuza kadar bir sonraki frontend olayini beklemez. Runtime'in
// KENDI donus degeri burada yoksayilir (best-effort bildirim): runtime
// zaten baska bir nedenle sonlanmis olabilir, bu ExtendedFrontend'in
// KENDI sonucunu (cause) etkilemez.
func (f *ExtendedFrontend) terminate(ctx context.Context, reason gateway.FrontendCloseReason, cause error) {
	if f.terminated {
		return
	}
	f.terminated = true
	f.err = cause
	_ = f.runtime.NotifyFrontendClosed(ctx, reason, cause)
}

// markTerminatedCleanly, ExtendedFrontend'i hata OLMADAN sonlandirir (ör.
// basarili bir client-baslatilan Terminate sonrasi - bkz. handleTerminate).
func (f *ExtendedFrontend) markTerminatedCleanly() {
	f.terminated = true
}

func (f *ExtendedFrontend) closeClean(ctx context.Context) {
	if f.terminated {
		return
	}
	f.terminated = true
	_ = f.runtime.NotifyFrontendClosed(ctx, gateway.FrontendClosedEOF, nil)
}

func (f *ExtendedFrontend) closeReadError(ctx context.Context, readErr error) {
	if f.terminated {
		return
	}
	wrapped := fmt.Errorf("%w: %v", ErrExtendedFrontendReadFailed, readErr)
	f.terminated = true
	f.err = wrapped
	_ = f.runtime.NotifyFrontendClosed(ctx, gateway.FrontendClosedReadError, readErr)
}

func (f *ExtendedFrontend) handleDecodeError(ctx context.Context, err error) {
	if f.terminated {
		return
	}
	wrapped := fmt.Errorf("%w: %v", ErrExtendedFrontendDecodeFailed, err)
	f.terminate(ctx, gateway.FrontendClosedProtocolError, wrapped)
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

// --- Mesaj dagitimi (bkz. gorev 9, 11, 12, 13) ------------------------------

// handle, protocol.NewSteadyStateClientDecoder'in senkron handler geri
// cagirisidir - Gate.RunExtended'in TEK okuma goroutine'inden cagirilir.
func (f *ExtendedFrontend) handle(ctx context.Context, m protocol.Message) {
	if f.terminated {
		return
	}

	// Sync/Terminate discard durumundan BAGIMSIZ HER ZAMAN islenir (bkz.
	// gorev 11: "Still honor: Sync... Terminate: forward immediately and
	// terminate").
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
	// fail-closed reddedilir (bkz. gorev 13).
	switch m.Type {
	case protocol.MsgParse, protocol.MsgBind, protocol.MsgDescribe, protocol.MsgExecute, protocol.MsgClose, protocol.MsgFlush:
		// devam
	default:
		f.terminate(ctx, gateway.FrontendClosedProtocolError, fmt.Errorf("%w: %s", ErrExtendedFrontendUnsupportedMessage, m.Name))
		return
	}

	if f.discarding() {
		// bkz. gorev 11: discard sirasinda Parse/Bind/Describe/Execute/
		// Close/Flush hicbir isleme (ayristirma/politika/kayit/iletim)
		// tabi tutulmadan sessizce dusurulur.
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

// handleParse, TEK Parse-zamanli politika denetim noktasidir (bkz. gorev 8).
func (f *ExtendedFrontend) handleParse(ctx context.Context, m protocol.Message) {
	if m.Parse == nil {
		// Savunma amacli: gercek decoder-beslenen akiste bu HICBIR ZAMAN
		// olusmaz (protocol.Decoder, MsgParse'i govde basarili sekilde
		// ayristirilmadan asla emit etmez) - yalnizca dogrudan Message
		// insa eden testler icin ulasilabilir bir daldir.
		f.rejectLocally(ctx, sqlStateProtocolError, reasonMalformedBody)
		return
	}

	policyMsg := protocol.Message{Direction: protocol.Frontend, Type: protocol.MsgParse, Name: "Parse", Query: m.Parse.Query}
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
		StatementName: m.Parse.StatementName,
		Query:         m.Parse.Query,
		ParamOIDs:     m.Parse.ParamOIDs,
	}
	f.registerAndForward(ctx, req, m)
}

func (f *ExtendedFrontend) handleBind(ctx context.Context, m protocol.Message) {
	if m.Bind == nil {
		f.rejectLocally(ctx, sqlStateProtocolError, reasonMalformedBody)
		return
	}
	req := gateway.FrontendOperationRequest{
		Kind:          protocol.OpBind,
		PortalName:    m.Bind.PortalName,
		StatementName: m.Bind.StatementName,
		ParamFormats:  m.Bind.ParamFormats,
		ParamNulls:    bindParamNulls(m.Bind.Params),
		ResultFormats: m.Bind.ResultFormats,
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

func (f *ExtendedFrontend) handleDescribe(ctx context.Context, m protocol.Message) {
	if m.Describe == nil {
		f.rejectLocally(ctx, sqlStateProtocolError, reasonMalformedBody)
		return
	}
	req := gateway.FrontendOperationRequest{Kind: protocol.OpDescribeStatement}
	if m.Describe.Target == protocol.TargetPortal {
		req.Kind = protocol.OpDescribePortal
		req.PortalName = m.Describe.Name
	} else {
		req.StatementName = m.Describe.Name
	}
	f.registerAndForward(ctx, req, m)
}

func (f *ExtendedFrontend) handleExecute(ctx context.Context, m protocol.Message) {
	if m.Execute == nil {
		f.rejectLocally(ctx, sqlStateProtocolError, reasonMalformedBody)
		return
	}
	req := gateway.FrontendOperationRequest{Kind: protocol.OpExecute, PortalName: m.Execute.PortalName}
	f.registerAndForward(ctx, req, m)
}

func (f *ExtendedFrontend) handleClose(ctx context.Context, m protocol.Message) {
	if m.Close == nil {
		f.rejectLocally(ctx, sqlStateProtocolError, reasonMalformedBody)
		return
	}
	req := gateway.FrontendOperationRequest{Kind: protocol.OpCloseStatement}
	if m.Close.Target == protocol.TargetPortal {
		req.Kind = protocol.OpClosePortal
		req.PortalName = m.Close.Name
	} else {
		req.StatementName = m.Close.Name
	}
	f.registerAndForward(ctx, req, m)
}

// handleFlush, hicbir State/sequencer mutasyonu yapmadan Flush'i
// ExtendedRuntime.ForwardFlush araciligiyla upstream'e iletir (bkz.
// gorev 6/9). Bu yol icin runtime tarafindan bildirilen HERHANGI bir hata
// - gercek decoder-beslenen akiste bu HICBIR ZAMAN olusmaz, cerceve zaten
// gecerlidir - fail-closed olarak ele alinir (Flush'in "yerel ret +
// discard" kavramsal karsiligi yoktur).
func (f *ExtendedFrontend) handleFlush(ctx context.Context, m protocol.Message) {
	if err := f.runtime.ForwardFlush(ctx, m.Raw); err != nil {
		f.terminate(ctx, gateway.FrontendClosedProtocolError, err)
	}
}

// handleTerminate, discard durumundan BAGIMSIZ HER ZAMAN cagrilir (bkz.
// gorev 6/11). Basarili iletimden SONRA bridge kendi tarafini HATASIZ
// (temiz) olarak sonlandirir - runtime'in KENDI ic sonlanma nedeni (bkz.
// ErrFrontendTerminateRequested) RunExtended'in donus degerini ETKILEMEZ;
// Gate.Run'in temiz-EOF sozlesmesiyle TUTARLI olarak RunExtended nil doner.
func (f *ExtendedFrontend) handleTerminate(ctx context.Context, m protocol.Message) {
	if f.terminated {
		return
	}
	if err := f.runtime.ForwardTerminate(ctx, m.Raw); err != nil {
		f.terminate(ctx, gateway.FrontendClosedProtocolError, err)
		return
	}
	f.markTerminatedCleanly()
}

// handleSync, discard durumundan BAGIMSIZ HER ZAMAN cagrilir (bkz. gorev
// 11, "Still honor: Sync"). Basarili kayit/iletimden sonra, eger bridge
// discard modundaysa, dondurulen CycleID'nin bridge'in kaydettigi
// engellenmis cycle ile TAM OLARAK eslesmesi GEREKIR - eslesmezse bu
// imkansiz bir sahiplik/sira ihlalidir ve fail-closed sonlanir.
func (f *ExtendedFrontend) handleSync(ctx context.Context, m protocol.Message) {
	if f.terminated {
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

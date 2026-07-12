package protocol

import (
	"encoding/binary"
	"errors"
)

// Bu dosya, PostgreSQL Extended Query Protocol'u icin bir BACKEND-YANIT
// KORELATORU (BackendCorrelator) tanimlar. Bu SADECE saf, deterministik bir
// bilesendir:
//
//   - baglanti-yereldir (connection-local)
//   - tek bir *protocol.State ornegine sahiptir (paylasilan global durum
//     yoktur)
//   - hicbir G/C (I/O) yapmaz, hicbir goroutine/kanal kullanmaz, hicbir sey
//     loglamaz
//   - ham backend cerceve baytlarini, SQL metnini ya da Bind parametre
//     degerlerini ASLA saklamaz
//   - gelecekteki tek bir sequencer goroutine'i tarafindan SIRALI
//     cagrilmak uzere tasarlanmistir
//   - yalnizca bagimsiz DEGER goruntuleri (snapshot) dondurur
//
// masking.Transformer, firewall.Gate ya da cmd/gateway'e HENUZ BAGLI
// DEGILDIR. SentinelDB, calisma zamaninda Extended Query mesajlarini hala
// fail-closed reddeder (bkz. internal/firewall/gate.go,
// isExtendedProtocolMessage). Bu dosya yalnizca ileriki asamalarin
// (bkz. docs/design/0001-extended-query.md, "Implementation decomposition",
// asama 3) uzerine insa edecegi bagimsiz bir yapi tasidir.
//
// Kaynak: https://www.postgresql.org/docs/current/protocol-flow.html ve
// https://www.postgresql.org/docs/current/protocol-message-formats.html.

// --- Sabit, guvenli hata kategorileri --------------------------------------
//
// Bu paketteki digerleriyle ayni ilke: hicbir hata SQL metni, Bind
// parametre degeri, ham protokol baytlari, sunucu ErrorResponse metni,
// CommandComplete etiketi ya da sinirsiz istemci/sunucu-saglanan veri
// icermez.
var (
	ErrNilCorrelatorState            = errors.New("extendedcorrelation: nil State ile korelator olusturulamaz")
	ErrNoPendingOperation            = errors.New("extendedcorrelation: bekleyen islem yok")
	ErrWrongBackendPhase             = errors.New("extendedcorrelation: yanlis backend fazi (startup/auth mesaji ya da yon)")
	ErrMalformedBackendMessage       = errors.New("extendedcorrelation: bozuk backend mesaji")
	ErrDuplicateDescribeIntermediate = errors.New("extendedcorrelation: yinelenen ParameterDescription")
	ErrMissingParameterDescription   = errors.New("extendedcorrelation: RowDescription/NoData'dan once ParameterDescription eksik")
	ErrUnsupportedCopyResponse       = errors.New("extendedcorrelation: COPY protokolu desteklenmiyor")
	ErrImpossibleBackendOrdering     = errors.New("extendedcorrelation: imkansiz backend mesaj sirasi")
)

// NOT: ErrErrorResponseForSync kasitli olarak KALDIRILDI. PostgreSQL,
// Sync'in KENDISI islenirken bir hata olustugunda su sirayla mesaj
// gonderebilir: Sync -> ErrorResponse -> ReadyForQuery. Bu, discard-until-
// Sync davranisini BASLATMAZ (islenen mesaj zaten Sync'in kendisidir) ve
// PostgreSQL yine de o Sync icin TAM OLARAK bir ReadyForQuery gonderir.
// Bu yuzden Sync bekleyen kuyruk basiyken gelen yapisal olarak gecerli bir
// ErrorResponse artik GECERLI (fail-closed olmayan) bir durumdur - bkz.
// handleErrorResponse.

// CorrelationResult, tek bir backend Message'in korelasyon sonucudur.
// YALNIZCA sinirli, guvenli metadata tasir - ham cerceve baytlari, SQL
// metni, statement/portal adlari, Bind parametre degerleri, ErrorResponse
// metni, CommandComplete etiketi ya da sinirsiz sunucu string'leri ASLA
// icermez. Cagiran taraf, orijinal protocol.Message'a zaten sahiptir ve
// Raw baytlarinin nasil iletilecegine (relay) kendisi karar verir - bu
// yapi o karari VERMEZ, yalnizca bilgilendirir.
type CorrelationResult struct {
	// MessageType, islenen backend mesajinin etiketidir.
	MessageType MessageType

	// Async true ise mesaj eszamansizdir (NoticeResponse/ParameterStatus/
	// NotificationResponse) - hicbir bekleyen islemi tuketmez/tamamlamaz.
	Async bool
	// Intermediate true ise mesaj, bekleyen islemin basini TUKETMEDEN
	// (kuyruktan cikarmadan) bir ara adimi temsil eder (ör. DataRow,
	// ParameterDescription).
	Intermediate bool
	// OperationCompleted true ise bekleyen islemin basi bu mesajla
	// (basariyla ya da ErrorResponse ile) kuyruktan cikarildi.
	OperationCompleted bool
	// CycleCompleted true ise bu mesaj (yalnizca ReadyForQuery) bir cycle'i
	// tamamladi.
	CycleCompleted bool
	// IsErrorResponse true ise mesaj gercek bir backend ErrorResponse'udur.
	IsErrorResponse bool

	// OperationID/OperationKind/CycleID, OperationCompleted ya da
	// Intermediate true oldugunda, etkilenen islemin (islenmeden ONCEKI
	// kuyruk basi) degismez kimligidir.
	OperationID   PendingOperationID
	OperationKind OperationKind
	CycleID       CycleID

	// CompletedCycleID, yalnizca CycleCompleted true oldugunda anlamlidir.
	CompletedCycleID CycleID

	// FailedOperation, yalnizca IsErrorResponse true VE OperationKind Sync
	// DEGILKEN doldurulur (Sync'in kendi hatasi - bkz. asagidaki
	// "Sync -> ErrorResponse" notu - hicbir islemi "basarisiz" saymaz,
	// yalnizca bir ara adimdir): gercekten basarisiz olan islemin
	// bagimsiz, GUVENLI (isim icermeyen) bir goruntusudur.
	FailedOperation CorrelatedOperation
	// AbandonedOperations, yalnizca IsErrorResponse true VE ayni cycle'da
	// daha sonraki islemler varsa doldurulur: PostgreSQL'in bu noktadan
	// sonra o cycle'in Sync'ine kadar sessizce yok saydigi - ve bu yuzden
	// HICBIR ZAMAN bir onay almayacak olan - islemlerin bagimsiz, GUVENLI
	// (isim icermeyen) goruntuleridir.
	AbandonedOperations []CorrelatedOperation
}

// CorrelatedOperation, bir PendingOperation'in GUVENLI (istemci-saglanan ad
// icermeyen) bir goruntusudur. CorrelationResult'in disari sizdirdigi TEK
// islem-goruntusu turudur - PendingOperation'in kendisi (ör.
// protocol.State.PendingOperations() araciligiyla) TargetName alanini
// tasidigindan, dogrudan disari verilmez. State'in kendi PendingOperation
// modeli DEGISMEDEN kalir; bu yalnizca korelator sinirinda uygulanan bir
// gecis (sanitization) turudur.
type CorrelatedOperation struct {
	ID    PendingOperationID
	Cycle CycleID
	Kind  OperationKind
	// TargetGeneration, bu islemin olusturdugu/referans verdigi
	// generation'in degismez ID'sidir - ISIM DEGIL, yalnizca sayisal bir
	// kimlik (bkz. dosya basi "YALNIZCA sinirli, guvenli metadata").
	TargetGeneration GenerationID
}

// sanitizeOperation, bir State PendingOperation goruntusunu, TargetName'i
// (istemci-saglanan statement/portal adi) ATARAK guvenli bir
// CorrelatedOperation'a donusturur.
func sanitizeOperation(op PendingOperation) CorrelatedOperation {
	return CorrelatedOperation{ID: op.ID, Cycle: op.Cycle, Kind: op.Kind, TargetGeneration: op.TargetGeneration}
}

// sanitizeOperations, sanitizeOperation'i bagimsiz bir dilim uzerinde
// uygular - donen dilim, girdi dilimiyle hicbir backing array paylasmaz.
func sanitizeOperations(ops []PendingOperation) []CorrelatedOperation {
	out := make([]CorrelatedOperation, len(ops))
	for i, op := range ops {
		out[i] = sanitizeOperation(op)
	}
	return out
}

// BackendCorrelator, decode edilmis backend protocol.Message degerlerini
// kabul eden, bekleyen Extended Query islemini belirleyen, backend yanit
// seklini dogrulayan, dogru gecisi *State'e uygulayan ve gelecekteki bir
// yanit sequencer'i icin guvenli, tipli korelasyon metadata'si dondüren
// baglanti-yerel bir bilesendir.
//
// Concurrency: State gibi, BackendCorrelator da tek bir goroutine
// tarafindan sirali cagrilmak uzere tasarlanmistir - dahili hicbir
// kilitleme yapmaz.
type BackendCorrelator struct {
	state *State

	// describeParamSeen, YALNIZCA statement-Describe (OpDescribeStatement)
	// islemleri icin, o TAM PendingOperationID'ye ozel "ParameterDescription
	// zaten gorulduSSSmu" alt-durumunu tasir (bkz. gereksinim: "minimal
	// per-head substate where required"). Bir islem tamamlandiginda,
	// basarisiz olduğunda ya da terk edildiginde (abandoned) bu haritadan
	// HEMEN silinir - hicbir islem sinirini asip kalici hale gelmez.
	describeParamSeen map[PendingOperationID]bool

	// syncErrorSeen, YALNIZCA Sync (OpSync) islemleri icin, o TAM
	// PendingOperationID'ye ozel "bu Sync icin zaten yapisal olarak
	// gecerli bir ErrorResponse gorulduSSSmu" alt-durumunu tasir (bkz.
	// handleErrorResponse - "Sync -> ErrorResponse -> ReadyForQuery"
	// sirasi PostgreSQL'de gecerlidir, discard-until-Sync baslatmaz, ve
	// Sync kuyruk basindan HIC cikarilmaz). Bir sonraki ikinci
	// ErrorResponse "imkansiz backend sirasi" olarak reddedilir - bu
	// yuzden HANGI Sync icin zaten bir ErrorResponse gorulduğu izlenmelidir.
	// Karsilik gelen ReadyForQuery o Sync'i basariyla tamamladiginda bu
	// haritadan HEMEN silinir.
	syncErrorSeen map[PendingOperationID]bool
}

// NewBackendCorrelator, verilen *State'i kullanan yeni bir
// BackendCorrelator olusturur. state nil ise hata doner.
func NewBackendCorrelator(state *State) (*BackendCorrelator, error) {
	if state == nil {
		return nil, ErrNilCorrelatorState
	}
	return &BackendCorrelator{
		state:             state,
		describeParamSeen: make(map[PendingOperationID]bool),
		syncErrorSeen:     make(map[PendingOperationID]bool),
	}, nil
}

// backendBody, bir backend Message'in tag(1)+length(4) sonrasindaki
// govdesini dondurur. Cagiran, Handle icinde len(m.Raw) >= 5 oldugunu zaten
// dogrulamis olmalidir.
func backendBody(m Message) []byte {
	return m.Raw[5:]
}

// Handle, tek bir decode edilmis backend Message'i isler. m.Direction
// Backend olmalidir. Donen CorrelationResult, yalnizca hata nil oldugunda
// anlamlidir.
func (c *BackendCorrelator) Handle(m Message) (CorrelationResult, error) {
	if m.Direction != Backend {
		return CorrelationResult{}, ErrWrongBackendPhase
	}
	if len(m.Raw) < 5 {
		return CorrelationResult{}, ErrMalformedBackendMessage
	}

	switch m.Type {
	case MsgAuthentication, MsgBackendKeyData:
		// Bu korelator yalnizca Extended Query akisi icindir; baslangic/
		// kimlik dogrulama mesajlari kapsam disidir.
		return CorrelationResult{}, ErrWrongBackendPhase

	case MsgNoticeResponse, MsgParameterStatus, MsgNotificationResponse:
		return c.handleAsync(m)

	case MsgCopyInResponse, MsgCopyOutResponse, MsgCopyBothResponse:
		// SentinelDB V1 COPY protokolunu desteklemez; sabit, fail-closed
		// bir korelasyon hatasi doner - hicbir State mutasyonu yapilmaz.
		return CorrelationResult{}, ErrUnsupportedCopyResponse

	case MsgParseComplete:
		return c.handleSimpleTerminal(m, OpParse, true)
	case MsgBindComplete:
		return c.handleSimpleTerminal(m, OpBind, true)
	case MsgCloseComplete:
		return c.handleCloseComplete(m)

	case MsgParameterDescription:
		return c.handleParameterDescription(m)
	case MsgRowDescription:
		return c.handleDescribeResult(m, true)
	case MsgNoData:
		return c.handleDescribeResult(m, false)

	case MsgDataRow:
		return c.handleDataRow(m)
	case MsgCommandComplete:
		return c.handleExecuteTerminal(m, true)
	case MsgEmptyQueryResponse:
		return c.handleExecuteTerminal(m, false)
	case MsgPortalSuspended:
		return c.handleExecuteTerminal(m, false)

	case MsgErrorResponse:
		return c.handleErrorResponse(m)
	case MsgReadyForQuery:
		return c.handleReadyForQuery(m)

	default:
		return CorrelationResult{}, ErrImpossibleBackendOrdering
	}
}

// handleAsync, eszamansiz (uncorrelated) uc backend mesaj turunu isler:
// NoticeResponse, ParameterStatus, NotificationResponse. Govde SEKLI
// (framing) dogrulanir - hicbir mesaj hicbir bekleyen islemi tuketmeden/
// degistirmeden reddedilebilir - ama govde ICERIGI (bildirim metni,
// parametre adi/degeri, kanal adi, payload, PID) hicbir zaman okunup
// disari dondurulmez/saklanmaz; yalnizca NUL sonlandiricilarin/alan
// kodlarinin KONUMLARI incelenir.
func (c *BackendCorrelator) handleAsync(m Message) (CorrelationResult, error) {
	body := backendBody(m)
	var err error
	switch m.Type {
	case MsgNoticeResponse:
		// NoticeResponse, ErrorResponse ile AYNI alan cercevelemesini
		// kullanir (bkz. https://www.postgresql.org/docs/current/protocol-message-formats.html).
		err = validateFieldFraming(body)
	case MsgParameterStatus:
		err = validateParameterStatusFraming(body)
	case MsgNotificationResponse:
		err = validateNotificationResponseFraming(body)
	}
	if err != nil {
		return CorrelationResult{}, err
	}
	return CorrelationResult{MessageType: m.Type, Async: true}, nil
}

// requireHead, kuyruk basinin var oldugunu ve "want" kumesinden birine ait
// oldugunu dogrular; State'i degistirmez.
func (c *BackendCorrelator) requireHead(mismatchErr error, want ...OperationKind) (PendingOperation, error) {
	head, ok := c.state.HeadPendingOperation()
	if !ok {
		return PendingOperation{}, ErrNoPendingOperation
	}
	for _, k := range want {
		if head.Kind == k {
			return head, nil
		}
	}
	return PendingOperation{}, mismatchErr
}

// handleSimpleTerminal, ParseComplete/BindComplete gibi - govdesi bos
// olmasi gereken ve dogrudan bir generation'i "committed" yapan (commit=
// true ise State'in ilgili Apply*Complete metodu cagirilir) terminal
// mesajlari isler.
func (c *BackendCorrelator) handleSimpleTerminal(m Message, kind OperationKind, commit bool) (CorrelationResult, error) {
	if err := validateEmptyBody(backendBody(m)); err != nil {
		return CorrelationResult{}, err
	}
	head, err := c.requireHead(ErrAckKindMismatch, kind)
	if err != nil {
		return CorrelationResult{}, err
	}
	switch kind {
	case OpParse:
		if _, err := c.state.ApplyParseComplete(head.ID); err != nil {
			return CorrelationResult{}, err
		}
	case OpBind:
		if _, err := c.state.ApplyBindComplete(head.ID); err != nil {
			return CorrelationResult{}, err
		}
	}
	_ = commit
	return CorrelationResult{
		MessageType: m.Type, OperationCompleted: true,
		OperationID: head.ID, OperationKind: head.Kind, CycleID: head.Cycle,
	}, nil
}

func (c *BackendCorrelator) handleCloseComplete(m Message) (CorrelationResult, error) {
	if err := validateEmptyBody(backendBody(m)); err != nil {
		return CorrelationResult{}, err
	}
	head, err := c.requireHead(ErrAckKindMismatch, OpCloseStatement, OpClosePortal)
	if err != nil {
		return CorrelationResult{}, err
	}
	if err := c.state.ApplyCloseComplete(head.ID); err != nil {
		return CorrelationResult{}, err
	}
	return CorrelationResult{
		MessageType: m.Type, OperationCompleted: true,
		OperationID: head.ID, OperationKind: head.Kind, CycleID: head.Cycle,
	}, nil
}

// handleParameterDescription, statement-Describe'in ilk (zorunlu) ara
// yanitini isler. Kuyruk basi degistirilmez (Intermediate=true) - yalnizca
// bu TAM PendingOperationID'ye ozel "gorulduSSSmu" alt-durumu isaretlenir.
func (c *BackendCorrelator) handleParameterDescription(m Message) (CorrelationResult, error) {
	if _, err := ParseParameterDescription(backendBody(m)); err != nil {
		return CorrelationResult{}, ErrMalformedBackendMessage
	}
	head, err := c.requireHead(ErrImpossibleBackendOrdering, OpDescribeStatement)
	if err != nil {
		return CorrelationResult{}, err
	}
	if c.describeParamSeen[head.ID] {
		return CorrelationResult{}, ErrDuplicateDescribeIntermediate
	}
	c.describeParamSeen[head.ID] = true
	return CorrelationResult{
		MessageType: m.Type, Intermediate: true,
		OperationID: head.ID, OperationKind: head.Kind, CycleID: head.Cycle,
	}, nil
}

// handleDescribeResult, RowDescription (hasRowDescription=true) ya da
// NoData (false) isler - her ikisi de hem statement-Describe hem de
// portal-Describe icin gecerli terminal yanitlardir, ancak statement-
// Describe icin ONCE bir ParameterDescription gorulmus olmalidir (bkz.
// describeParamSeen); portal-Describe icin ParameterDescription HIC
// GECERLI DEGILDIR (requireHead zaten reddeder, cunku bu fonksiyon
// cagrilmadan once handleParameterDescription farkli bir head.Kind
// bekler).
func (c *BackendCorrelator) handleDescribeResult(m Message, hasRowDescription bool) (CorrelationResult, error) {
	body := backendBody(m)
	if hasRowDescription {
		if _, err := ParseRowDescription(body); err != nil {
			return CorrelationResult{}, ErrMalformedBackendMessage
		}
	} else {
		if err := validateEmptyBody(body); err != nil {
			return CorrelationResult{}, err
		}
	}

	head, err := c.requireHead(ErrImpossibleBackendOrdering, OpDescribeStatement, OpDescribePortal)
	if err != nil {
		return CorrelationResult{}, err
	}
	if head.Kind == OpDescribeStatement && !c.describeParamSeen[head.ID] {
		return CorrelationResult{}, ErrMissingParameterDescription
	}
	if err := c.state.CompleteOperation(head.ID); err != nil {
		return CorrelationResult{}, err
	}
	delete(c.describeParamSeen, head.ID)
	return CorrelationResult{
		MessageType: m.Type, OperationCompleted: true,
		OperationID: head.ID, OperationKind: head.Kind, CycleID: head.Cycle,
	}, nil
}

// handleDataRow, YALNIZCA Execute icin gecerli bir ara mesajdir - kuyruk
// basini asla tuketmez.
func (c *BackendCorrelator) handleDataRow(m Message) (CorrelationResult, error) {
	if _, err := ParseDataRow(backendBody(m)); err != nil {
		return CorrelationResult{}, ErrMalformedBackendMessage
	}
	head, err := c.requireHead(ErrImpossibleBackendOrdering, OpExecute)
	if err != nil {
		return CorrelationResult{}, err
	}
	return CorrelationResult{
		MessageType: m.Type, Intermediate: true,
		OperationID: head.ID, OperationKind: head.Kind, CycleID: head.Cycle,
	}, nil
}

// handleExecuteTerminal, CommandComplete (requireTag=true - etiketin NUL
// ile sonlandigi ve arkasindan bayt gelmedigi dogrulanir, ancak etiket
// ASLA saklanmaz/dondurulmez), EmptyQueryResponse ve PortalSuspended
// (ikisi de bos govdeli, requireTag=false) icin ortak terminal
// isleyicidir - hepsi yalnizca Execute icin gecerlidir.
func (c *BackendCorrelator) handleExecuteTerminal(m Message, requireTag bool) (CorrelationResult, error) {
	body := backendBody(m)
	if requireTag {
		if err := validateCommandCompleteTag(body); err != nil {
			return CorrelationResult{}, err
		}
	} else {
		if err := validateEmptyBody(body); err != nil {
			return CorrelationResult{}, err
		}
	}

	head, err := c.requireHead(ErrImpossibleBackendOrdering, OpExecute)
	if err != nil {
		return CorrelationResult{}, err
	}
	if err := c.state.CompleteOperation(head.ID); err != nil {
		return CorrelationResult{}, err
	}
	return CorrelationResult{
		MessageType: m.Type, OperationCompleted: true,
		OperationID: head.ID, OperationKind: head.Kind, CycleID: head.Cycle,
	}, nil
}

// handleErrorResponse, gercek bir backend ErrorResponse'unu isler:
// kuyruk basindaki islemi basarisiz isaretler VE ayni cycle'daki daha
// sonraki islemleri (o cycle'in kendi Sync'i haric) terk edilmis
// (abandoned) sayar (bkz. State.ApplyErrorResponseAndAbandonCycle).
// handleErrorResponse, gercek bir backend ErrorResponse'unu isler. Iki
// farkli durum vardir:
//
//   - Kuyruk basi Sync ISE: PostgreSQL'in "Sync -> ErrorResponse ->
//     ReadyForQuery" sirasini yansitir - Sync'in KENDISI islenirken bir
//     hata olustugunda gorulur (bkz. https://www.postgresql.org/docs/current/protocol-flow.html,
//     "Extended Query"). Bu durum discard-until-Sync davranisini BASLATMAZ
//     (islenen mesaj zaten Sync'in kendisidir) ve PostgreSQL yine de o
//     Sync icin TAM OLARAK bir ReadyForQuery gonderir. Bu yuzden: Sync ne
//     kuyruktan cikarilir ne de "tamamlanmis" sayilir - yalnizca bir ARA
//     adim olarak isaretlenir (Intermediate=true, OperationCompleted=
//     false) ve karsilik gelen ReadyForQuery, o Sync'i normal sekilde
//     tamamlar. Ayni Sync icin IKINCI bir ErrorResponse imkansiz bir
//     backend sirasidir (reddedilir, State degismez).
//   - Kuyruk basi Sync DEGILSE: State.ApplyErrorResponseAndAbandonCycle
//     cagrilir - kuyruk basindaki islemi basarisiz isaretler VE ayni
//     cycle'daki daha sonraki islemleri (o cycle'in kendi Sync'i haric)
//     terk edilmis (abandoned) sayar.
func (c *BackendCorrelator) handleErrorResponse(m Message) (CorrelationResult, error) {
	if err := validateFieldFraming(backendBody(m)); err != nil {
		return CorrelationResult{}, err
	}
	head, ok := c.state.HeadPendingOperation()
	if !ok {
		return CorrelationResult{}, ErrNoPendingOperation
	}

	if head.Kind == OpSync {
		if c.syncErrorSeen[head.ID] {
			// Ayni Sync icin ikinci bir ErrorResponse - PostgreSQL'in
			// protokolunde bir Sync en fazla bir kez basarisiz "ara adim"
			// bildirimi alabilir (sonrasinda tam olarak bir ReadyForQuery
			// beklenir). Bu, imkansiz bir backend sirasidir.
			return CorrelationResult{}, ErrImpossibleBackendOrdering
		}
		c.syncErrorSeen[head.ID] = true
		return CorrelationResult{
			MessageType: m.Type, IsErrorResponse: true, Intermediate: true,
			OperationID: head.ID, OperationKind: head.Kind, CycleID: head.Cycle,
		}, nil
	}

	failed, abandoned, err := c.state.ApplyErrorResponseAndAbandonCycle(head.ID)
	if err != nil {
		return CorrelationResult{}, err
	}

	// Describe alt-durumu, basarisiz olan VE terk edilen her Describe
	// (statement) islemi icin hemen temizlenir - hicbir islem sinirini
	// asip kalici kalmaz.
	delete(c.describeParamSeen, failed.ID)
	for _, ab := range abandoned {
		delete(c.describeParamSeen, ab.ID)
	}

	return CorrelationResult{
		MessageType: m.Type, IsErrorResponse: true, OperationCompleted: true,
		OperationID: failed.ID, OperationKind: failed.Kind, CycleID: failed.Cycle,
		FailedOperation: sanitizeOperation(failed), AbandonedOperations: sanitizeOperations(abandoned),
	}, nil
}

// handleReadyForQuery, YALNIZCA Sync icin gecerli bir terminal mesajdir;
// State.ApplyReadyForQuery FIFO en-eski-bekleyen-cycle eslestirmesini ve
// islem durumu ('I'/'T'/'E') dogrulamasini kendisi yapar. Bu Sync'e ait,
// korelator-ozel bir Sync-hatasi alt-durumu (bkz. syncErrorSeen) varsa,
// basarili tamamlanmadan hemen sonra temizlenir.
func (c *BackendCorrelator) handleReadyForQuery(m Message) (CorrelationResult, error) {
	body := backendBody(m)
	if len(body) != 1 {
		return CorrelationResult{}, ErrMalformedBackendMessage
	}
	head, err := c.requireHead(ErrAckKindMismatch, OpSync)
	if err != nil {
		return CorrelationResult{}, err
	}
	completedCycle, err := c.state.ApplyReadyForQuery(body[0])
	if err != nil {
		return CorrelationResult{}, err
	}
	delete(c.syncErrorSeen, head.ID)
	return CorrelationResult{
		MessageType: m.Type, OperationCompleted: true, CycleCompleted: true,
		OperationID: head.ID, OperationKind: head.Kind, CycleID: head.Cycle,
		CompletedCycleID: completedCycle,
	}, nil
}

// --- Backend mesaj gecerlilik/ayristirma yardimcilari ----------------------
//
// Bu yardimcilar, mevcut ParseRowDescription/ParseDataRow (bkz.
// internal/protocol/rowdescription.go, datarow.go) ile AYNI disiplini
// izler: guvenilmeyen "wire" verisi uzerinde calisirlar, tampon sinirlarini
// her adimda dogrularlar, hicbir girdide panic etmezler.

// validateEmptyBody, govdenin TAM OLARAK bos olmasini gerektiren backend
// mesajlari (ParseComplete/BindComplete/CloseComplete/NoData/
// EmptyQueryResponse/PortalSuspended) icin kullanilir.
func validateEmptyBody(body []byte) error {
	if len(body) != 0 {
		return ErrMalformedBackendMessage
	}
	return nil
}

// validateCommandCompleteTag, bir CommandComplete govdesinin tam olarak
// tek bir NUL-sonlandirmali komut etiketi icerdigini (NUL'den sonra hicbir
// bayt gelmedigini) dogrular. Etiketin ICERIGI hicbir zaman donulmez/
// saklanmaz - yalnizca sekil dogrulanir.
func validateCommandCompleteTag(body []byte) error {
	idx := -1
	for i, b := range body {
		if b == 0 {
			idx = i
			break
		}
	}
	if idx == -1 {
		return ErrMalformedBackendMessage
	}
	if idx != len(body)-1 {
		return ErrMalformedBackendMessage
	}
	return nil
}

// findCStringEnd, body[offset:] icinde NUL sonlandiricinin MUTLAK (body
// basindan itibaren) index'ini bulur, bulunamazsa -1 doner. Deger ICERIGI
// hicbir zaman okunmaz/donulmez - yalnizca konumu.
func findCStringEnd(body []byte, offset int) int {
	for i := offset; i < len(body); i++ {
		if body[i] == 0 {
			return i
		}
	}
	return -1
}

// validateFieldFraming, ErrorResponse VE NoticeResponse'un PAYLASTIGI
// PostgreSQL alan cercevelemesini dogrular (bkz.
// https://www.postgresql.org/docs/current/protocol-message-formats.html,
// ErrorResponse/NoticeResponse): EN AZ BIR sifir-olmayan alan kodu baytini
// bir NUL-sonlandirmali deger stringi izler, govde tek bir sifir alan-
// kodu baytiyla (son bayt olarak) sonlanir. Yalnizca-terminator (hicbir
// alan icermeyen) bir govde REDDEDILIR - gercek PostgreSQL, en azindan
// 'S'/'V' (severity) ve 'C' (SQLSTATE) alanlarini her zaman gonderir.
// Kapali bir alan-kodu izin listesi ZORUNLU KILINMAZ (PostgreSQL gelecekte
// yeni alan turleri ekleyebilir). HICBIR alan DEGERI (icerigi) okunmaz/
// donulmez/saklanmaz - yalnizca cerceve sekli dogrulanir.
func validateFieldFraming(body []byte) error {
	offset := 0
	sawField := false
	for {
		if offset >= len(body) {
			return ErrMalformedBackendMessage
		}
		fieldCode := body[offset]
		if fieldCode == 0 {
			if !sawField || offset != len(body)-1 {
				return ErrMalformedBackendMessage
			}
			return nil
		}
		sawField = true
		idx := findCStringEnd(body, offset+1)
		if idx == -1 {
			return ErrMalformedBackendMessage
		}
		offset = idx + 1
	}
}

// validateParameterStatusFraming, bir ParameterStatus govdesinin tam
// olarak iki NUL-sonlandirmali string (parametre adi, parametre degeri)
// icerdigini ve arkasindan baska hicbir bayt gelmedigini dogrular.
// Stringlerin ICERIGI hicbir zaman okunmaz/donulmez/saklanmaz.
func validateParameterStatusFraming(body []byte) error {
	firstEnd := findCStringEnd(body, 0)
	if firstEnd == -1 {
		return ErrMalformedBackendMessage
	}
	secondEnd := findCStringEnd(body, firstEnd+1)
	if secondEnd == -1 {
		return ErrMalformedBackendMessage
	}
	if secondEnd != len(body)-1 {
		return ErrMalformedBackendMessage
	}
	return nil
}

// validateNotificationResponseFraming, bir NotificationResponse
// govdesinin Int32(surec kimligi/PID) + NUL-sonlandirmali kanal adi +
// NUL-sonlandirmali payload iceriginden olustugunu ve arkasindan baska
// hicbir bayt gelmedigini dogrular. PID DEGERI ve stringlerin ICERIGI
// hicbir zaman okunmaz/donulmez/saklanmaz.
func validateNotificationResponseFraming(body []byte) error {
	if len(body) < 4 {
		return ErrMalformedBackendMessage
	}
	channelEnd := findCStringEnd(body, 4)
	if channelEnd == -1 {
		return ErrMalformedBackendMessage
	}
	payloadEnd := findCStringEnd(body, channelEnd+1)
	if payloadEnd == -1 {
		return ErrMalformedBackendMessage
	}
	if payloadEnd != len(body)-1 {
		return ErrMalformedBackendMessage
	}
	return nil
}

// ParameterDescription, ayristirilmis bir ParameterDescription ('t')
// mesajinin govdesidir - yalnizca parametre tipi OID'lerini tasir (deger
// degil).
type ParameterDescription struct {
	ParamOIDs []uint32
}

// ParseParameterDescription, bir ParameterDescription mesajinin govdesini
// (tag ve length alanlari haric) ayristirir.
//
// Wire format: Int16(parametre sayisi N) + N x Int32(parametre tipi OID).
//
// Guvenilmeyen "wire" verisi uzerinde calisir: tampon sinirlarini her
// adimda dogrular, hicbir girdide panic etmez. Donen OID dilimi, decoder
// tamponundan bagimsiz TAZE bir tahsistir (asla input "body" dilimini
// yeniden dilimlemez) - cagiran tarafin elinde tuttugu bir referans,
// decoder'in ic tamponuna takma ad (alias) olusturmaz.
func ParseParameterDescription(body []byte) (*ParameterDescription, error) {
	if len(body) < 2 {
		return nil, errParameterDescriptionShape
	}
	count := int(binary.BigEndian.Uint16(body[0:2]))
	offset := 2

	// count, bir Uint16'dan okundugu icin her zaman [0, 65535] araligindadir
	// (negatif olamaz) ve count*4 asla int tasmasina yol acmaz (en fazla
	// 262140).
	if offset+count*4 > len(body) {
		return nil, errParameterDescriptionShape
	}
	oids := make([]uint32, 0, count)
	for i := 0; i < count; i++ {
		oids = append(oids, binary.BigEndian.Uint32(body[offset:offset+4]))
		offset += 4
	}
	if offset != len(body) {
		return nil, errParameterDescriptionShape
	}
	return &ParameterDescription{ParamOIDs: oids}, nil
}

var errParameterDescriptionShape = errors.New("protocol: ParameterDescription govdesi gecersiz")

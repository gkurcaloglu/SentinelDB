package protocol

import (
	"encoding/binary"
	"errors"
)

// ResponseSequencer, Extended Query Protocol icin uc kaynagi birlestirerek
// dogru sirali istemci cikti eylemleri uretir:
//
//  1. Frontend islenmesinden gelen response-plan olaylari (AddForwardedOperation),
//  2. Cozumlenmis backend mesajlari (HandleBackendMessage, ic olarak
//     BackendCorrelator kullanir),
//  3. Yerel olarak uretilen sentetik ErrorResponse cerceveleri (AddSyntheticError).
//
// ResponseSequencer soket G/C yapmaz, goroutine baslatmaz ve gercek gateway
// akisina baglanmaz (bkz. internal/firewall/gate.go, internal/masking/transformer.go,
// cmd/gateway/main.go) - Extended Query calisma zamaninda fail-closed
// reddedilmeye devam eder.
//
// Kayit-once-iletim sozlesmesi (registration-before-forwarding contract):
// bir cagiran, her Extended Query islemi icin su sirayi izlemelidir:
//
//  1. State uzerinde ilgili Create* metodunu cagirarak islemi olustur,
//  2. Donen PendingOperation'i AddForwardedOperation ile sequencer'a kaydet,
//  3. Ancak bundan SONRA orijinal frontend baytlarini backend'e ilet.
//
// Bu sira ihlal edilirse (ör. bir islem State'te olusturulmadan/sequencer'a
// kaydedilmeden backend'e iletilirse), backend'den gelen yanit
// HandleBackendMessage tarafindan plan/State uyusmazligi olarak fail-closed
// reddedilir (bkz. ErrPlanMismatch, ErrNoPendingOperation).
type ResponseSequencer struct {
	correlator *BackendCorrelator
	state      *State
	limits     SequencerLimits

	plan      []*planUnit
	planIndex map[PendingOperationID]*planUnit

	cycleSeenOps    map[CycleID]map[PendingOperationID]bool
	blockedCycles   map[CycleID]bool
	reallyFailed    map[CycleID]bool
	activeCycles    map[CycleID]bool
	cycleTombstones map[CycleID]map[PendingOperationID]bool

	abandonedOps map[PendingOperationID]bool

	highestCompletedCycle CycleID

	terminal bool
}

// PlanUnitKind, bir response-plan biriminin turunu ayirt eder.
type PlanUnitKind int

const (
	// PlanUnitForwardedOperation, State uzerinde olusturulmus gercek bir
	// Extended Query islemine (Parse/Bind/Describe/Execute/Close/Sync)
	// karsilik gelir. Flush ve Terminate icin plan birimi olusturulmaz -
	// Flush'in backend'den bir onayi yoktur, Terminate ise baglantiyi
	// dogrudan sonlandirir.
	PlanUnitForwardedOperation PlanUnitKind = iota + 1
	// PlanUnitSyntheticError, backend'e hic iletilmemis, yerel olarak
	// uretilmis bir ErrorResponse cercevesidir (ör. politika reddi).
	PlanUnitSyntheticError
)

type planUnit struct {
	kind   PlanUnitKind
	opID   PendingOperationID
	opKind OperationKind
	cycle  CycleID
	frame  []byte // yalnizca PlanUnitSyntheticError icin, sequencer'a ait bagimsiz kopya
}

// OutputActionKind, bir OutputAction'in temsil ettigi eylem kategorisidir.
type OutputActionKind int

const (
	// ActionEmitBackendFrame, gercek backend'den gelen dogrulanmis bir
	// cercevenin (veya asenkron bir mesajin) oldugu gibi istemciye
	// iletilmesi gerektigini belirtir.
	ActionEmitBackendFrame OutputActionKind = iota + 1
	// ActionEmitSyntheticFrame, backend'e hic gonderilmemis, yerel olarak
	// uretilmis bir ErrorResponse cercevesinin istemciye iletilmesi
	// gerektigini belirtir.
	ActionEmitSyntheticFrame
	// ActionTerminateConnection, cagiranin cerceveyi (varsa) ilettikten
	// hemen sonra istemci baglantisini sonlandirmasi gerektigini belirtir.
	ActionTerminateConnection
)

// OutputAction, ResponseSequencer'in urettigi tek bir sirali cikti
// eylemidir. Guvenli meta-veri disinda hicbir alan (SQL metni, Bind
// parametre degerleri, statement/portal adi, ham sunucu dizeleri) tasimaz.
type OutputAction struct {
	Kind          OutputActionKind
	MessageType   MessageType
	CycleID       CycleID
	OperationID   PendingOperationID
	OperationKind OperationKind
	Synthetic     bool
	// TargetGeneration, ilgili CorrelationResult'tan aynen kopyalanan,
	// ISIM ICERMEYEN statement/portal generation kimligidir - hangi
	// generation'a ait oldugunu bir yanit maskeleme katmaninin (bkz.
	// internal/masking) belirleyebilmesi icindir. Asenkron/baglanti-
	// seviyesi cerceveler ve TUM sentetik eylemler icin her zaman
	// NoGeneration'dir.
	TargetGeneration GenerationID
	// Bytes, istemciye oldugu gibi iletilecek tam cerceve baytlaridir
	// (tag + uzunluk + govde). ActionTerminateConnection icin nil'dir.
	// Her zaman sequencer'in ic durumundan bagimsiz, cagirana ait bir
	// kopyadir.
	Bytes []byte
}

// SequencerLimits, ResponseSequencer'in sinirsiz bellek buyumesine karsi
// uyguladigi sabit kaynak sinirlaridir. Tum alanlar pozitif olmalidir.
type SequencerLimits struct {
	// MaxPlanUnits, ayni anda kuyrukta bekleyebilecek en fazla plan
	// birimi (forwarded + synthetic) sayisidir.
	MaxPlanUnits int
	// MaxSyntheticFrameBytes, tek bir sentetik ErrorResponse cercevesinin
	// en fazla toplam bayt boyutudur (tag + uzunluk dahil).
	MaxSyntheticFrameBytes int
	// MaxAbandonedTombstones, henuz plan'a kaydedilmemis, gercek backend
	// hatasi tarafindan terk edilmis islem kimlikleri icin tutulan en
	// fazla "tombstone" sayisidir.
	MaxAbandonedTombstones int
	// MaxActiveCycles, ayni anda izlenen en fazla farkli cycle sayisidir.
	MaxActiveCycles int
}

// DefaultSequencerLimits, uretim disi/test amacli makul varsayilan
// sinirlar dondurur.
func DefaultSequencerLimits() SequencerLimits {
	return SequencerLimits{
		MaxPlanUnits:           4096,
		MaxSyntheticFrameBytes: 8192,
		MaxAbandonedTombstones: 4096,
		MaxActiveCycles:        1024,
	}
}

func (l SequencerLimits) validate() error {
	if l.MaxPlanUnits <= 0 || l.MaxSyntheticFrameBytes <= 0 || l.MaxAbandonedTombstones <= 0 || l.MaxActiveCycles <= 0 {
		return ErrInvalidSequencerLimits
	}
	return nil
}

// Sequencer'a ozgu sabit hata kategorileri. Hicbiri protokol govdesi,
// SQL metni, parametre degeri veya istemci tarafindan saglanan isim
// tasimaz.
var (
	ErrInvalidSequencerLimits    = errors.New("extendedsequence: gecersiz sequencer sinirlari (pozitif olmali)")
	ErrInvalidOperationSnapshot  = errors.New("extendedsequence: gecersiz (sifir kimlikli) islem goruntusu")
	ErrDuplicatePlanRegistration = errors.New("extendedsequence: yinelenen plan kaydi")
	ErrOperationAbandoned        = errors.New("extendedsequence: islem zaten terk edilmis, canli olarak kaydedilemez")
	ErrCycleBlocked              = errors.New("extendedsequence: cycle zaten engellenmis durumda")
	ErrSequencerTerminal         = errors.New("extendedsequence: baglanti sonlandirma durumunda, yeni islem kabul edilmiyor")
	ErrPlanQueueFull             = errors.New("extendedsequence: plan kuyrugu sinirina ulasildi")
	ErrActiveCycleLimitExceeded  = errors.New("extendedsequence: aktif cycle izleme sinirina ulasildi")
	ErrSyntheticFrameTooLarge    = errors.New("extendedsequence: sentetik cerceve boyutu sinirini asiyor")
	ErrMalformedSyntheticFrame   = errors.New("extendedsequence: gecersiz sentetik ErrorResponse cercevesi")
	ErrPlanMismatch              = errors.New("extendedsequence: plan basi State bekleyen basiyla uyusmuyor")
	ErrImpossibleCycle           = errors.New("extendedsequence: imkansiz (zaten tamamlanmis) cycle kimligi")
)

// NewResponseSequencer, verilen State uzerinde calisan yeni bir
// ResponseSequencer olusturur. state nil olamaz. limits'in tum alanlari
// pozitif olmalidir.
func NewResponseSequencer(state *State, limits SequencerLimits) (*ResponseSequencer, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	correlator, err := NewBackendCorrelator(state)
	if err != nil {
		return nil, err
	}
	return &ResponseSequencer{
		correlator:      correlator,
		state:           state,
		limits:          limits,
		planIndex:       make(map[PendingOperationID]*planUnit),
		cycleSeenOps:    make(map[CycleID]map[PendingOperationID]bool),
		blockedCycles:   make(map[CycleID]bool),
		reallyFailed:    make(map[CycleID]bool),
		activeCycles:    make(map[CycleID]bool),
		cycleTombstones: make(map[CycleID]map[PendingOperationID]bool),
		abandonedOps:    make(map[PendingOperationID]bool),
	}, nil
}

// AddForwardedOperation, State uzerinde onceden olusturulmus (Create*
// cagrisiyla) bir islemi response-plan kuyruguna kaydeder. op, cagiranin
// State.Create* cagrisindan aldigi tam goruntu olmalidir (yalnizca ID,
// Kind ve Cycle alanlari okunur; TargetName hicbir zaman saklanmaz veya
// disariya yansitilmaz).
//
// Basarili bir kayit hicbir zaman dogrudan cikti eylemi uretmez (yeni
// eklenen birim kuyrugun sonuna gider, bu yuzden mevcut bas asla
// degismez) - bu nedenle donen slice basarili durumda her zaman nil'dir.
func (s *ResponseSequencer) AddForwardedOperation(op PendingOperation) ([]OutputAction, error) {
	if s.terminal {
		return nil, ErrSequencerTerminal
	}
	if op.ID == NoPendingOperation || op.Cycle == NoCycle {
		return nil, ErrInvalidOperationSnapshot
	}
	if op.Cycle <= s.highestCompletedCycle {
		return nil, ErrImpossibleCycle
	}
	if s.abandonedOps[op.ID] {
		return nil, ErrOperationAbandoned
	}
	if op.Kind != OpSync && s.blockedCycles[op.Cycle] {
		return nil, ErrCycleBlocked
	}
	if seen := s.cycleSeenOps[op.Cycle]; seen != nil && seen[op.ID] {
		return nil, ErrDuplicatePlanRegistration
	}
	if len(s.plan) >= s.limits.MaxPlanUnits {
		return nil, ErrPlanQueueFull
	}
	if s.cycleSeenOps[op.Cycle] == nil && len(s.cycleSeenOps) >= s.limits.MaxActiveCycles {
		return nil, ErrActiveCycleLimitExceeded
	}

	unit := &planUnit{kind: PlanUnitForwardedOperation, opID: op.ID, opKind: op.Kind, cycle: op.Cycle}
	s.plan = append(s.plan, unit)
	s.planIndex[op.ID] = unit
	if s.cycleSeenOps[op.Cycle] == nil {
		s.cycleSeenOps[op.Cycle] = make(map[PendingOperationID]bool)
	}
	s.cycleSeenOps[op.Cycle][op.ID] = true
	if op.Kind == OpSync {
		s.activeCycles[op.Cycle] = true
	}
	return nil, nil
}

// AddSyntheticError, backend'e hic iletilmemis bir ErrorResponse
// cercevesini belirtilen cycle icin kuyruga ekler. frame, tam bir
// ErrorResponse cercevesi (tag 'E' + 4 baytlik uzunluk + en az bir alan
// tasiyan govde) olmalidir; aksi halde reddedilir ve hicbir mutasyon
// yapilmaz.
//
// cycle zaten yerel bir sentetik hata veya gercek bir backend hatasi
// tarafindan engellenmisse, cagri sessizce bastirilir (hata donmez, cikti
// uretilmez) - bu, ayni cycle icin ikinci bir sentetik hatanin veya
// gercek backend hatasi tarafindan zaten basarisiz sayilmis bir cycle
// icin gec gelen bir sentetik hatanin nasil ele alinacagina dair tek,
// belgelenmis kuraldir.
func (s *ResponseSequencer) AddSyntheticError(cycle CycleID, frame []byte) ([]OutputAction, error) {
	if s.terminal {
		return nil, ErrSequencerTerminal
	}
	if cycle == NoCycle {
		return nil, ErrInvalidOperationSnapshot
	}
	if cycle <= s.highestCompletedCycle {
		return nil, ErrImpossibleCycle
	}
	if s.blockedCycles[cycle] {
		return nil, nil
	}
	if len(frame) > s.limits.MaxSyntheticFrameBytes {
		return nil, ErrSyntheticFrameTooLarge
	}
	if err := validateSyntheticErrorResponseFrame(frame); err != nil {
		return nil, err
	}
	if len(s.plan) >= s.limits.MaxPlanUnits {
		return nil, ErrPlanQueueFull
	}

	copied := append([]byte(nil), frame...)
	unit := &planUnit{kind: PlanUnitSyntheticError, cycle: cycle, frame: copied}
	s.plan = append(s.plan, unit)
	s.blockedCycles[cycle] = true

	return s.drain(), nil
}

// validateSyntheticErrorResponseFrame, cagiran tarafindan saglanan bir
// sentetik cercevenin tam, tek bir ErrorResponse mesaji oldugunu
// dogrular (baska hicbir mesaj turune, ozellikle ReadyForQuery'ye, izin
// verilmez). Govde icerigi asla saklanmaz; yalnizca cerceveleme
// dogrulanir (bkz. validateFieldFraming).
func validateSyntheticErrorResponseFrame(frame []byte) error {
	if len(frame) < 5 {
		return ErrMalformedSyntheticFrame
	}
	if MessageType(frame[0]) != MsgErrorResponse {
		return ErrMalformedSyntheticFrame
	}
	length := int(binary.BigEndian.Uint32(frame[1:5]))
	if length < 4 {
		return ErrMalformedSyntheticFrame
	}
	if 1+length != len(frame) {
		return ErrMalformedSyntheticFrame
	}
	if err := validateFieldFraming(frame[5:]); err != nil {
		return ErrMalformedSyntheticFrame
	}
	return nil
}

// drain, plan kuyrugunun basinda art arda bekleyen tum sentetik hata
// birimlerini cikarir ve karsilik gelen cikti eylemlerini dondurur.
// Iletilmis (forwarded) bir birim basa geldigi anda durur - iletilmis
// birimler yalnizca HandleBackendMessage araciligiyla kaldirilabilir.
func (s *ResponseSequencer) drain() []OutputAction {
	var actions []OutputAction
	for len(s.plan) > 0 {
		head := s.plan[0]
		if head.kind != PlanUnitSyntheticError {
			break
		}
		s.plan = s.plan[1:]
		actions = append(actions, OutputAction{
			Kind:        ActionEmitSyntheticFrame,
			MessageType: MsgErrorResponse,
			CycleID:     head.cycle,
			Synthetic:   true,
			Bytes:       append([]byte(nil), head.frame...),
		})
	}
	return actions
}

// HasPendingWork, plan kuyrugunda (iletilmis ya da sentetik) cozumlenmeyi
// bekleyen en az bir birim olup olmadigini bildirir. Hicbir birimin
// icerigini disariya yansitmaz - yalnizca bir cagiranin (ör. gelecekteki
// bir calisma zamani bilesenin), backend baglantisinin erken kapanmasinin
// sirali/temiz bir durdurma mi yoksa cozumlenmemis bir sekans ortasinda
// beklenmedik bir kopma mi oldugunu ayirt edebilmesi icin.
func (s *ResponseSequencer) HasPendingWork() bool {
	return len(s.plan) > 0
}

func isAsyncBackendType(t MessageType) bool {
	return t == MsgNoticeResponse || t == MsgParameterStatus || t == MsgNotificationResponse
}

func isCopyBackendType(t MessageType) bool {
	return t == MsgCopyInResponse || t == MsgCopyOutResponse || t == MsgCopyBothResponse
}

// HandleBackendMessage, cozumlenmis tek bir backend mesajini isler ve
// sirali cikti eylemlerini dondurur. m.Direction Backend olmalidir (bu,
// alttaki BackendCorrelator tarafindan dogrulanir).
func (s *ResponseSequencer) HandleBackendMessage(m Message) ([]OutputAction, error) {
	if s.terminal {
		return nil, ErrSequencerTerminal
	}

	if isAsyncBackendType(m.Type) {
		return s.handleAsyncMessage(m)
	}

	if isCopyBackendType(m.Type) {
		_, err := s.correlator.Handle(m)
		return nil, err
	}

	if m.Type == MsgErrorResponse {
		if _, hasHead := s.state.HeadPendingOperation(); !hasHead {
			return s.handleConnectionLevelErrorResponse(m)
		}
	}

	stateHead, hasHead := s.state.HeadPendingOperation()
	if !hasHead {
		return nil, ErrNoPendingOperation
	}
	if len(s.plan) == 0 {
		return nil, ErrPlanMismatch
	}
	planHead := s.plan[0]
	if planHead.kind != PlanUnitForwardedOperation {
		return nil, ErrPlanMismatch
	}
	if planHead.opID != stateHead.ID || planHead.opKind != stateHead.Kind || planHead.cycle != stateHead.Cycle {
		return nil, ErrPlanMismatch
	}

	res, err := s.correlator.Handle(m)
	if err != nil {
		return nil, err
	}

	return s.applyCorrelationResult(m, res), nil
}

func (s *ResponseSequencer) handleAsyncMessage(m Message) ([]OutputAction, error) {
	res, err := s.correlator.Handle(m)
	if err != nil {
		return nil, err
	}
	if !res.Async {
		return nil, ErrImpossibleBackendOrdering
	}
	return []OutputAction{{
		Kind:        ActionEmitBackendFrame,
		MessageType: m.Type,
		Bytes:       append([]byte(nil), m.Raw...),
	}}, nil
}

// handleConnectionLevelErrorResponse, State'te hicbir bekleyen islem
// yokken gelen bir ErrorResponse'u ele alir. Bu, bir istem/yanit
// dongusunun disinda olusan bir baglanti seviyesi backend hatasini
// (ör. sunucu tarafindan baslatilan kapanis) temsil eder. Islem
// olusturmaz veya tuketmez; cerceveyi oldugu gibi iletir ve sequencer'i
// kalici olarak sonlandirma durumuna gecirir.
func (s *ResponseSequencer) handleConnectionLevelErrorResponse(m Message) ([]OutputAction, error) {
	if len(m.Raw) < 5 {
		return nil, ErrMalformedBackendMessage
	}
	if err := validateFieldFraming(m.Raw[5:]); err != nil {
		return nil, err
	}
	s.terminal = true
	return []OutputAction{
		{Kind: ActionEmitBackendFrame, MessageType: MsgErrorResponse, Bytes: append([]byte(nil), m.Raw...)},
		{Kind: ActionTerminateConnection},
	}, nil
}

func (s *ResponseSequencer) applyCorrelationResult(m Message, res CorrelationResult) []OutputAction {
	actions := []OutputAction{
		{
			Kind:             ActionEmitBackendFrame,
			MessageType:      m.Type,
			CycleID:          res.CycleID,
			OperationID:      res.OperationID,
			OperationKind:    res.OperationKind,
			TargetGeneration: res.TargetGeneration,
			Bytes:            append([]byte(nil), m.Raw...),
		},
	}

	switch {
	case res.IsErrorResponse && res.OperationKind == OpSync && !res.OperationCompleted:
		// Sync -> ErrorResponse: ara durum, Sync plan birimi basta kalir.

	case res.CycleCompleted:
		s.popPlanHeadIfMatches(res.OperationID)
		s.finishCycle(res.CompletedCycleID)

	case res.IsErrorResponse:
		if !s.applyRealFailure(res) {
			// Tombstone kapasitesi bu terk-edilme kumesinin tamamini
			// karsilayamiyor: eksik dogruluk durumuyla normal calismaya
			// devam etmek fail-closed garantisini ihlal eder. Gercek
			// ErrorResponse (yukarida zaten eklendi) TAM OLARAK BIR KEZ
			// iletilir, sequencer kalici olarak sonlandirma durumuna
			// gecer ve baska hicbir sey (baska cycle'lardan drain dahil)
			// yayinlanmaz - bu bir kaynak-tukenmesi fail-closed baglanti
			// sonlandirmasidir.
			s.terminal = true
			return append(actions, OutputAction{Kind: ActionTerminateConnection})
		}

	case res.OperationCompleted:
		s.popPlanHeadIfMatches(res.OperationID)

	default:
		// Ara durum (ParameterDescription, DataRow): plan basi degismez.
	}

	actions = append(actions, s.drain()...)
	return actions
}

func (s *ResponseSequencer) popPlanHeadIfMatches(opID PendingOperationID) {
	if len(s.plan) == 0 {
		return
	}
	head := s.plan[0]
	if head.kind != PlanUnitForwardedOperation || head.opID != opID {
		return
	}
	s.plan = s.plan[1:]
	delete(s.planIndex, opID)
}

// applyRealFailure, gercek bir backend ErrorResponse'unun ayni cycle
// icindeki daha sonraki islemleri terk ettirdigi (abandon) durumu
// sequencer tarafinda atomik olarak yansitir. Tombstone kapasitesi bir
// dogruluk (correctness) siniridir, en-iyi-caba (best-effort) bir onbellek
// DEGILDIR: eksik terk-edilmis-islem izlemesiyle normal calismaya devam
// etmek, gec gelen bir AddForwardedOperation cagrisinin zaten terk
// edilmis bir islemi canliymis gibi yanlislikla kabul etmesine izin
// verebilir - bu, fail-closed garantisini ihlal eder.
//
// Once, HICBIR SEY MUTASYONA UGRATILMADAN, kac YENI tombstone
// gerekecegi hesaplanir (zaten kuyrukta bekleyen bir plan birimi olan
// terk edilmis islemler dogrudan kaldirilir, tombstone gerektirmez).
// Bu gereksinim s.limits.MaxAbandonedTombstones'u asarsa, HICBIR
// mutasyon uygulanmadan false donulur - cagiran, sequencer'i kalici
// sonlandirma durumuna gecirmekten sorumludur (bkz. applyCorrelationResult).
// Yalnizca tam tombstone gereksinimi sigarsa, tam gecis atomik olarak
// uygulanir: basarisiz islemin kendi plan birimi kaldirilir, zaten
// kuyruktaki terk edilmis birimler kaldirilir, ayni cycle'daki bekleyen
// sentetik birimler bastirilir ve gereken her tombstone kaydedilir.
func (s *ResponseSequencer) applyRealFailure(res CorrelationResult) bool {
	cycle := res.FailedOperation.Cycle

	abandonedIDs := make(map[PendingOperationID]bool, len(res.AbandonedOperations))
	for _, ab := range res.AbandonedOperations {
		abandonedIDs[ab.ID] = true
	}

	// Salt-okunur asama: hangi terk edilmis kimliklerin zaten kuyrukta
	// bir plan birimi YOK (bu yuzden YENI bir tombstone gerektirir) -
	// hicbir sey mutasyona ugratilmadan belirlenir.
	needsTombstone := make(map[PendingOperationID]bool, len(abandonedIDs))
	for id := range abandonedIDs {
		if _, queued := s.planIndex[id]; !queued {
			needsTombstone[id] = true
		}
	}
	if len(s.abandonedOps)+len(needsTombstone) > s.limits.MaxAbandonedTombstones {
		return false // kapasite yetersiz: hicbir mutasyon uygulanmadi
	}

	// Kapasite yeterli dogrulandi - tam gecisi uygula.
	s.popPlanHeadIfMatches(res.OperationID)
	s.blockedCycles[cycle] = true
	s.reallyFailed[cycle] = true

	remaining := s.plan[:0:0]
	for _, unit := range s.plan {
		if unit.kind == PlanUnitForwardedOperation && abandonedIDs[unit.opID] {
			delete(s.planIndex, unit.opID)
			continue
		}
		if unit.kind == PlanUnitSyntheticError && unit.cycle == cycle {
			continue
		}
		remaining = append(remaining, unit)
	}
	s.plan = remaining

	for id := range needsTombstone {
		s.abandonedOps[id] = true
		if s.cycleTombstones[cycle] == nil {
			s.cycleTombstones[cycle] = make(map[PendingOperationID]bool)
		}
		s.cycleTombstones[cycle][id] = true
	}
	return true
}

// finishCycle, bir cycle'in ReadyForQuery ile basariyla tamamlanmasinin
// ardindan o cycle'a ait tum gecici izleme durumunu (blok, tombstone,
// aktif cycle kaydi) temizler ve o cycle kimligini kalici olarak
// "tamamlanmis" (bir daha asla gecerli olamaz) isaretler.
func (s *ResponseSequencer) finishCycle(cycle CycleID) {
	delete(s.cycleSeenOps, cycle)
	delete(s.blockedCycles, cycle)
	delete(s.reallyFailed, cycle)
	delete(s.activeCycles, cycle)
	if ids, ok := s.cycleTombstones[cycle]; ok {
		for id := range ids {
			delete(s.abandonedOps, id)
		}
		delete(s.cycleTombstones, cycle)
	}
	if cycle > s.highestCompletedCycle {
		s.highestCompletedCycle = cycle
	}
}

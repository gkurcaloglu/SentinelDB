package masking

import (
	"errors"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// Bu dosya, PostgreSQL Extended Query Protocol'u icin baglanti-yerel, TEK
// SAHIPLI (single-owner) bir maskeleme sekli (shape) izleyicisi tanimlar.
//
// ExtendedTracker:
//   - hicbir soket G/C'si yapmaz, hicbir goroutine baslatmaz;
//   - internal/gateway ya da internal/firewall'a BAGIMLI DEGILDIR (bu
//     dosya yalnizca internal/protocol'un GUVENLI, isim icermeyen
//     GenerationID/RowField turlerine bagimlidir);
//   - dahili hicbir kilitleme yapmaz - YALNIZCA cagiranin (bkz.
//     internal/gateway.ExtendedRuntime'in event-loop goroutine'i) sirali
//     cagirdigi varsayimiyla tasarlanmistir;
//   - SQL metni, Bind parametre degerleri, DataRow degerleri, tam
//     RowDescription/DataRow cerceveleri, statement/portal ADLARI ya da
//     hedef-olmayan sutun adlarini ASLA saklamaz - yalnizca sekil
//     (column count, hedef sutun index/adi, generation kimligi) tutar.
//
// Kaynak: docs/postgresql-protocol.md, docs/design/0001-extended-query.md.

// ExtendedLimits, ExtendedTracker'in sinirsiz bellek buyumesine karsi
// uyguladigi sabit kaynak sinirlaridir. Tum alanlar pozitif olmalidir.
type ExtendedLimits struct {
	// MaxStatementShapes, ayni anda onbellege alinabilecek en fazla
	// statement-Describe sekli sayisidir.
	MaxStatementShapes int
	// MaxPortalShapes, ayni anda onbellege alinabilecek en fazla portal-
	// Describe sekli sayisidir (portal-Describe sekilleri VE taahhut
	// edilmis effective plan'lar icin AYRI AYRI uygulanir).
	MaxPortalShapes int
	// MaxFieldsPerShape, tek bir sekildeki (RowDescription'dan gelen) en
	// fazla sutun sayisidir.
	MaxFieldsPerShape int
	// MaxTotalShapeFields, TUM onbellege alinmis sekiller genelinde en
	// fazla toplam hedef (maskelenecek) sutun sayisidir.
	MaxTotalShapeFields int
}

// DefaultExtendedLimits, uretim disi/test amacli makul varsayilan sinirlar
// dondurur.
func DefaultExtendedLimits() ExtendedLimits {
	return ExtendedLimits{
		MaxStatementShapes:  256,
		MaxPortalShapes:     256,
		MaxFieldsPerShape:   1024,
		MaxTotalShapeFields: 16384,
	}
}

func (l ExtendedLimits) validate() error {
	if l.MaxStatementShapes <= 0 || l.MaxPortalShapes <= 0 || l.MaxFieldsPerShape <= 0 || l.MaxTotalShapeFields <= 0 {
		return ErrInvalidExtendedLimits
	}
	return nil
}

// Extended maskeleme icin sabit, guvenli hata kategorileri. Hicbiri SQL
// metni, statement/portal adi, sutun adi, Bind degeri ya da ham cerceve
// icermez - cagiran taraflar (bkz. internal/gateway, internal/firewall)
// bunlari SABIT, istemciye-guvenli kategorilere esler.
var (
	ErrInvalidExtendedLimits = errors.New("masking: gecersiz extended sinirlari (pozitif olmali)")
	// ErrExtendedShapeUnknown, maskeleme etkinken bir Execute icin ne
	// portal-Describe ne de statement-Describe sekli hic gozlenmemisse
	// donulur.
	ErrExtendedShapeUnknown = errors.New("masking: bilinmeyen sonuc sekli")
	// ErrExtendedBinaryTarget, yapilandirilmis bir maskeleme hedefi
	// sutununun GERCEK (Bind'tan turetilen) format kodu ikili (1) ise
	// donulur.
	ErrExtendedBinaryTarget = errors.New("masking: maskeleme hedefi sutun ikili formatta")
	// ErrExtendedInvalidResultFormat, Bind sonuc format kodu dizisi
	// PostgreSQL kurallarina (0/1/N adet) uymuyorsa ya da portal-Describe
	// gozlenen format kodlari beklenen (Bind'tan turetilen) kodlarla
	// tutarsizsa donulur.
	ErrExtendedInvalidResultFormat = errors.New("masking: gecersiz ya da tutarsiz sonuc format meta verisi")
	// ErrExtendedCapacityExceeded, ExtendedLimits'te tanimli sinirlardan
	// biri asilirsa donulur.
	ErrExtendedCapacityExceeded = errors.New("masking: extended maskeleme sekil kapasitesi asildi")
	// ErrExtendedMalformedRowDescription, gercek bir backend
	// RowDescription'i ayristirilamadiginda donulur.
	ErrExtendedMalformedRowDescription = errors.New("masking: RowDescription ayristirilamadi")
)

// shapeTarget, bir describeShape icinde maskelenmesi gereken TEK bir
// sutunu tanimlar - yalnizca index ve ad (Masker'a gecirilmek uzere).
type shapeTarget struct {
	Index      int
	ColumnName string
}

// describeShape, bir statement ya da portal Describe yanitindan gozlenen,
// gizlilik-en-aza-indirgenmis sekil meta verisidir: sutun sayisi + yapilandirilmis
// hedef sutunlarin index/adi. Hedef OLMAYAN sutunlarin adlari
// SAKLANMAZ. Format kodlari burada TUTULMAZ (statement Describe icin
// anlamsiz birer yer tutucudur; portal Describe icin dogrulama anindan
// hemen sonra atilir - bkz. ObservePortalDescribeRowDescription).
type describeShape struct {
	// NoData true ise Describe NoData ile tamamlanmistir: bu islem hicbir
	// zaman DataRow uretmeyecegi BILINEN bir sekildir (ColumnCount/Targets
	// anlamsizdir). false VE bu generation haritada hic YOKSA "bilinmeyen
	// sekil" anlamina gelir - bu ayrim ExtendedTracker'in ",ok" harita
	// aramasiyla saglanir, describeShape'in kendi alanlariyla degil.
	NoData      bool
	ColumnCount int
	Targets     []shapeTarget
}

// ExtendedTracker, tek bir Extended Query baglantisi icin sekil/plan
// onbellegidir. YALNIZCA sahibi olan ExtendedRuntime'in event-loop
// goroutine'i tarafindan cagirilmalidir - dahili hicbir senkronizasyon
// yapmaz.
type ExtendedTracker struct {
	cfg    Config
	limits ExtendedLimits

	statementShapes map[protocol.GenerationID]describeShape
	portalShapes    map[protocol.GenerationID]describeShape
	portalPlans     map[protocol.GenerationID]RowMaskPlan

	totalFields int
}

// NewExtendedTracker, verilen Config ve ExtendedLimits ile yeni, bos bir
// ExtendedTracker olusturur. limits.validate() basarisiz olursa hata
// doner.
func NewExtendedTracker(cfg Config, limits ExtendedLimits) (*ExtendedTracker, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	return &ExtendedTracker{
		cfg:             cfg,
		limits:          limits,
		statementShapes: make(map[protocol.GenerationID]describeShape),
		portalShapes:    make(map[protocol.GenerationID]describeShape),
		portalPlans:     make(map[protocol.GenerationID]RowMaskPlan),
	}, nil
}

// buildShape, RowDescription alanlarindan gizlilik-en-aza-indirgenmis bir
// describeShape insa eder. Maskeleme devre disiysa (cfg.Enabled false)
// Targets her zaman bostur (Execute'un maskeleme yukumlulugu olmaz).
func (tr *ExtendedTracker) buildShape(fields []protocol.RowField) (describeShape, error) {
	if len(fields) > tr.limits.MaxFieldsPerShape {
		return describeShape{}, ErrExtendedCapacityExceeded
	}
	shape := describeShape{ColumnCount: len(fields)}
	if tr.cfg.Enabled {
		for i, f := range fields {
			if tr.cfg.ShouldMask(f.Name) {
				shape.Targets = append(shape.Targets, shapeTarget{Index: i, ColumnName: f.Name})
			}
		}
	}
	return shape, nil
}

// ObserveStatementDescribeRowDescription, bir statement-Describe'in
// RowDescription yanitindan sekil meta verisini gozlemler ve statement
// generation'a gore onbellege alir. RowDescription'in format kodlari
// yalnizca yer tutucudur ve HICBIR ZAMAN saklanmaz/kullanilmaz - bkz. dosya
// basi.
func (tr *ExtendedTracker) ObserveStatementDescribeRowDescription(gen protocol.GenerationID, body []byte) error {
	rd, err := protocol.ParseRowDescription(body)
	if err != nil {
		return ErrExtendedMalformedRowDescription
	}
	shape, err := tr.buildShape(rd.Fields)
	if err != nil {
		return err
	}
	return tr.commitStatementShape(gen, shape)
}

// ObserveStatementDescribeNoData, bir statement-Describe'in NoData ile
// tamamlandigini (bilinen-NoData) kaydeder.
func (tr *ExtendedTracker) ObserveStatementDescribeNoData(gen protocol.GenerationID) error {
	return tr.commitStatementShape(gen, describeShape{NoData: true})
}

// ObservePortalDescribeRowDescription, bir portal-Describe'in
// RowDescription yanitindan sekil meta verisini gozlemler. expectedFormats,
// bu portalin Bind'inda ISTENEN sonuc format kodlaridir (bkz.
// ExpandResultFormats) - RowDescription'daki GERCEK format kodlari, bu
// beklenen kodlarla TUTARLI olmalidir (aksi halde imkansiz bir uyusmazlik,
// fail-closed reddedilir); tutarlilik dogrulandiktan hemen sonra format
// kodlarinin kendisi ATILIR ve ASLA onbellege alinmaz - Execute anindaki
// GERCEK format, her zaman yeniden Bind'in ResultFormats'indan turetilir
// (bkz. ResolveExecutePlan).
func (tr *ExtendedTracker) ObservePortalDescribeRowDescription(gen protocol.GenerationID, body []byte, expectedFormats []int16) error {
	rd, err := protocol.ParseRowDescription(body)
	if err != nil {
		return ErrExtendedMalformedRowDescription
	}
	expanded, err := ExpandResultFormats(expectedFormats, len(rd.Fields))
	if err != nil {
		return ErrExtendedInvalidResultFormat
	}
	for i, f := range rd.Fields {
		if f.FormatCode != expanded[i] {
			return ErrExtendedInvalidResultFormat
		}
	}
	shape, err := tr.buildShape(rd.Fields)
	if err != nil {
		return err
	}
	return tr.commitPortalShape(gen, shape)
}

// ObservePortalDescribeNoData, bir portal-Describe'in NoData ile
// tamamlandigini (bilinen-NoData) kaydeder.
func (tr *ExtendedTracker) ObservePortalDescribeNoData(gen protocol.GenerationID) error {
	return tr.commitPortalShape(gen, describeShape{NoData: true})
}

func (tr *ExtendedTracker) commitStatementShape(gen protocol.GenerationID, shape describeShape) error {
	old, existed := tr.statementShapes[gen]
	oldCount := 0
	if existed {
		oldCount = len(old.Targets)
	}
	if !existed && len(tr.statementShapes) >= tr.limits.MaxStatementShapes {
		return ErrExtendedCapacityExceeded
	}
	if tr.totalFields-oldCount+len(shape.Targets) > tr.limits.MaxTotalShapeFields {
		return ErrExtendedCapacityExceeded
	}
	tr.totalFields = tr.totalFields - oldCount + len(shape.Targets)
	tr.statementShapes[gen] = shape
	return nil
}

func (tr *ExtendedTracker) commitPortalShape(gen protocol.GenerationID, shape describeShape) error {
	old, existed := tr.portalShapes[gen]
	oldCount := 0
	if existed {
		oldCount = len(old.Targets)
	}
	if !existed && len(tr.portalShapes) >= tr.limits.MaxPortalShapes {
		return ErrExtendedCapacityExceeded
	}
	if tr.totalFields-oldCount+len(shape.Targets) > tr.limits.MaxTotalShapeFields {
		return ErrExtendedCapacityExceeded
	}
	tr.totalFields = tr.totalFields - oldCount + len(shape.Targets)
	tr.portalShapes[gen] = shape
	return nil
}

// RetireStatement, bir statement generation'a ait onbellege alinmis sekil
// meta verisini kaldirir (bkz. basarisiz Parse, CloseComplete cascade,
// adsiz-Parse degistirme).
func (tr *ExtendedTracker) RetireStatement(gen protocol.GenerationID) {
	if shape, ok := tr.statementShapes[gen]; ok {
		tr.totalFields -= len(shape.Targets)
		delete(tr.statementShapes, gen)
	}
}

// RetirePortal, bir portal generation'a ait onbellege alinmis sekil VE
// taahhut edilmis effective plan meta verisini kaldirir (bkz. basarisiz
// Bind, CloseComplete, adsiz-Bind degistirme, ReadyForQuery('I') gecersiz
// kilma).
func (tr *ExtendedTracker) RetirePortal(gen protocol.GenerationID) {
	if shape, ok := tr.portalShapes[gen]; ok {
		tr.totalFields -= len(shape.Targets)
		delete(tr.portalShapes, gen)
	}
	delete(tr.portalPlans, gen)
}

// ResolveExecutePlan, bir Execute icin degismez, G/C icermeyen effective
// maskeleme planini hesaplar - HICBIR State mutasyonu yapmaz. Sekil
// oncelik sirasi: portal-Describe sekli (varsa) > statement sekli (varsa)
// > bilinmeyen. Maskeleme devre disiysa (cfg.Enabled false) her zaman
// bos, hicbir yukumlulugu olmayan bir plan doner - sekil hic gozlenmemis
// olsa bile.
func (tr *ExtendedTracker) ResolveExecutePlan(portalGen, statementGen protocol.GenerationID, resultFormats []int16) (RowMaskPlan, error) {
	if !tr.cfg.Enabled {
		return RowMaskPlan{}, nil
	}

	shape, ok := tr.portalShapes[portalGen]
	if !ok {
		shape, ok = tr.statementShapes[statementGen]
	}
	if !ok {
		return RowMaskPlan{}, ErrExtendedShapeUnknown
	}
	if shape.NoData {
		return RowMaskPlan{}, nil
	}

	expanded, err := ExpandResultFormats(resultFormats, shape.ColumnCount)
	if err != nil {
		return RowMaskPlan{}, ErrExtendedInvalidResultFormat
	}
	if len(shape.Targets) == 0 {
		return RowMaskPlan{ColumnCount: shape.ColumnCount}, nil
	}

	plan := RowMaskPlan{ColumnCount: shape.ColumnCount, Targets: make([]MaskTarget, len(shape.Targets))}
	for i, tgt := range shape.Targets {
		if tgt.Index < 0 || tgt.Index >= len(expanded) {
			return RowMaskPlan{}, ErrExtendedInvalidResultFormat
		}
		fc := expanded[tgt.Index]
		if fc != 0 {
			return RowMaskPlan{}, ErrExtendedBinaryTarget
		}
		plan.Targets[i] = MaskTarget{Index: tgt.Index, ColumnName: tgt.ColumnName, FormatCode: fc}
	}
	return plan, nil
}

// CommitExecutePlan, ResolveExecutePlan tarafindan hesaplanmis effective
// plani, sonraki DataRow'larda kullanilmak uzere portal generation'a gore
// onbellege alir. Cagiran, bunu YALNIZCA State.CreateExecute VE sequencer
// kaydi BASARILI OLDUKTAN SONRA, upstream'e yazmadan HEMEN ONCE
// cagirmalidir (bkz. docs/design "masking preflight -> State.CreateExecute
// -> sequencer registration -> effective plan commit -> upstream write ->
// ack" sirasi).
func (tr *ExtendedTracker) CommitExecutePlan(portalGen protocol.GenerationID, plan RowMaskPlan) error {
	if _, exists := tr.portalPlans[portalGen]; !exists && len(tr.portalPlans) >= tr.limits.MaxPortalShapes {
		return ErrExtendedCapacityExceeded
	}
	tr.portalPlans[portalGen] = plan
	return nil
}

// LookupExecutePlan, bir portal generation icin daha once taahhut edilmis
// effective plani dondurur. ok false ise (bkz. eksik plan) cagiran fail-
// closed davranmalidir - hicbir DataRow, taahhut edilmis bir plan olmadan
// maskelenmemelidir.
func (tr *ExtendedTracker) LookupExecutePlan(portalGen protocol.GenerationID) (RowMaskPlan, bool) {
	plan, ok := tr.portalPlans[portalGen]
	return plan, ok
}

// WouldExceedPortalPlanCapacity, portalGen icin (henuz mevcut degilse) YENI
// bir plan taahhut etmenin MaxPortalShapes sinirini asip asmayacagini
// bildirir - salt-okunur, HICBIR mutasyon yapmaz. Cagiran (bkz.
// internal/gateway.ExtendedRuntime), bunu State.CreateExecute cagrisindan
// ONCE, Execute preflight'inin bir parcasi olarak kullanmalidir - boylece
// kapasite reddi HER ZAMAN State mutasyonundan once, kurtarilabilir bir
// yerel ret olarak gerceklesir (bkz. gorev 9/16).
func (tr *ExtendedTracker) WouldExceedPortalPlanCapacity(portalGen protocol.GenerationID) bool {
	if _, exists := tr.portalPlans[portalGen]; exists {
		return false
	}
	return len(tr.portalPlans) >= tr.limits.MaxPortalShapes
}

// StatementGenerations, onbellege alinmis TUM statement sekli
// generation kimliklerini (yalnizca sayisal ID'ler - isim/sutun/deger
// icermez) dondurur. Cagiran, bunu State ile mutabakat (reconciliation)
// icin kullanir (bkz. gorev 15).
func (tr *ExtendedTracker) StatementGenerations() []protocol.GenerationID {
	out := make([]protocol.GenerationID, 0, len(tr.statementShapes))
	for g := range tr.statementShapes {
		out = append(out, g)
	}
	return out
}

// PortalGenerations, onbellege alinmis TUM portal sekli VE/veya effective
// plan generation kimliklerinin (yalnizca sayisal ID'ler) BIRLESIMINI
// dondurur.
func (tr *ExtendedTracker) PortalGenerations() []protocol.GenerationID {
	seen := make(map[protocol.GenerationID]struct{}, len(tr.portalShapes)+len(tr.portalPlans))
	for g := range tr.portalShapes {
		seen[g] = struct{}{}
	}
	for g := range tr.portalPlans {
		seen[g] = struct{}{}
	}
	out := make([]protocol.GenerationID, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	return out
}

// --- Yalnizca sayisal, DEGER icermeyen gozlem yardimcilari (testler icin) -
//
// Bunlarin hicbiri sutun adi, index ya da baska bir "sekil" detayi
// dondurmez - yalnizca SAYAC/bool. bkz. "Shape entries must not be exposed
// through public mutable snapshots".

func (tr *ExtendedTracker) StatementShapeCount() int { return len(tr.statementShapes) }
func (tr *ExtendedTracker) PortalShapeCount() int    { return len(tr.portalShapes) }
func (tr *ExtendedTracker) PortalPlanCount() int     { return len(tr.portalPlans) }
func (tr *ExtendedTracker) TotalFieldCount() int     { return tr.totalFields }

func (tr *ExtendedTracker) HasStatementShape(gen protocol.GenerationID) bool {
	_, ok := tr.statementShapes[gen]
	return ok
}
func (tr *ExtendedTracker) HasPortalShape(gen protocol.GenerationID) bool {
	_, ok := tr.portalShapes[gen]
	return ok
}
func (tr *ExtendedTracker) HasPortalPlan(gen protocol.GenerationID) bool {
	_, ok := tr.portalPlans[gen]
	return ok
}

// ExpandResultFormats, PostgreSQL'in Bind sonuc-format-kodu genisletme
// kurallarini uygular (bkz. https://www.postgresql.org/docs/current/protocol-message-formats.html,
// Bind): SIFIR kod -> her sutun metin(0); BIR kod -> her sutuna uygulanir;
// TAM OLARAK columnCount kadar kod -> pozisyonel; baska HERHANGI BIR sayi
// reddedilir. Her kod 0 ya da 1 olmalidir. Donen dilim, codes'tan bagimsiz
// TAZE bir tahsistir.
func ExpandResultFormats(codes []int16, columnCount int) ([]int16, error) {
	if columnCount < 0 {
		return nil, ErrExtendedInvalidResultFormat
	}
	for _, c := range codes {
		if c != 0 && c != 1 {
			return nil, ErrExtendedInvalidResultFormat
		}
	}
	out := make([]int16, columnCount)
	switch len(codes) {
	case 0:
		// Tumu zaten sifir (metin) degerinde baslatildi.
	case 1:
		for i := range out {
			out[i] = codes[0]
		}
	default:
		if len(codes) != columnCount {
			return nil, ErrExtendedInvalidResultFormat
		}
		copy(out, codes)
	}
	return out, nil
}

package protocol

import (
	"errors"
	"math"
)

// Bu dosya, PostgreSQL Extended Query Protocol'u (Parse/Bind/Describe/
// Execute/Close/Sync) icin baglanti-yerel (connection-local) bir DURUM
// MODELI tanimlar. Bu SADECE bir durum modelidir:
//
//   - hicbir agi/soket davranisini degistirmez
//   - firewall.Gate, masking.Transformer ya da cmd/gateway'e BAGLI DEGILDIR
//   - hicbir G/C (I/O) yapmaz, hicbir goroutine baslatmaz, hicbir sey
//     loglamaz
//   - deterministiktir ve dogrudan birim testleriyle sinanabilir
//
// SentinelDB, calisma zamaninda Extended Query mesajlarini hala fail-closed
// reddeder (bkz. internal/firewall/gate.go, isExtendedProtocolMessage). Bu
// dosya yalnizca ileriki asamalarin (bkz. docs/design/0001-extended-query.md,
// "Implementation decomposition" bolumu, asama 2) uzerine insa edecegi
// bagimsiz bir yapi tasidir. Bu asamada hicbir gateway/masking/firewall
// entegrasyonu yapilmamistir.
//
// Concurrency: State, tek bir goroutine tarafindan sirali cagrilmak uzere
// tasarlanmistir (protocol.Decoder'in kendi buf alani gibi) - dahili hicbir
// kilitleme yapmaz. Baglanti basina bir State ornegi kullanilmalidir.
//
// Degismezlik (immutability) sozlesmesi: TUM public sorgulama/olusturma/
// onaylama metodlari (ResolveStatement/CommittedStatement/ResolvePortal/
// CommittedPortal/Statement/Portal/PendingOperations/Create*/
// ApplyParseComplete/ApplyBindComplete dahil) State icinde saklanan
// nesnelere degil, TAM (struct + tum slice alanlari) bagimsiz KOPYALARINA
// deger olarak doner. Donen bir degeri (ör. ParamOIDs[0]'i) degistirmek
// State'in dahili durumunu ASLA etkilemez - dahili mutasyon yalnizca State
// metodlari araciligiyla olur. Bkz. copyStatementGeneration/
// copyPortalGeneration/copyPendingOperation.

// GenerationID, bir prepared statement ya da portal "generation"ini
// (bkz. docs/design/0001-extended-query.md, "Object generations") tekil
// olarak tanimlayan, bir State ornegi icinde monoton artan bir tamsayidir.
// Sifir deger (NoGeneration) hicbir zaman gecerli bir generation'i
// tanimlamaz.
type GenerationID uint64

// CycleID, bir Sync ile sinirlanan tek bir frontend "cycle"ini tanimlayan,
// bir State ornegi icinde monoton artan bir tamsayidir. Sifir deger
// (NoCycle) hicbir zaman gecerli bir cycle'i tanimlamaz.
type CycleID uint64

// PendingOperationID, bekleyen-islem kuyrugundaki (pending-operation queue)
// tek bir girdiyi tanimlayan, bir State ornegi icinde monoton artan bir
// tamsayidir. Sifir deger (NoPendingOperation) hicbir zaman gecerli bir
// islemi tanimlamaz.
type PendingOperationID uint64

const (
	NoGeneration       GenerationID       = 0
	NoCycle            CycleID            = 0
	NoPendingOperation PendingOperationID = 0
)

// LifecycleState, bir statement ya da portal generation'inin yasam
// dongusundeki durumunu ifade eder.
type LifecycleState int

const (
	// LifecyclePending: gercek sunucuya iletildigi varsayilir (bu paketin
	// disindaki bir cagiran tarafindan), ancak henuz onaylanmamistir
	// (ParseComplete/BindComplete beklenmektedir).
	LifecyclePending LifecycleState = iota + 1
	// LifecycleCommitted: karsilik gelen backend onayi (ParseComplete/
	// BindComplete) uygulanmistir.
	LifecycleCommitted
	// LifecycleFailed: bir ErrorResponse, beklenen onay yerine
	// uygulanmistir.
	LifecycleFailed
)

// OperationKind, bekleyen-islem kuyrugundaki bir girdinin hangi frontend
// mesajina karsilik geldigini belirtir. Flush bilerek bu listede degildir:
// gercek protokolde Flush'in karsilik gelen bir onay mesaji yoktur (bkz.
// docs/design/0001-extended-query.md, "Frontend message table"), bu yuzden
// bekleyen-islem kuyruguna hic girmez.
type OperationKind int

const (
	OpParse OperationKind = iota + 1
	OpBind
	OpDescribeStatement
	OpDescribePortal
	OpExecute
	OpCloseStatement
	OpClosePortal
	OpSync
)

// StatementGeneration, ayristirilmis (bkz. internal/protocol/extended.go,
// ParseMessage) bir Parse mesajindan turetilen, guvenli bir hazirlanmis
// deyim (prepared statement) generation kaydidir. Bind parametre DEGERLERI
// hicbir zaman burada saklanmaz - yalnizca Parse ile birlikte gelen
// parametre OID'leri (deger degil, tip bilgisi) kopyalanir.
//
// State'ten donen her StatementGeneration DEGERI bagimsiz bir kopyadir
// (bkz. dosya basi "Degismezlik sozlesmesi") - ParamOIDs dahil hicbir alani
// degistirmek State'i etkilemez.
type StatementGeneration struct {
	ID    GenerationID
	Name  string // "" ise isimsiz (unnamed) slot
	Query string
	// ParamOIDs, Parse mesaji ile bildirilen parametre tipi OID'lerinin
	// kopyasidir (deger degil, sadece tip bilgisi).
	ParamOIDs []uint32
	// CreatedCycle, bu generation'in olusturuldugu frontend cycle'idir.
	CreatedCycle CycleID
	State        LifecycleState
}

// PortalGeneration, ayristirilmis (bkz. internal/protocol/extended.go,
// BindMessage) bir Bind mesajindan turetilen, guvenli bir portal generation
// kaydidir. Bind parametre DEGERLERI hicbir zaman burada saklanmaz -
// yalnizca format kodlari ve NULL/NULL-olmayan bilgisi kopyalanir.
//
// State'ten donen her PortalGeneration DEGERI bagimsiz bir kopyadir (bkz.
// dosya basi "Degismezlik sozlesmesi") - ParamFormats/ParamNulls/
// ResultFormats dahil hicbir alani degistirmek State'i etkilemez.
type PortalGeneration struct {
	ID   GenerationID
	Name string // "" ise isimsiz (unnamed) slot
	// StatementID, bu portal'in bagli oldugu TAM statement generation'idir
	// (yalnizca isim degil) - istatement adi sonradan baska bir generation'a
	// isaret etse bile bu portal her zaman ayni generation'a bagli kalir.
	StatementID GenerationID
	// ParamFormats, Bind ile bildirilen parametre format kodlarinin
	// kopyasidir (0=metin, 1=ikili).
	ParamFormats []int16
	// ParamNulls, her parametrenin NULL olup olmadigini tasir - parametre
	// DEGERLERI (bkz. protocol.BindParam.Value) hicbir zaman burada
	// saklanmaz. len(ParamNulls) parametre sayisidir.
	ParamNulls []bool
	// ResultFormats, Bind ile istenen sonuc sutunu format kodlarinin
	// kopyasidir.
	ResultFormats []int16
	CreatedCycle  CycleID
	State         LifecycleState
}

// PendingOperation, gercek sunucudan gelecek bir backend onayini (ya da
// ErrorResponse'unu) FIFO sirayla eslestirmek icin kullanilan, bekleyen-
// islem kuyrugundaki tek bir girdidir. Ad/hedef alanlari, islem
// olusturuldugu andaki degismez (immutable) bir goruntudur (snapshot) -
// isim eslemeleri sonradan degisse bile bu girdi degismez.
//
// State'ten donen her PendingOperation DEGERI bagimsiz bir kopyadir (bkz.
// dosya basi "Degismezlik sozlesmesi"); PendingOperation'in hicbir slice
// alani olmadigindan (tum alanlar deger tipi) bu kopyalama otomatik olarak
// tamdir.
type PendingOperation struct {
	ID    PendingOperationID
	Cycle CycleID
	Kind  OperationKind
	// TargetName, islemle ilgili istemci tarafindan verilen ad
	// goruntusudur (statement ya da portal adi; Sync icin bos).
	TargetName string
	// TargetGeneration, bu islemin olusturdugu (Parse/Bind) ya da
	// referans verdigi (Describe/Execute/Close) generation'in olusturma
	// anindaki degismez ID'sidir - committed VEYA HALA PENDING olan bir
	// generation'a isaret edebilir (ör. bir Close, karsilik gelen Parse/
	// Bind henuz onaylanmadan pipeline edilmis olabilir; bkz.
	// CreateCloseStatement/CreateClosePortal). Close icin, hedef ad o anda
	// bilinen (committed ya da pending) hicbir generation'a karsilik
	// gelmiyorsa NoGeneration olabilir (gercek sunucuda var olmayan bir
	// adi kapatmak hata degildir).
	TargetGeneration GenerationID
}

// --- Degismezlik (immutability) icin dahili derin-kopya yardimcilari ------
//
// Bu yardimcilar YALNIZCA State'in kendi paket-ici (internal) *T
// isaretcilerinden (haritalarda saklanan, mutasyona ugrayabilen nesneler)
// bagimsiz, tam DEGER kopyalari uretmek icindir - hicbir slice alani
// atlanmaz. Public metodlarin TAMAMI donus degerlerini bu yardimcilar
// araciligiyla uretir; hicbir public metod dahili bir *StatementGeneration/
// *PortalGeneration/*PendingOperation'i dogrudan (ya da onun slice
// alanlarindan birini paylasarak) disari sizdirmaz.
func copyStatementGeneration(g *StatementGeneration) StatementGeneration {
	c := *g
	c.ParamOIDs = append([]uint32(nil), g.ParamOIDs...)
	return c
}

func copyPortalGeneration(g *PortalGeneration) PortalGeneration {
	c := *g
	c.ParamFormats = append([]int16(nil), g.ParamFormats...)
	c.ParamNulls = append([]bool(nil), g.ParamNulls...)
	c.ResultFormats = append([]int16(nil), g.ResultFormats...)
	return c
}

func copyPendingOperation(op *PendingOperation) PendingOperation {
	// PendingOperation'in hicbir slice/isaretci alani yoktur (ID/Cycle/Kind
	// int/uint tipli, TargetName string -Go'da stringler zaten degismezdir-,
	// TargetGeneration GenerationID) - bu yuzden deger kopyasi (*op) zaten
	// tamdir. Yine de diger iki yardimciyla simetri ve gelecekte
	// PendingOperation'a slice alani eklenirse otomatik dogrulugu korumak
	// icin ayri bir fonksiyon olarak tutulur.
	return *op
}

// Sabit, guvenli hata kategorileri (bkz. gereksinim: hicbir hata SQL
// metni, Bind parametre degeri, ham protokol baytlari ya da sinirsiz
// istemci-saglanan ad icermemelidir).
var (
	ErrUnknownStatement           = errors.New("extendedstate: bilinmeyen statement")
	ErrUnknownPortal              = errors.New("extendedstate: bilinmeyen portal")
	ErrUnknownGeneration          = errors.New("extendedstate: bilinmeyen generation")
	ErrInvalidLifecycleTransition = errors.New("extendedstate: gecersiz yasam-dongusu gecisi")
	ErrAckKindMismatch            = errors.New("extendedstate: onay turu kuyruk basiyla uyusmuyor")
	ErrAckOrderMismatch           = errors.New("extendedstate: onay sirasi kuyruk basiyla uyusmuyor")
	ErrInvalidTransactionStatus   = errors.New("extendedstate: gecersiz islem durumu baytı")
	ErrCycleClosed                = errors.New("extendedstate: bekleyen (acik) cycle yok")
	ErrIdentifierExhaustion       = errors.New("extendedstate: tanimlayici (identifier) tukendi")
)

// State, tek bir baglanti icin Extended Query Protocol durumunu tasir.
// Sifir degeri kullanilamaz - her zaman NewState ile olusturulmalidir.
// State kendi icinde hicbir kilitleme yapmaz; tek bir goroutine tarafindan
// sirali cagrilmalidir (bkz. dosya basindaki concurrency notu).
type State struct {
	nextGeneration uint64
	nextCycle      uint64
	nextOp         uint64

	statements              map[GenerationID]*StatementGeneration
	namedStatementCommitted map[string]GenerationID
	unnamedStatementCurrent GenerationID

	portals              map[GenerationID]*PortalGeneration
	namedPortalCommitted map[string]GenerationID
	unnamedPortalCurrent GenerationID

	// pendingOps, FIFO bekleyen-islem kuyrugudur; index 0 kuyruk basidir
	// (bir sonraki backend onayinin eslesmesi gereken islem).
	pendingOps []*PendingOperation

	currentCycle CycleID
	// outstandingSyncCycles, Sync'i "gonderilmis" sayilan (bu paket
	// kapsaminda: CreateSync cagrilmis) ama karsilik gelen gercek
	// ReadyForQuery'si henuz uygulanmamis cycle ID'lerinin FIFO listesidir.
	outstandingSyncCycles []CycleID

	txStatus byte
}

// NewState, bos, yeni bir baglanti icin State olusturur. Ilk cycle ID'si
// gecerli ve sifirdan farklidir (NoCycle degildir).
func NewState() *State {
	s := &State{
		statements:              make(map[GenerationID]*StatementGeneration),
		namedStatementCommitted: make(map[string]GenerationID),
		portals:                 make(map[GenerationID]*PortalGeneration),
		namedPortalCommitted:    make(map[string]GenerationID),
		txStatus:                TxStatusIdle,
	}
	// Ilk cycle tahsisi (1'den baslar) asla identifier tukenmesine yol
	// acmaz; hata donmesi imkansizdir, bu yuzden goz ardi edilir.
	cyc, _ := s.allocCycle()
	s.currentCycle = cyc
	return s
}

// --- Tanimlayici (identifier) tahsisi ---------------------------------

func (s *State) allocGeneration() (GenerationID, error) {
	if s.nextGeneration == math.MaxUint64 {
		return NoGeneration, ErrIdentifierExhaustion
	}
	s.nextGeneration++
	return GenerationID(s.nextGeneration), nil
}

func (s *State) allocCycle() (CycleID, error) {
	if s.nextCycle == math.MaxUint64 {
		return NoCycle, ErrIdentifierExhaustion
	}
	s.nextCycle++
	return CycleID(s.nextCycle), nil
}

func (s *State) allocOp() (PendingOperationID, error) {
	if s.nextOp == math.MaxUint64 {
		return NoPendingOperation, ErrIdentifierExhaustion
	}
	s.nextOp++
	return PendingOperationID(s.nextOp), nil
}

// --- Sorgulama (resolve/lookup) yardimcilari ----------------------------

// ResolveStatement, bir sonraki frontend mesaji "name" statement adini
// belirtseydi hangi generation'a cozumlenecegini dondurur: isimsiz slot
// icin her zaman guncel (current) generation; isimli slotlar icin once
// committed generation, o yoksa en yeni pending generation (pipelining
// sirasinda "gecici olarak gecerli" kabul edilir - bkz. tasarim belgesi,
// "State should not be committed when the frontend message arrives").
// Failed generation'lar hicbir zaman cozumlenmez.
//
// Donen deger, dahili durumun bagimsiz bir kopyasidir (bkz. dosya basi
// "Degismezlik sozlesmesi").
func (s *State) ResolveStatement(name string) (StatementGeneration, bool) {
	g, ok := s.resolveStatementPtr(name)
	if !ok {
		return StatementGeneration{}, false
	}
	return copyStatementGeneration(g), true
}

func (s *State) resolveStatementPtr(name string) (*StatementGeneration, bool) {
	if name == "" {
		if s.unnamedStatementCurrent == NoGeneration {
			return nil, false
		}
		g, ok := s.statements[s.unnamedStatementCurrent]
		return g, ok
	}
	if id, ok := s.namedStatementCommitted[name]; ok {
		g, ok := s.statements[id]
		return g, ok
	}
	var best *StatementGeneration
	for _, g := range s.statements {
		if g.Name == name && g.State == LifecyclePending {
			if best == nil || g.ID > best.ID {
				best = g
			}
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}

// CommittedStatement, "name" icin YALNIZCA backend tarafindan onaylanmis
// (committed) generation'i dondurur - asla sadece pending olan bir
// generation'i dondurmez.
//
// Donen deger, dahili durumun bagimsiz bir kopyasidir.
func (s *State) CommittedStatement(name string) (StatementGeneration, bool) {
	if name == "" {
		if s.unnamedStatementCurrent == NoGeneration {
			return StatementGeneration{}, false
		}
		g, ok := s.statements[s.unnamedStatementCurrent]
		if !ok || g.State != LifecycleCommitted {
			return StatementGeneration{}, false
		}
		return copyStatementGeneration(g), true
	}
	id, ok := s.namedStatementCommitted[name]
	if !ok {
		return StatementGeneration{}, false
	}
	g, ok := s.statements[id]
	if !ok {
		return StatementGeneration{}, false
	}
	return copyStatementGeneration(g), true
}

// ResolvePortal, ResolveStatement ile ayni kurallari portal'lar icin uygular.
//
// Donen deger, dahili durumun bagimsiz bir kopyasidir.
func (s *State) ResolvePortal(name string) (PortalGeneration, bool) {
	g, ok := s.resolvePortalPtr(name)
	if !ok {
		return PortalGeneration{}, false
	}
	return copyPortalGeneration(g), true
}

func (s *State) resolvePortalPtr(name string) (*PortalGeneration, bool) {
	if name == "" {
		if s.unnamedPortalCurrent == NoGeneration {
			return nil, false
		}
		g, ok := s.portals[s.unnamedPortalCurrent]
		return g, ok
	}
	if id, ok := s.namedPortalCommitted[name]; ok {
		g, ok := s.portals[id]
		return g, ok
	}
	var best *PortalGeneration
	for _, g := range s.portals {
		if g.Name == name && g.State == LifecyclePending {
			if best == nil || g.ID > best.ID {
				best = g
			}
		}
	}
	if best == nil {
		return nil, false
	}
	return best, true
}

// CommittedPortal, CommittedStatement ile ayni kurallari portal'lar icin
// uygular.
//
// Donen deger, dahili durumun bagimsiz bir kopyasidir.
func (s *State) CommittedPortal(name string) (PortalGeneration, bool) {
	if name == "" {
		if s.unnamedPortalCurrent == NoGeneration {
			return PortalGeneration{}, false
		}
		g, ok := s.portals[s.unnamedPortalCurrent]
		if !ok || g.State != LifecycleCommitted {
			return PortalGeneration{}, false
		}
		return copyPortalGeneration(g), true
	}
	id, ok := s.namedPortalCommitted[name]
	if !ok {
		return PortalGeneration{}, false
	}
	g, ok := s.portals[id]
	if !ok {
		return PortalGeneration{}, false
	}
	return copyPortalGeneration(g), true
}

// Statement, verilen generation ID'sine sahip statement kaydinin bagimsiz
// bir KOPYASINI dondurur (dahili haritanin mutasyona ugramasini onlemek
// icin - ParamOIDs dahil).
func (s *State) Statement(id GenerationID) (StatementGeneration, bool) {
	g, ok := s.statements[id]
	if !ok {
		return StatementGeneration{}, false
	}
	return copyStatementGeneration(g), true
}

// Portal, verilen generation ID'sine sahip portal kaydinin bagimsiz bir
// KOPYASINI dondurur (ParamFormats/ParamNulls/ResultFormats dahil).
func (s *State) Portal(id GenerationID) (PortalGeneration, bool) {
	g, ok := s.portals[id]
	if !ok {
		return PortalGeneration{}, false
	}
	return copyPortalGeneration(g), true
}

// --- Parse / Bind olusturma ----------------------------------------------

// CreateParse, ALLOWED (Policy tarafindan izin verilmis ve gercek sunucuya
// iletilmis KABUL EDILEN) bir Parse mesaji icin yeni bir statement
// generation ve karsilik gelen bekleyen-islem kuyruğu girdisi olusturur.
//
// Cagiran, bu metodu YALNIZCA ilgili Parse mesaji gercekten iletilecekse
// (Policy engellemediyse) cagirmalidir - engellenen bir Parse icin bu
// metod hic cagrilmamalidir (bkz. dosya basi notu: "blocked, temsili hic
// cagirmama").
//
// name == "" (isimsiz slot) ise, onceki isimsiz "current" generation
// FORWARD ANINDA (bu cagri sirasinda, ParseComplete beklenmeden) hemen
// cozumlenemez hale gelir - gercek sunucunun kendi davranisini yansitir
// (bkz. docs/design/0001-extended-query.md, "Object generations").
//
// Atomiklik: tum tanimlayici (identifier) tahsisleri (generation VE
// pending-op ID'si) herhangi bir dahili durum (statements haritasi,
// unnamedStatementCurrent isaretcisi, pendingOps kuyrugu) degistirilmeden
// ONCE yapilir. Boylece ErrIdentifierExhaustion ile basarisiz olan bir
// cagri, State'te KISMI/YARIM hicbir yan etki birakmaz - ne bir generation
// haritada kalir, ne isaretci degisir, ne de kuyruga bir islem eklenir.
func (s *State) CreateParse(name, query string, paramOIDs []uint32) (PendingOperation, StatementGeneration, error) {
	genID, err := s.allocGeneration()
	if err != nil {
		return PendingOperation{}, StatementGeneration{}, err
	}
	opID, err := s.allocOp()
	if err != nil {
		// genID zaten tuketildi (sayaclar asla geri sarilmaz), ama HENUZ
		// hicbir haritaya/isaretciye/kuyruga yazilmadi - geri alinacak bir
		// yan etki yok.
		return PendingOperation{}, StatementGeneration{}, err
	}

	gen := &StatementGeneration{
		ID:           genID,
		Name:         name,
		Query:        query,
		ParamOIDs:    append([]uint32(nil), paramOIDs...),
		CreatedCycle: s.currentCycle,
		State:        LifecyclePending,
	}
	s.statements[genID] = gen
	if name == "" {
		s.unnamedStatementCurrent = genID
	}

	op := &PendingOperation{ID: opID, Cycle: s.currentCycle, Kind: OpParse, TargetName: name, TargetGeneration: genID}
	s.pendingOps = append(s.pendingOps, op)
	return copyPendingOperation(op), copyStatementGeneration(gen), nil
}

// CreateBind, ALLOWED bir Bind mesaji icin yeni bir portal generation ve
// karsilik gelen bekleyen-islem kuyrugu girdisi olusturur. Referans verilen
// statement bilinmiyorsa (ResolveStatement basarisiz) ErrUnknownStatement
// doner ve hicbir sey olusturulmaz.
//
// paramValues DEGERLERI bu metoda hic verilmez - yalnizca NULL/NULL-olmayan
// bilgisi (paramNulls) alinir.
//
// Atomiklik: CreateParse ile ayni ilke - tum tanimlayici tahsisleri
// (statement cozumlemesi HARIC - o zaten salt-okunur bir sorgudur) herhangi
// bir dahili durum degistirilmeden once yapilir.
func (s *State) CreateBind(portalName, statementName string, paramFormats []int16, paramNulls []bool, resultFormats []int16) (PendingOperation, PortalGeneration, error) {
	stmt, ok := s.resolveStatementPtr(statementName)
	if !ok {
		return PendingOperation{}, PortalGeneration{}, ErrUnknownStatement
	}

	genID, err := s.allocGeneration()
	if err != nil {
		return PendingOperation{}, PortalGeneration{}, err
	}
	opID, err := s.allocOp()
	if err != nil {
		return PendingOperation{}, PortalGeneration{}, err
	}

	gen := &PortalGeneration{
		ID:            genID,
		Name:          portalName,
		StatementID:   stmt.ID,
		ParamFormats:  append([]int16(nil), paramFormats...),
		ParamNulls:    append([]bool(nil), paramNulls...),
		ResultFormats: append([]int16(nil), resultFormats...),
		CreatedCycle:  s.currentCycle,
		State:         LifecyclePending,
	}
	s.portals[genID] = gen
	if portalName == "" {
		s.unnamedPortalCurrent = genID
	}

	op := &PendingOperation{ID: opID, Cycle: s.currentCycle, Kind: OpBind, TargetName: portalName, TargetGeneration: genID}
	s.pendingOps = append(s.pendingOps, op)
	return copyPendingOperation(op), copyPortalGeneration(gen), nil
}

// --- Describe / Execute olusturma -----------------------------------------

// CreateDescribeStatement, bilinen (committed ya da gecerli sekilde
// pending) bir statement icin bir Describe islemi kaydeder. Bilinmiyorsa
// ErrUnknownStatement doner.
func (s *State) CreateDescribeStatement(name string) (PendingOperation, error) {
	stmt, ok := s.resolveStatementPtr(name)
	if !ok {
		return PendingOperation{}, ErrUnknownStatement
	}
	return s.createSimpleOp(OpDescribeStatement, name, stmt.ID)
}

// CreateDescribePortal, bilinen bir portal icin bir Describe islemi
// kaydeder. Bilinmiyorsa ErrUnknownPortal doner.
func (s *State) CreateDescribePortal(name string) (PendingOperation, error) {
	p, ok := s.resolvePortalPtr(name)
	if !ok {
		return PendingOperation{}, ErrUnknownPortal
	}
	return s.createSimpleOp(OpDescribePortal, name, p.ID)
}

// CreateExecute, bilinen bir portal icin bir Execute islemi kaydeder.
// Bilinmiyorsa ErrUnknownPortal doner.
func (s *State) CreateExecute(portalName string) (PendingOperation, error) {
	p, ok := s.resolvePortalPtr(portalName)
	if !ok {
		return PendingOperation{}, ErrUnknownPortal
	}
	return s.createSimpleOp(OpExecute, portalName, p.ID)
}

// createSimpleOp, tek bir tanimlayici tahsisi (allocOp) disinda hicbir
// fallible adim icermez ve bu tahsis herhangi bir durum degisikliginden
// ONCE yapilir - bu yuzden zaten atomiktir (ya tamamen basarili olur ya da
// hicbir yan etki birakmadan hata doner).
func (s *State) createSimpleOp(kind OperationKind, name string, target GenerationID) (PendingOperation, error) {
	opID, err := s.allocOp()
	if err != nil {
		return PendingOperation{}, err
	}
	op := &PendingOperation{ID: opID, Cycle: s.currentCycle, Kind: kind, TargetName: name, TargetGeneration: target}
	s.pendingOps = append(s.pendingOps, op)
	return copyPendingOperation(op), nil
}

// --- Close olusturma -------------------------------------------------------

// CreateCloseStatement, bir Close (statement) islemi kaydeder.
//
// Hedef, Describe/Bind ile AYNI committed-veya-pending cozumleme kurallarini
// (ResolveStatement) kullanarak belirlenir - YALNIZCA committed degil.
// Bu, gecerli bir pipelined akisi (ör. "Parse statement_x" hemen ardindan,
// ParseComplete beklenmeden, "Close statement_x") dogru sekilde destekler:
// PostgreSQL mesajlari sirayla isler, bu yuzden Parse basarili olursa
// ardindan gelen Close o YENI (henuz pending) generation'i basariyla
// kapatabilir.
//
// Gercek protokolde var olmayan bir adi kapatmak hata DEGILDIR (sunucu
// tarafinda no-op) - bu yuzden bu metod, "name" ne committed ne de pending
// bilinen bir generation'a cozumlenmese bile HICBIR ZAMAN hata dondurmez;
// bu durumda dondurulen islemin TargetGeneration'i NoGeneration olur
// (ApplyCloseComplete bunu no-op olarak isler).
//
// Donen PendingOperation.TargetGeneration, bu cagri anindaki DEGISMEZ bir
// goruntudur (snapshot): isim eslemeleri (ör. ayni ad baska bir generation'a
// tasinsa) sonradan degisse bile, ApplyCloseComplete HER ZAMAN bu ayni,
// yakalanmis generation'i hedefler - ismi asla YENIDEN cozumlemez.
func (s *State) CreateCloseStatement(name string) (PendingOperation, error) {
	target := NoGeneration
	if g, ok := s.resolveStatementPtr(name); ok {
		target = g.ID
	}
	return s.createSimpleOp(OpCloseStatement, name, target)
}

// CreateClosePortal, CreateCloseStatement ile ayni kurallari (committed-
// veya-pending cozumleme, degismez snapshot, var-olmayan-ad icin no-op)
// portal'lar icin uygular.
func (s *State) CreateClosePortal(name string) (PendingOperation, error) {
	target := NoGeneration
	if g, ok := s.resolvePortalPtr(name); ok {
		target = g.ID
	}
	return s.createSimpleOp(OpClosePortal, name, target)
}

// --- Sync / cycle olusturma ------------------------------------------------

// CreateSync, mevcut cycle icin bir Sync islemi kaydeder ("Sync'i
// kaydetmek" - registering Sync). Bu cagri, mevcut cycle'i KAPATIR: bu
// noktadan sonra olusturulan her islem YENI bir cycle'a ait olur. Donen
// PendingOperation.Cycle, KAPANAN (yeni degil) cycle'a aittir.
//
// Atomiklik: hem pending-op ID'si hem de yeni cycle ID'si, pendingOps/
// outstandingSyncCycles/currentCycle degistirilmeden ONCE tahsis edilir -
// ikinci tahsis (allocCycle) basarisiz olursa, ilk basarili tahsisin
// (allocOp) hicbir gozlemlenebilir yan etkisi olmamistir.
func (s *State) CreateSync() (PendingOperation, error) {
	opID, err := s.allocOp()
	if err != nil {
		return PendingOperation{}, err
	}
	newCycle, err := s.allocCycle()
	if err != nil {
		return PendingOperation{}, err
	}

	closingCycle := s.currentCycle
	op := &PendingOperation{ID: opID, Cycle: closingCycle, Kind: OpSync}
	s.pendingOps = append(s.pendingOps, op)
	s.outstandingSyncCycles = append(s.outstandingSyncCycles, closingCycle)
	s.currentCycle = newCycle
	return copyPendingOperation(op), nil
}

// CurrentCycle, su an yeni islemlerin damgalanacagi (henuz Sync ile
// kapatilmamis) cycle ID'sini dondurur.
func (s *State) CurrentCycle() CycleID {
	return s.currentCycle
}

// --- Backend onayi (acknowledgement) uygulama ------------------------------

// popHead, kuyruk basindaki islemi, ID'sinin "id" ile ve turunun
// "wantKinds" kumesinden biriyle eslestigini dogrulayarak kuyruktan
// cikarir. Kuyruk bosysa ya da ID eslesmiyorsa ErrAckOrderMismatch,
// ID eslesip tur eslesmiyorsa ErrAckKindMismatch doner.
func (s *State) popHead(id PendingOperationID, wantKinds ...OperationKind) (*PendingOperation, error) {
	if len(s.pendingOps) == 0 {
		return nil, ErrAckOrderMismatch
	}
	head := s.pendingOps[0]
	if head.ID != id {
		return nil, ErrAckOrderMismatch
	}
	matched := false
	for _, k := range wantKinds {
		if head.Kind == k {
			matched = true
			break
		}
	}
	if !matched {
		return nil, ErrAckKindMismatch
	}
	s.pendingOps = s.pendingOps[1:]
	return head, nil
}

// ApplyParseComplete, "id" bekleyen Parse islemine gercek sunucudan
// ParseComplete geldigini bildirir: generation "committed" olur ve
// (isimliyse) adin committed haritasina yazilir.
//
// Donen deger, dahili durumun bagimsiz bir kopyasidir.
func (s *State) ApplyParseComplete(id PendingOperationID) (StatementGeneration, error) {
	op, err := s.popHead(id, OpParse)
	if err != nil {
		return StatementGeneration{}, err
	}
	gen, ok := s.statements[op.TargetGeneration]
	if !ok {
		return StatementGeneration{}, ErrUnknownGeneration
	}
	gen.State = LifecycleCommitted
	if gen.Name != "" {
		s.namedStatementCommitted[gen.Name] = gen.ID
	}
	s.cleanup()
	return copyStatementGeneration(gen), nil
}

// ApplyBindComplete, ApplyParseComplete ile ayni kurallari Bind/portal
// icin uygular.
//
// Donen deger, dahili durumun bagimsiz bir kopyasidir.
func (s *State) ApplyBindComplete(id PendingOperationID) (PortalGeneration, error) {
	op, err := s.popHead(id, OpBind)
	if err != nil {
		return PortalGeneration{}, err
	}
	gen, ok := s.portals[op.TargetGeneration]
	if !ok {
		return PortalGeneration{}, ErrUnknownGeneration
	}
	gen.State = LifecycleCommitted
	if gen.Name != "" {
		s.namedPortalCommitted[gen.Name] = gen.ID
	}
	s.cleanup()
	return copyPortalGeneration(gen), nil
}

// ApplyCloseComplete, "id" bekleyen Close islemine gercek sunucudan
// CloseComplete geldigini bildirir. Hedef generation, Close olusturuldugu
// andaki DEGISMEZ goruntudur (isim eslemeleri sonradan degismis olsa bile,
// ya da hedef generation Close olusturuldugunda hala pending idiyse ve o
// sirada zaten commit/fail olmus olsa bile) - isim BURADA YENIDEN
// COZUMLENMEZ, yalnizca yakalanmis TargetGeneration kullanilir.
//
//   - Statement kapatma basarili olursa: statement kaldirilir VE o TAM
//     generation'dan olusturulmus her portal da kaldirilir (cascade).
//   - Portal kapatma basarili olursa: yalnizca o portal kaldirilir.
//   - Hedef NoGeneration ise (Close, var olmayan bir adi hedeflemisti):
//     hicbir sey kaldirilmaz - bu bir hata degildir (gercek sunucu
//     davranisiyla ayni).
func (s *State) ApplyCloseComplete(id PendingOperationID) error {
	op, err := s.popHead(id, OpCloseStatement, OpClosePortal)
	if err != nil {
		return err
	}
	if op.TargetGeneration == NoGeneration {
		s.cleanup()
		return nil
	}

	switch op.Kind {
	case OpCloseStatement:
		if gen, ok := s.statements[op.TargetGeneration]; ok {
			s.detachStatementPointer(gen)
			delete(s.statements, op.TargetGeneration)
		}
		for pid, p := range s.portals {
			if p.StatementID == op.TargetGeneration {
				s.detachPortalPointer(p)
				delete(s.portals, pid)
			}
		}
	case OpClosePortal:
		if p, ok := s.portals[op.TargetGeneration]; ok {
			s.detachPortalPointer(p)
			delete(s.portals, op.TargetGeneration)
		}
	}
	s.cleanup()
	return nil
}

func (s *State) detachStatementPointer(gen *StatementGeneration) {
	if gen.Name != "" {
		if cur, ok := s.namedStatementCommitted[gen.Name]; ok && cur == gen.ID {
			delete(s.namedStatementCommitted, gen.Name)
		}
		return
	}
	if s.unnamedStatementCurrent == gen.ID {
		s.unnamedStatementCurrent = NoGeneration
	}
}

func (s *State) detachPortalPointer(gen *PortalGeneration) {
	if gen.Name != "" {
		if cur, ok := s.namedPortalCommitted[gen.Name]; ok && cur == gen.ID {
			delete(s.namedPortalCommitted, gen.Name)
		}
		return
	}
	if s.unnamedPortalCurrent == gen.ID {
		s.unnamedPortalCurrent = NoGeneration
	}
}

// CompleteOperation, Describe (statement/portal) ya da Execute icin -
// gercek protokolde ozel adli tek bir onay mesaji olmayan (ParameterDescription/
// RowDescription/NoData ya da DataRow*/CommandComplete/PortalSuspended
// gibi cok sayida olasi mesajla sonuclanan) - genel BASARILI tamamlanmayi
// isaretler. Parse/Bind/Close/Sync icin KULLANILMAMALIDIR - onlarin kendi
// ozel Apply*Complete/ApplyReadyForQuery metodlari vardir (bkz. yukarida);
// bu kisitlama, bir statement/portal generation'inin dogru terfi mantigi
// atlanarak yanlislikla "committed" sayilmasini engeller.
func (s *State) CompleteOperation(id PendingOperationID) error {
	_, err := s.popHead(id, OpDescribeStatement, OpDescribePortal, OpExecute)
	if err != nil {
		return err
	}
	s.cleanup()
	return nil
}

// ApplyErrorResponse, "id" bekleyen islemine gercek sunucudan (islemin
// kendi beklenen onayi yerine) bir ErrorResponse geldigini bildirir.
//
//   - Parse/Bind: yeni generation "failed" olur. ISIMLI ise onceki
//     committed generation TAMAMEN ETKILENMEZ (hic dokunulmamisti zaten).
//     ISIMSIZ ise "current" isaretci GERI ALINMAZ (eski generation zaten
//     gercek sunucu tarafindan yok edilmisti) - slot bos kalir.
//   - Close (statement/portal): hicbir sey degismez (committed generation
//     korunur) - bu yontem hicbir zaman iyimser (optimistic) kaldirma
//     yapmadigindan basarisiz bir Close'un geri alinacak bir sey yoktur.
//   - Describe/Execute: hicbir generation etkilenmez.
//   - Sync: gercek protokolde imkansizdir (Sync her zaman bir
//     ReadyForQuery ile sonuclanir) - ErrInvalidLifecycleTransition doner.
func (s *State) ApplyErrorResponse(id PendingOperationID) error {
	if len(s.pendingOps) == 0 {
		return ErrAckOrderMismatch
	}
	head := s.pendingOps[0]
	if head.ID != id {
		return ErrAckOrderMismatch
	}
	if head.Kind == OpSync {
		return ErrInvalidLifecycleTransition
	}
	s.pendingOps = s.pendingOps[1:]

	switch head.Kind {
	case OpParse:
		if gen, ok := s.statements[head.TargetGeneration]; ok {
			gen.State = LifecycleFailed
			if gen.Name == "" && s.unnamedStatementCurrent == gen.ID {
				s.unnamedStatementCurrent = NoGeneration
			}
		}
	case OpBind:
		if gen, ok := s.portals[head.TargetGeneration]; ok {
			gen.State = LifecycleFailed
			if gen.Name == "" && s.unnamedPortalCurrent == gen.ID {
				s.unnamedPortalCurrent = NoGeneration
			}
		}
	case OpCloseStatement, OpClosePortal, OpDescribeStatement, OpDescribePortal, OpExecute:
		// Hicbir generation durumu degismez - bkz. yukaridaki dokumantasyon.
	}
	s.cleanup()
	return nil
}

// ApplyReadyForQuery, "id" degil, gercek sunucudan gelen bir ReadyForQuery
// mesajini bildirir. En ESKI bekleyen (outstanding) Sync cycle'i ile FIFO
// olarak eslesir (bkz. docs/design/0001-extended-query.md, "Explicit
// pipeline-cycle identities"). status YALNIZCA 'I'/'T'/'E' olabilir.
//
// status == 'I' ise, YALNIZCA CreatedCycle'i tamamlanan cycle'a ("completed
// cycle") esit ya da ondan KUCUK olan portal kayitlari (isimli ve isimsiz,
// pending ve committed) kaldirilir - bunlarin islem omru bu ReadyForQuery
// sinirinda sona erer. CreatedCycle'i tamamlanan cycle'dan BUYUK olan
// portal'lar (daha sonraki, halihazirda pipeline edilmis bir cycle'a ait)
// KORUNUR - cunku onlarin kendi islemleri henuz bitmemistir (bkz. Duzeltme
// notu asagida). Hazirlanmis deyimler (statements) hicbir zaman bu sekilde
// kaldirilmaz.
//
// DUZELTME: onceki bir revizyon burada TUM portal kayitlarini kosulsuzca
// (cycle'a bakmaksizin) temizliyordu. Bu, birden fazla Sync-sinirli cycle
// pipeline edildiginde GUVENSIZDI: cycle 2'nin bir portali (ör. Bind
// portal_2), cycle 1'in ReadyForQuery'si daha donmeden yerel olarak zaten
// kayitli olabilir - cycle 1'in ReadyForQuery('I')'si bu durumda cycle 2'ye
// ait portal_2'yi de (sirf o an yerel state'te var oldugu icin) hatalicasina
// silerdi. Duzeltilen kural, CreatedCycle degerini tamamlanan cycle ID'siyle
// karsilastirarak yalnizca GERCEKTEN o sinirlanan islem omrune ait
// portal'lari kaldirir.
func (s *State) ApplyReadyForQuery(status byte) (CycleID, error) {
	if status != TxStatusIdle && status != TxStatusInTransaction && status != TxStatusFailedTransaction {
		return NoCycle, ErrInvalidTransactionStatus
	}
	if len(s.outstandingSyncCycles) == 0 {
		return NoCycle, ErrCycleClosed
	}
	if len(s.pendingOps) == 0 || s.pendingOps[0].Kind != OpSync {
		return NoCycle, ErrAckOrderMismatch
	}
	op := s.pendingOps[0]

	completedCycle := s.outstandingSyncCycles[0]
	if op.Cycle != completedCycle {
		return NoCycle, ErrAckOrderMismatch
	}
	s.pendingOps = s.pendingOps[1:]
	s.outstandingSyncCycles = s.outstandingSyncCycles[1:]

	s.txStatus = status
	if status == TxStatusIdle {
		s.invalidatePortalsThroughCycle(completedCycle)
	}
	s.cleanup()
	return completedCycle, nil
}

// invalidatePortalsThroughCycle, CreatedCycle'i "completedCycle" ya da ondan
// ONCEKI (kucuk esit) olan her portal kaydini kaldirir - bu, o cycle'in
// kapanmasiyla (ReadyForQuery('I')) sona eren islem omrune ait tum
// portal'lari, ondan SONRAKI (daha buyuk CreatedCycle'a sahip) - halihazirda
// pipeline edilmis, henuz kendi Sync/ReadyForQuery'sine ulasmamis - portal'lara
// DOKUNMADAN kaldirir (bkz. ApplyReadyForQuery dokumantasyonu).
func (s *State) invalidatePortalsThroughCycle(completedCycle CycleID) {
	for id, p := range s.portals {
		if p.CreatedCycle > completedCycle {
			continue
		}
		s.detachPortalPointer(p)
		delete(s.portals, id)
	}
}

// TransactionStatus, en son ApplyReadyForQuery cagrisiyla bildirilen islem
// durumunu dondurur (baslangicta TxStatusIdle).
func (s *State) TransactionStatus() byte {
	return s.txStatus
}

// --- Simple Query yardimcisi -----------------------------------------------

// ApplyAllowedSimpleQuery, Policy tarafindan IZIN VERILEN (Block edilmemis)
// bir Simple Query ('Q') mesaji gercek sunucuya iletilecegi/iletildigi anda
// cagrilmalidir - engellenen bir Simple Query icin bu metod hic
// CAGRILMAMALIDIR (bu, "hicbir degisiklik yok" davranisinin nasil temsil
// edildigidir).
//
// Mevcut isimsiz statement ve isimsiz portal "current" isaretcilerini
// HEMEN temizler (gercek sunucunun Simple Query islemeye baslarken kendi
// isimsiz nesnelerini yok etmesini yansitir - bkz. docs/design/
// 0001-extended-query.md, "Mixed Simple/Extended Query state handling").
// Isimli statement'lar ve portal'lar ETKILENMEZ. Hala bir portal
// tarafindan referans verilen tarihsel (historical) generation'lar
// (varsa) dahili olarak kalmaya devam eder.
func (s *State) ApplyAllowedSimpleQuery() {
	s.unnamedStatementCurrent = NoGeneration
	s.unnamedPortalCurrent = NoGeneration
	s.cleanup()
}

// --- Temizlik (cleanup) -----------------------------------------------------

// cleanup, artik hicbir sekilde erisilemeyen (referans verilmeyen) statement
// ve portal generation kayitlarini kaldirir. Bir generation'in kaldirilmaya
// uygun olmasi icin UCU KOSUL birden de saglanmalidir:
//
//  1. onu hedefleyen bekleyen (pending) hicbir islem yok (bu, henuz
//     onaylanmamis - "pending" durumundaki - generation'larin YANLISLIKLA
//     erken kaldirilmasini da yapisal olarak engeller, cunku pending bir
//     generation'in kendi Parse/Bind islemi onaylanana kadar kuyrukta
//     kalir)
//  2. (yalnizca statement icin) onu referans veren hicbir portal yok
//  3. su an isim/isimsiz-slot eslemesinde "current" degil
//
// Bu, gereksinim maddesindeki kurali dogrudan uygular: "statement
// generations with no current name mapping, no pending operation and no
// live portal references."
func (s *State) cleanup() {
	s.cleanupPortals()
	s.cleanupStatements()
}

func (s *State) cleanupStatements() {
	for id, gen := range s.statements {
		if s.pendingOpTargets(id, OpParse, OpDescribeStatement, OpCloseStatement) {
			continue
		}
		if s.portalReferencesStatement(id) {
			continue
		}
		if gen.Name == "" {
			if s.unnamedStatementCurrent == id {
				continue
			}
		} else if cur, ok := s.namedStatementCommitted[gen.Name]; ok && cur == id {
			continue
		}
		delete(s.statements, id)
	}
}

func (s *State) cleanupPortals() {
	for id, gen := range s.portals {
		if s.pendingOpTargets(id, OpBind, OpDescribePortal, OpExecute, OpClosePortal) {
			continue
		}
		if gen.Name == "" {
			if s.unnamedPortalCurrent == id {
				continue
			}
		} else if cur, ok := s.namedPortalCommitted[gen.Name]; ok && cur == id {
			continue
		}
		delete(s.portals, id)
	}
}

func (s *State) pendingOpTargets(id GenerationID, kinds ...OperationKind) bool {
	for _, op := range s.pendingOps {
		if op.TargetGeneration != id {
			continue
		}
		for _, k := range kinds {
			if op.Kind == k {
				return true
			}
		}
	}
	return false
}

func (s *State) portalReferencesStatement(id GenerationID) bool {
	for _, p := range s.portals {
		if p.StatementID == id {
			return true
		}
	}
	return false
}

// --- Sayim/anlik-goruntu (snapshot) yardimcilari (testler icin) -----------

func (s *State) StatementCount() int        { return len(s.statements) }
func (s *State) PortalCount() int           { return len(s.portals) }
func (s *State) PendingOperationCount() int { return len(s.pendingOps) }
func (s *State) OutstandingCycleCount() int { return len(s.outstandingSyncCycles) }

// PendingOperations, kuyruktaki islemlerin sirali, bagimsiz bir
// KOPYASINI dondurur (yalnizca testler/gozlem icin - dahili kuyrugu
// degistirmez; donen dilimi ya da elemanlarini degistirmek State'i
// etkilemez).
func (s *State) PendingOperations() []PendingOperation {
	out := make([]PendingOperation, len(s.pendingOps))
	for i, op := range s.pendingOps {
		out[i] = copyPendingOperation(op)
	}
	return out
}

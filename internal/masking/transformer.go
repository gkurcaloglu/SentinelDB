package masking

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// maskKindEmail, internal/wasmproto.KindEmail'in bu paketteki takma adıdır
// (wasmproto'ya doğrudan bağımlılığı yalnızca bu tek sabitle sınırlamak
// için). V1'de desteklenen tek maskeleme türü budur.
const maskKindEmail = "email"

// Masker, tek bir hücre değerini maskeleyen alt sistemi soyutlar. Gerçek
// implementasyon internal/wasm.Masker (mevcut, tek yüklü Wasm eklentisi
// üzerinden çalışır); testlerde sahte bir Masker enjekte etmek mümkündür.
type Masker interface {
	Mask(ctx context.Context, column, kind, value string) (maskedValue string, changed bool, reason string, err error)
}

// Hooks, Transformer'ın gözlem/metrik amaçlı çağırdığı isteğe bağlı geri
// çağrılardır. Hiçbiri hücre DEĞERİ almaz - yalnızca sütun adı, karar ve
// zamanlama gibi güvenli metadata.
type Hooks struct {
	// OnMessage, iletilen/dönüştürülen her backend mesajı için çağrılır
	// (loglama amaçlı).
	OnMessage func(m protocol.Message)
	// OnMaskAttempt, maskelenmesi yapılandırılmış her hücre için (başarılı
	// ya da başarısız) çağrılır; metrik/log amaçlıdır.
	OnMaskAttempt func(column string, changed bool, err error, duration time.Duration)
	// OnError, bir ayrıştırma/dönüştürme hatası (fail-closed'a yol açan)
	// oluştuğunda çağrılır.
	OnError func(err error)
}

// Transformer, server -> client yönünü gözlemleyen eski salt-gözlemci
// SniffReader'ın yerini alan aktif bir bileşendir: RowDescription ile
// gelen sütun düzenini bağlantı başına saklar, sonraki DataRow
// mesajlarında yapılandırılmış sütunları Wasm eklentisi aracılığıyla
// maskeler ve mesajları orijinal sırasıyla, değişmeyenleri olduğu gibi,
// client'a yazar.
//
// V1 sınırlamaları (bilerek):
//   - İkili (format code != 0) hedef sütunlar desteklenmez; fail-closed.
//   - COPY protokolü desteklenmez; fail-closed.
//   - Genişletilmiş sorgu protokolü zaten firewall.Gate tarafından
//     reddedildiğinden burada görülmez.
//   - Hücre değerleri, client_encoding'in UTF-8 olduğu varsayılarak
//     Go string'ine çevrilir; başka bir kodlama kullanan bağlantılar için
//     bu varsayım geçerli olmayabilir (V1 kapsamı dışında).
type Transformer struct {
	ctx     context.Context
	dec     *protocol.Decoder
	client  io.Writer
	masker  Masker
	cfg     Config
	txState *protocol.TxState
	hooks   Hooks
	err     error

	// Mevcut sonuç kümesinin (result set) durumu.
	fields     []protocol.RowField
	maskColIdx []int // fields icindeki, maskelenecek sutunlarin indeksleri
}

// NewTransformer, verilen Config ve Masker ile bir Transformer oluşturur.
// ctx, bağlantının kök/iptal edilebilir context'idir; her Mask çağrısına
// AYNEN geçilir (yeni bir context.Background() ÜRETİLMEZ) - böylece
// gateway kapatılırken (ctx iptal edildiğinde) devam eden bir mask_value
// çağrısı da hemen sonlandırılabilir. client, izin verilen/dönüştürülen
// tüm baytların yazılacağı gerçek client bağlantısıdır (tipik olarak bir
// *protocol.SerializedWriter, bkz. görev F). txState nil olabilir (bu
// durumda ReadyForQuery durumu takip edilmez).
func NewTransformer(ctx context.Context, cfg Config, masker Masker, client io.Writer, txState *protocol.TxState, hooks Hooks) *Transformer {
	if ctx == nil {
		ctx = context.Background()
	}
	t := &Transformer{ctx: ctx, cfg: cfg, masker: masker, client: client, txState: txState, hooks: hooks}
	t.dec = protocol.NewServerDecoder(t.handle, t.handleDecodeError)
	return t
}

// Run, server'dan (gerçek PostgreSQL bağlantısı) EOF olana ya da bir hata
// oluşana kadar okur. Okunan her tam mesaj işlenip client'a iletilir; her
// zaman aynı anda en fazla bir tam mesaj işlenir (sonuç kümesi asla
// sınırsız biriktirilmez). Normal kapanışta nil, fail-closed durumlarda
// ErrMaskingFailed (bkz. IsFailClosed), aksi halde oluşan G/Ç hatası
// döndürülür.
func (t *Transformer) Run(server io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := server.Read(buf)
		if n > 0 {
			t.dec.Write(buf[:n])
			if t.err != nil {
				return t.err
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

func (t *Transformer) handle(m protocol.Message) {
	if t.err != nil {
		return
	}
	if t.hooks.OnMessage != nil {
		t.hooks.OnMessage(m)
	}

	switch m.Type {
	case protocol.MsgRowDescription:
		t.handleRowDescription(m)
	case protocol.MsgDataRow:
		t.handleDataRow(m)
	case protocol.MsgCopyInResponse, protocol.MsgCopyOutResponse, protocol.MsgCopyBothResponse:
		// SentinelDB V1, COPY protokolunu desteklemez: COPY sirasindaki
		// veri akisi DataRow cercevesine uymaz ve maskeleme denetiminden
		// gecmez. Sessizce iletmek yerine acikca reddediyoruz.
		t.failClosed(fmt.Errorf("COPY protokolu bu surumde desteklenmiyor (mesaj: %s)", m.Name))
	case protocol.MsgCommandComplete, protocol.MsgErrorResponse:
		t.clearResultSet()
		t.forwardRaw(m)
	case protocol.MsgReadyForQuery:
		if t.txState != nil && len(m.Raw) >= 6 {
			t.txState.Set(m.Raw[5]) // tag(1) + length(4) + status(1)
		}
		t.clearResultSet()
		t.forwardRaw(m)
	default:
		t.forwardRaw(m)
	}
}

func (t *Transformer) handleRowDescription(m protocol.Message) {
	if len(m.Raw) < 5 {
		t.failClosed(fmt.Errorf("RowDescription govdesi cok kisa"))
		return
	}
	rd, err := protocol.ParseRowDescription(m.Raw[5:])
	if err != nil {
		t.failClosed(fmt.Errorf("RowDescription ayristirilamadi: %w", err))
		return
	}

	t.fields = rd.Fields
	t.maskColIdx = t.maskColIdx[:0]
	if t.cfg.Enabled {
		for i, f := range rd.Fields {
			if t.cfg.ShouldMask(f.Name) {
				t.maskColIdx = append(t.maskColIdx, i)
			}
		}
	}

	// RowDescription'in kendisi (sutun meta verisi) hic degistirilmez;
	// yalnizca DataRow hucreleri maskelenir.
	t.forwardRaw(m)
}

func (t *Transformer) handleDataRow(m protocol.Message) {
	if len(m.Raw) < 5 {
		t.failClosed(fmt.Errorf("DataRow govdesi cok kisa"))
		return
	}

	if len(t.maskColIdx) == 0 {
		// Bu sonuc kumesinde maskelenecek hicbir sutun yok (ya da hic
		// RowDescription gorulmedi); hucreleri ayristirmaya bile gerek yok.
		t.forwardRaw(m)
		return
	}

	row, err := protocol.ParseDataRow(m.Raw[5:])
	if err != nil {
		t.failClosed(fmt.Errorf("DataRow ayristirilamadi: %w", err))
		return
	}
	if len(row.Cells) != len(t.fields) {
		t.failClosed(fmt.Errorf("DataRow alan sayisi RowDescription ile uyusmuyor: %d != %d", len(row.Cells), len(t.fields)))
		return
	}

	changed := false
	for _, idx := range t.maskColIdx {
		cell := row.Cells[idx]
		if cell.Null {
			// NULL degerler icin eklenti hic cagrilmaz.
			continue
		}

		field := t.fields[idx]
		if field.FormatCode != 0 {
			// V1: yalnizca metin format kodu (0) destekleniyor. Binary
			// veriyi metin gibi maskelemeye calismak veriyi sessizce
			// bozabilir; bunun yerine acikca reddediyoruz.
			t.failClosed(fmt.Errorf("maskelenecek sutun %q ikili (binary) formatta, V1 bunu desteklemiyor", field.Name))
			return
		}

		start := time.Now()
		maskedValue, valueChanged, _, maskErr := t.masker.Mask(t.ctx, field.Name, maskKindEmail, string(cell.Value))
		duration := time.Since(start)
		if t.hooks.OnMaskAttempt != nil {
			t.hooks.OnMaskAttempt(field.Name, valueChanged, maskErr, duration)
		}
		if maskErr != nil {
			t.failClosed(fmt.Errorf("sutun %q maskelenemedi: %w", field.Name, maskErr))
			return
		}
		if !valueChanged {
			continue
		}

		newRow, cellErr := row.WithCell(idx, protocol.DataCell{Value: []byte(maskedValue)})
		if cellErr != nil {
			t.failClosed(fmt.Errorf("hucre guncellenemedi: %w", cellErr))
			return
		}
		row = newRow
		changed = true
	}

	if !changed {
		t.forwardRaw(m)
		return
	}
	t.forwardBytes(row.Build())
}

func (t *Transformer) clearResultSet() {
	t.fields = nil
	t.maskColIdx = t.maskColIdx[:0]
}

func (t *Transformer) forwardRaw(m protocol.Message) {
	t.forwardBytes(m.Raw)
}

func (t *Transformer) forwardBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	if _, err := t.client.Write(b); err != nil {
		t.err = err
	}
}

// failClosed, işlemeye devam edip potansiyel olarak maskelenmemiş bir
// değeri sessizce geçirmek yerine, istemciye bir FATAL ErrorResponse yazıp
// bağlantıyı kapatmayı işaretler.
func (t *Transformer) failClosed(err error) {
	if t.err != nil {
		return
	}
	if t.hooks.OnError != nil {
		t.hooks.OnError(err)
	}
	const reason = "SentinelDB: yanit islenirken bir hata olustu, baglanti guvenlik icin kapatildi"
	t.client.Write(protocol.BuildErrorResponse("FATAL", "58030", reason))
	t.err = fmt.Errorf("%w: %v", ErrMaskingFailed, err)
}

func (t *Transformer) handleDecodeError(err error) {
	if t.hooks.OnError != nil {
		t.hooks.OnError(err)
	}
	if t.err != nil {
		return
	}
	const reason = "SentinelDB: sunucu yaniti ayristirilamadi, baglanti guvenlik icin kapatildi"
	t.client.Write(protocol.BuildErrorResponse("FATAL", "08P01", reason))
	t.err = fmt.Errorf("%w: %v", ErrMaskingFailed, err)
}

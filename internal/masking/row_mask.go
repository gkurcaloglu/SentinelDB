package masking

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// MaskTarget, bir RowMaskPlan icinde maskelenmesi gereken TEK bir sutunu
// tanimlar. ColumnName yalnizca Masker'a gecirilir (bkz. Masker arayuzu);
// hicbir yerde loglanmaz/saklanmaz.
type MaskTarget struct {
	// Index, DataRow icindeki 0-tabanli hucre indeksidir.
	Index int
	// ColumnName, RowDescription'dan gelen sutun adidir (Masker'in "kind"
	// kuralini secmesi icin kullanilir).
	ColumnName string
	// FormatCode, bu sutun icin GECERLI backend format kodudur (0=metin,
	// 1=ikili). Ikili hedef sutunlar desteklenmez (bkz. MaskDataRow).
	FormatCode int16
}

// RowMaskPlan, tek bir sonuc seklinin (statement/portal Describe ya da
// Simple Query RowDescription'i ile belirlenen) degismez, G/C icermeyen
// maskeleme planidir.
type RowMaskPlan struct {
	// KnownNoData true ise, bu plan bir Describe NoData yanitindan
	// turetilmistir: bu statement/portal'in HICBIR ZAMAN DataRow
	// uretmeyecegi BILINIR (ColumnCount/Targets bu durumda anlamsizdir,
	// her zaman sifir degerindedir). Boyle bir sekil icin bir DataRow
	// GORULMESI protokol acisindan IMKANSIZDIR - MaskDataRow bunu ASLA
	// "hicbir maskeleme yukumlulugu yok, oldugu gibi ilet" (bos, hedefsiz
	// bir plan) ile KARISTIRMAZ; ErrUnexpectedDataRowForNoData ile fail-
	// closed reddeder. Bos-hedefli-ama-satir-uretebilen bir sekil (bilinen
	// sutunlu ama hicbir sutunu maskeleme hedefi olmayan) KnownNoData=false
	// olarak kalir ve DataRow'lari normal sekilde degismeden iletir.
	KnownNoData bool
	// ColumnCount, DataRow'daki beklenen toplam hucre sayisidir (yalnizca
	// Targets bos olmadiginda dogrulanir).
	ColumnCount int
	Targets     []MaskTarget
}

// cloneRowMaskPlan, plan'in TAMAMEN bagimsiz bir derin kopyasini dondurur -
// donen deger, orijinalin Targets dilimiyle (ya da onun alttaki dizisiyle)
// HICBIR belleği paylasmaz. MaskTarget alanlarinin hicbiri (int/string/
// int16) baska bir mutable referans tasimadigindan, dilimin kendisini taze
// bir dizi uzerinde kopyalamak TAM bir derin kopya icin yeterlidir.
func cloneRowMaskPlan(plan RowMaskPlan) RowMaskPlan {
	out := RowMaskPlan{KnownNoData: plan.KnownNoData, ColumnCount: plan.ColumnCount}
	if len(plan.Targets) > 0 {
		out.Targets = make([]MaskTarget, len(plan.Targets))
		copy(out.Targets, plan.Targets)
	}
	return out
}

// --- Sabit, guvenli hata kategorileri --------------------------------------
//
// HICBIRI, altta yatan (parser/Masker/DataRow-mutasyon) hatasini SARMAZ
// (%w YOK) - bu bilincli bir tasarim karari: bir DataRow ayristirma hatasi
// ham baytlarin bir kismini icerebilir, bir Masker hatasi (masker uygulamasi
// SentinelDB'nin kontrolu DISINDADIR) girdi hucre degerini/sutun adini
// icerebilir. Bu turlerin ICERIGI, MaskDataRow'un DONDURDUGU hatada ASLA
// gorunmez - yalnizca (mevcut sozlesmeyi koruyarak) Hooks.OnMaskAttempt'e
// ORIJINAL Masker hatasi GECIRILIR, hicbir yerde SAKLANMAZ.
var (
	// ErrInvalidDataRowFrame, verilen frame tam, tek, gecerli bir DataRow
	// cercevesi (dogru tag + tutarli uzunluk alani + gecerli govde yapisi,
	// eksiksiz ve fazlasiz) OLMADIGINDA donulur.
	ErrInvalidDataRowFrame = errors.New("masking: gecersiz DataRow cercevesi")
	// ErrInvalidRowMaskPlan, plan kendi icinde tutarsizsa (negatif sutun
	// sayisi, aralik disi hedef indeksi, DataRow.WithCell'in reddettigi
	// bir mutasyon) donulur.
	ErrInvalidRowMaskPlan = errors.New("masking: gecersiz maskeleme plani")
	// ErrDataRowShapeMismatch, ayristirilan DataRow'un hucre sayisi
	// plan.ColumnCount ile uyusmadiginda donulur.
	ErrDataRowShapeMismatch = errors.New("masking: DataRow sekli beklenen plan ile uyusmuyor")
	// ErrRowMaskBinaryTarget, yapilandirilmis bir maskeleme hedefi
	// sutununun GERCEK format kodu ikili (1) oldugunda donulur.
	ErrRowMaskBinaryTarget = errors.New("masking: maskeleme hedefi sutun ikili formatta")
	// ErrMaskerInvocationFailed, Masker.Mask hata dondurdugunde donulur.
	// ORIJINAL Masker hatasi burada ASLA sarilmaz/saklanmaz - yalnizca bu
	// sabit kategori disariya cikar (bkz. dosya basi).
	ErrMaskerInvocationFailed = errors.New("masking: Masker cagrisi basarisiz")
	// ErrUnexpectedDataRowForNoData, plan.KnownNoData true iken bir DataRow
	// alindiginda donulur - bu, protokol acisindan IMKANSIZ bir durumdur
	// (bkz. RowMaskPlan.KnownNoData) ve HER ZAMAN fail-closed reddedilir.
	ErrUnexpectedDataRowForNoData = errors.New("masking: bilinen NoData sekli icin beklenmeyen DataRow")
)

// validateCompleteDataRowFrame, frame'in TAM, TEK, gecerli bir DataRow
// cercevesi (protocol.MsgDataRow tag'i + 4 baytlik uzunluk alani + TUTARLI
// govde) oldugunu, herhangi bir maskeleme yukumlulugune BAKMAKSIZIN
// dogrular ve ayristirilmis govdeyi dondurur. Su kontrolleri uygular: (1)
// en az tag+uzunluk (5 bayt); (2) tag == protocol.MsgDataRow; (3) uzunluk
// alani guvenle okunur; (4) uzunluk >= 4; (5) 1+uzunluk == len(frame)
// (TAM OLARAK - ne eksik ne fazla/artik bayt/ikinci bir cerceve); (6)
// govde protocol.ParseDataRow ile yapisal olarak gecerli. Hicbir hata
// mesaji tag/uzunluk/hucre sayisi/deger/ham bayt icermez - yalnizca sabit
// ErrInvalidDataRowFrame donulur.
func validateCompleteDataRowFrame(frame []byte) (*protocol.DataRow, error) {
	if len(frame) < 5 {
		return nil, ErrInvalidDataRowFrame
	}
	if protocol.MessageType(frame[0]) != protocol.MsgDataRow {
		return nil, ErrInvalidDataRowFrame
	}
	length := binary.BigEndian.Uint32(frame[1:5])
	if length < 4 {
		return nil, ErrInvalidDataRowFrame
	}
	// int64 aritmetigi, 32-bit platformlarda dahi int tasmasi riskini
	// tamamen ortadan kaldirir (length en fazla 2^32-1, len(frame) her
	// zaman >= 0 bir int'tir - ikisi de int64'e kayipsiz sigar).
	if int64(1)+int64(length) != int64(len(frame)) {
		return nil, ErrInvalidDataRowFrame
	}
	row, err := protocol.ParseDataRow(frame[5:])
	if err != nil {
		return nil, ErrInvalidDataRowFrame
	}
	return row, nil
}

// MaskDataRow, plan'a gore TEK bir tam DataRow cercevesini (tag 'D' +
// 4 baytlik uzunluk + govde, protocol.NewServerDecoder/Message.Raw ile
// aynı bicimde) maskeler.
//
// Bu fonksiyon:
//   - hicbir soket G/C'si yapmaz, hicbir goroutine baslatmaz;
//   - frame'i ya da herhangi bir hucre degerini cagri dondukten sonra
//     saklamaz;
//   - TAM OLARAK bir DataRow cercevesi bekler (bir akis DEGIL) - govde
//     yapisi HER ZAMAN dogrulanir (bkz. validateCompleteDataRowFrame),
//     plan.Targets bos olsa BILE (hicbir maskeleme yukumlulugu olmayan
//     bir satir bile yapisal olarak gecersiz olabilir ve fail-closed
//     reddedilmelidir - "hedefsiz oldugu icin dogrulanmadan gecti" ASLA
//     dogru degildir);
//   - plan.KnownNoData true ise (bkz. RowMaskPlan.KnownNoData) HERHANGI
//     bir DataRow'u ErrUnexpectedDataRowForNoData ile reddeder - bu,
//     "hedefsiz, hicbir yukumlulugu olmayan plan" durumundan AYRI ve ONCE
//     kontrol edilir;
//   - plan.Targets bos degilse, hucre sayisinin plan.ColumnCount ile
//     uyustugunu dogrular;
//   - NULL hedef hucreler icin Masker'i HIC cagirmaz;
//   - ikili (FormatCode != 0) bir hedef sutuna, o sutunun degeri NULL
//     olmadigi surece, ulasilirsa reddeder (fail-closed);
//   - yalnizca yapilandirilmis hedef hucreler icin Masker'i cagirir, ctx'i
//     AYNEN gecirir;
//   - degisen hucreleri protocol.DataRow.WithCell/Build ile yeniden insa
//     eder;
//   - donen hatalar HER ZAMAN sabit, guvenli kategorilerdir (bkz. dosya
//     basi) - hicbir zaman hucre degeri, sutun adi, ham cerceve ya da
//     altta yatan parser/Masker/mutasyon hatasinin metnini SARMAZ/icermez.
//
// changed, donen baytlarin frame'den farkli olup olmadigini bildirir;
// yalnizca gozlem/metrik amaclidir - cagiran bunu DEGER ifsa etmek icin
// KULLANMAMALIDIR.
func MaskDataRow(ctx context.Context, masker Masker, plan RowMaskPlan, frame []byte, hooks Hooks) ([]byte, bool, error) {
	row, err := validateCompleteDataRowFrame(frame)
	if err != nil {
		return nil, false, err
	}

	if plan.KnownNoData {
		return nil, false, ErrUnexpectedDataRowForNoData
	}
	if plan.ColumnCount < 0 {
		return nil, false, ErrInvalidRowMaskPlan
	}

	if len(plan.Targets) == 0 {
		out := make([]byte, len(frame))
		copy(out, frame)
		return out, false, nil
	}

	if len(row.Cells) != plan.ColumnCount {
		return nil, false, ErrDataRowShapeMismatch
	}

	changed := false
	for _, target := range plan.Targets {
		if target.Index < 0 || target.Index >= len(row.Cells) {
			return nil, false, ErrInvalidRowMaskPlan
		}
		cell := row.Cells[target.Index]
		if cell.Null {
			// NULL degerler icin Masker hic cagrilmaz.
			continue
		}
		if target.FormatCode != 0 {
			// Ikili veriyi metin gibi maskelemeye calismak veriyi sessizce
			// bozabilir; bunun yerine acikca reddediyoruz.
			return nil, false, ErrRowMaskBinaryTarget
		}

		start := time.Now()
		maskedValue, valueChanged, _, maskErr := masker.Mask(ctx, target.ColumnName, maskKindEmail, string(cell.Value))
		duration := time.Since(start)
		if hooks.OnMaskAttempt != nil {
			// Mevcut kanca sozlesmesi KORUNUR: ORIJINAL Masker hatasi
			// (icerigi ne olursa olsun) burada, yalnizca cagiranin kendi
			// gozlem/metrik amacli kancasina gecirilir - hicbir yerde
			// BASKA SAKLANMAZ ve fonksiyonun DONDURDUGU hataya ASLA
			// karismaz (bkz. asagida ErrMaskerInvocationFailed).
			hooks.OnMaskAttempt(target.ColumnName, valueChanged, maskErr, duration)
		}
		if maskErr != nil {
			return nil, false, ErrMaskerInvocationFailed
		}
		if !valueChanged {
			continue
		}

		newRow, cellErr := row.WithCell(target.Index, protocol.DataCell{Value: []byte(maskedValue)})
		if cellErr != nil {
			return nil, false, ErrInvalidRowMaskPlan
		}
		row = newRow
		changed = true
	}

	if !changed {
		out := make([]byte, len(frame))
		copy(out, frame)
		return out, false, nil
	}
	return row.Build(), true, nil
}

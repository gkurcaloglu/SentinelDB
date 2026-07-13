package masking

import (
	"context"
	"fmt"
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
// maskeleme planidir. ColumnCount, DataRow'daki beklenen toplam hucre
// sayisidir (yalnizca Targets bos olmadiginda dogrulanir).
type RowMaskPlan struct {
	ColumnCount int
	Targets     []MaskTarget
}

// MaskDataRow, plan'a gore TEK bir tam DataRow cercevesini (tag 'D' +
// 4 baytlik uzunluk + govde, protocol.NewServerDecoder/Message.Raw ile
// aynı bicimde) maskeler.
//
// Bu fonksiyon:
//   - hicbir soket G/C'si yapmaz, hicbir goroutine baslatmaz;
//   - frame'i ya da herhangi bir hucre degerini cagri dondukten sonra
//     saklamaz;
//   - TAM OLARAK bir DataRow cercevesi bekler (bir akis DEGIL);
//   - plan.Targets bossa (bu sekilde hicbir maskeleme yukumlulugu yoksa)
//     govdeyi hic ayristirmadan, hucre sayisi dogrulamasi yapmadan
//     BAGIMSIZ bir kopyasini dondurur;
//   - plan.Targets bos degilse, hucre sayisinin plan.ColumnCount ile
//     uyustugunu dogrular;
//   - NULL hedef hucreler icin Masker'i HIC cagirmaz;
//   - ikili (FormatCode != 0) bir hedef sutuna, o sutunun degeri NULL
//     olmadigi surece, ulasilirsa reddeder (fail-closed);
//   - yalnizca yapilandirilmis hedef hucreler icin Masker'i cagirir, ctx'i
//     AYNEN gecirir;
//   - degisen hucreleri protocol.DataRow.WithCell/Build ile yeniden insa
//     eder;
//   - hicbir hata mesaji hucre degeri, sutun degeri iceren ham cerceve ya
//     da tam Raw cerceve icermez.
//
// changed, donen baytlarin frame'den farkli olup olmadigini bildirir;
// yalnizca gozlem/metrik amaclidir - cagiran bunu DEGER ifsa etmek icin
// KULLANMAMALIDIR.
func MaskDataRow(ctx context.Context, masker Masker, plan RowMaskPlan, frame []byte, hooks Hooks) ([]byte, bool, error) {
	if len(frame) < 5 {
		return nil, false, fmt.Errorf("dataRow govdesi cok kisa")
	}

	if len(plan.Targets) == 0 {
		out := make([]byte, len(frame))
		copy(out, frame)
		return out, false, nil
	}

	if plan.ColumnCount < 0 {
		return nil, false, fmt.Errorf("gecersiz plan: negatif sutun sayisi")
	}

	row, err := protocol.ParseDataRow(frame[5:])
	if err != nil {
		return nil, false, fmt.Errorf("dataRow ayristirilamadi: %w", err)
	}
	if len(row.Cells) != plan.ColumnCount {
		return nil, false, fmt.Errorf("dataRow alan sayisi beklenen sekil ile uyusmuyor: %d != %d", len(row.Cells), plan.ColumnCount)
	}

	changed := false
	for _, target := range plan.Targets {
		if target.Index < 0 || target.Index >= len(row.Cells) {
			return nil, false, fmt.Errorf("gecersiz hedef sutun indeksi")
		}
		cell := row.Cells[target.Index]
		if cell.Null {
			// NULL degerler icin Masker hic cagrilmaz.
			continue
		}
		if target.FormatCode != 0 {
			// Ikili veriyi metin gibi maskelemeye calismak veriyi sessizce
			// bozabilir; bunun yerine acikca reddediyoruz.
			return nil, false, fmt.Errorf("maskelenecek sutun ikili (binary) formatta, desteklenmiyor")
		}

		start := time.Now()
		maskedValue, valueChanged, _, maskErr := masker.Mask(ctx, target.ColumnName, maskKindEmail, string(cell.Value))
		duration := time.Since(start)
		if hooks.OnMaskAttempt != nil {
			hooks.OnMaskAttempt(target.ColumnName, valueChanged, maskErr, duration)
		}
		if maskErr != nil {
			return nil, false, fmt.Errorf("sutun maskelenemedi: %w", maskErr)
		}
		if !valueChanged {
			continue
		}

		newRow, cellErr := row.WithCell(target.Index, protocol.DataCell{Value: []byte(maskedValue)})
		if cellErr != nil {
			return nil, false, fmt.Errorf("hucre guncellenemedi: %w", cellErr)
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

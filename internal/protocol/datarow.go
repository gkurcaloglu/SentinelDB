package protocol

import (
	"encoding/binary"
	"fmt"
)

// maxCellValueSize, tek bir DataRow hücresi için kabul edilen üst
// sınırdır. Bunun üzerindeki bir uzunluk alanı bozuk veri ya da aşırı
// büyük (DoS amaçlı olabilecek) bir değer olarak reddedilir. Bu, dış
// çerçevenin (bkz. decoder.go, maxMessageLength) zaten uyguladığı 1 MiB
// sınırıyla aynı büyüklüktedir; ParseDataRow'un tek başına (Decoder
// olmadan) çağrıldığı durumlarda da kendi kendini savunmasını sağlar.
const maxCellValueSize = 1 << 20 // 1 MiB

// DataCell, bir DataRow içindeki tek bir sütun değeridir. Null true ise
// Value geçersizdir/boştur; bu, PostgreSQL'in NULL (-1 uzunluk) ile boş
// string ("" , 0 uzunluk) arasındaki ayrımını korur.
type DataCell struct {
	Null  bool
	Value []byte
}

// DataRow, ayrıştırılmış bir DataRow ('D') mesajının hücreleridir.
type DataRow struct {
	Cells []DataCell
}

// ParseDataRow, bir DataRow mesajının gövdesini (tag ve length alanları
// hariç, yani alan sayısından itibaren) ayrıştırır.
//
// Güvenilmeyen "wire" verisi üzerinde çalışır: her adımda tampon
// sınırlarını doğrular, hiçbir girişte panic etmez; kesilmiş, bozuk ya da
// aşırı büyük değerler için açıklayıcı bir hata döner.
func ParseDataRow(body []byte) (*DataRow, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("dataRow govdesi cok kisa: %d bayt (en az 2 gerekli)", len(body))
	}
	fieldCount := int(binary.BigEndian.Uint16(body[0:2]))
	offset := 2

	cells := make([]DataCell, 0, fieldCount)
	for i := 0; i < fieldCount; i++ {
		if offset+4 > len(body) {
			return nil, fmt.Errorf("alan %d: uzunluk alani okunamadi (govde kesilmis)", i)
		}
		length := int32(binary.BigEndian.Uint32(body[offset : offset+4]))
		offset += 4

		if length == -1 {
			cells = append(cells, DataCell{Null: true})
			continue
		}
		if length < 0 {
			return nil, fmt.Errorf("alan %d: gecersiz uzunluk: %d", i, length)
		}
		if length > maxCellValueSize {
			return nil, fmt.Errorf("alan %d: deger cok buyuk: %d bayt (ust sinir %d)", i, length, maxCellValueSize)
		}
		if offset+int(length) > len(body) {
			return nil, fmt.Errorf("alan %d: deger govdede kesilmis (beklenen %d bayt)", i, length)
		}

		value := make([]byte, length)
		copy(value, body[offset:offset+int(length)])
		cells = append(cells, DataCell{Value: value})
		offset += int(length)
	}

	if offset != len(body) {
		return nil, fmt.Errorf("dataRow govdesinde %d fazladan bayt var", len(body)-offset)
	}

	return &DataRow{Cells: cells}, nil
}

// WithCell, index'teki hücresi cell ile değiştirilmiş YENİ bir DataRow
// döndürür (orijinal değişmez). index geçerli aralığın dışındaysa hata
// döner. Hücre sayısı her zaman korunduğundan (yalnızca mevcut bir
// hücrenin içeriği değişir), bu API alan-sayısı uyuşmazlığı üretemez.
func (r *DataRow) WithCell(index int, cell DataCell) (*DataRow, error) {
	if index < 0 || index >= len(r.Cells) {
		return nil, fmt.Errorf("gecersiz hucre indeksi: %d (toplam %d hucre)", index, len(r.Cells))
	}
	newCells := make([]DataCell, len(r.Cells))
	copy(newCells, r.Cells)
	newCells[index] = cell
	return &DataRow{Cells: newCells}, nil
}

// Build, DataRow'u geçerli, tam bir 'D' mesajı (tag + length + gövde)
// olarak yeniden inşa eder. Her hücrenin uzunluğu ve toplam mesaj uzunluğu
// güncel hücre içeriğine göre yeniden hesaplanır.
func (r *DataRow) Build() []byte {
	payload := make([]byte, 2, 2+len(r.Cells)*8)
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(r.Cells)))

	for _, cell := range r.Cells {
		if cell.Null {
			payload = append(payload, 0xFF, 0xFF, 0xFF, 0xFF) // -1 (NULL)
			continue
		}
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(cell.Value)))
		payload = append(payload, lenBuf...)
		payload = append(payload, cell.Value...)
	}

	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)+4))

	out := make([]byte, 0, 1+4+len(payload))
	out = append(out, 'D')
	out = append(out, length...)
	out = append(out, payload...)
	return out
}

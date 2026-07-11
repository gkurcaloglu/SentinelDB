package protocol

import (
	"encoding/binary"
	"fmt"
)

// RowField, bir RowDescription mesajındaki tek bir sütunun tam meta
// verisidir. PostgreSQL wire protokolü alan sırasıyla korunur.
type RowField struct {
	// Name, sütun adıdır (RowDescription'daki null-sonlandırmalı string).
	Name string
	// TableOID, sütunun ait olduğu tablonun OID'sidir (bir tabloya ait
	// değilse 0).
	TableOID uint32
	// Attribute, sütunun tablo içindeki öznitelik numarasıdır (bir tabloya
	// ait değilse 0).
	Attribute int16
	// DataTypeOID, sütunun veri tipinin OID'sidir.
	DataTypeOID uint32
	// DataTypeSize, veri tipinin sabit boyutudur; değişken genişlikli
	// tipler için negatiftir (bkz. pg_type.typlen).
	DataTypeSize int16
	// TypeModifier, tipe özgü ek bilgidir (ör. varchar(N) için N).
	TypeModifier int32
	// FormatCode, bu sütun için kullanılan format kodudur: 0 = metin,
	// 1 = ikili (binary).
	FormatCode int16
}

// RowDescription, ayrıştırılmış bir RowDescription ('T') mesajının
// gövdesidir.
type RowDescription struct {
	Fields []RowField
}

// rowFieldFixedPartLen, bir alanın sütun adından sonraki sabit uzunluklu
// kısmının bayt cinsinden uzunluğudur: TableOID(4) + Attribute(2) +
// DataTypeOID(4) + DataTypeSize(2) + TypeModifier(4) + FormatCode(2).
const rowFieldFixedPartLen = 4 + 2 + 4 + 2 + 4 + 2

// ParseRowDescription, bir RowDescription mesajının gövdesini (tag ve
// length alanları hariç, yani alan sayısından itibaren) ayrıştırır.
//
// Güvenilmeyen "wire" verisi üzerinde çalışır: her adımda tampon
// sınırlarını doğrular, hiçbir girişte panic etmez; kesilmiş (truncated)
// ya da bozuk girişler için açıklayıcı bir hata döner.
func ParseRowDescription(body []byte) (*RowDescription, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("rowDescription govdesi cok kisa: %d bayt (en az 2 gerekli)", len(body))
	}
	fieldCount := int(binary.BigEndian.Uint16(body[0:2]))
	offset := 2

	fields := make([]RowField, 0, fieldCount)
	for i := 0; i < fieldCount; i++ {
		name, next, err := readCString(body, offset)
		if err != nil {
			return nil, fmt.Errorf("alan %d: sutun adi okunamadi: %w", i, err)
		}
		offset = next

		if offset+rowFieldFixedPartLen > len(body) {
			return nil, fmt.Errorf("alan %d: govde kesilmis (sabit uzunluklu kisim eksik)", i)
		}

		f := RowField{Name: name}
		f.TableOID = binary.BigEndian.Uint32(body[offset : offset+4])
		offset += 4
		f.Attribute = int16(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		f.DataTypeOID = binary.BigEndian.Uint32(body[offset : offset+4])
		offset += 4
		f.DataTypeSize = int16(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		f.TypeModifier = int32(binary.BigEndian.Uint32(body[offset : offset+4]))
		offset += 4
		f.FormatCode = int16(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2

		fields = append(fields, f)
	}

	if offset != len(body) {
		return nil, fmt.Errorf("rowDescription govdesinde %d fazladan bayt var", len(body)-offset)
	}

	return &RowDescription{Fields: fields}, nil
}

// readCString, body[offset:] içinden null sonlandırmalı bir string okur ve
// stringi ile null baytından sonraki offset'i döndürür. offset sınırların
// dışındaysa ya da null sonlandırıcı bulunamazsa hata döner; hiçbir zaman
// panic etmez.
func readCString(body []byte, offset int) (string, int, error) {
	if offset < 0 || offset > len(body) {
		return "", 0, fmt.Errorf("gecersiz offset: %d (govde uzunlugu %d)", offset, len(body))
	}
	idx := -1
	for i := offset; i < len(body); i++ {
		if body[i] == 0 {
			idx = i
			break
		}
	}
	if idx == -1 {
		return "", 0, fmt.Errorf("null sonlandirilmamis string (offset %d)", offset)
	}
	return string(body[offset:idx]), idx + 1, nil
}

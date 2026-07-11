package protocol

import (
	"encoding/binary"
	"testing"
)

// encodeRowDescriptionBody, bir RowDescription mesajının gövdesini (alan
// sayısından itibaren, tag+length haric) test amaçlı üretir.
func encodeRowDescriptionBody(fields []RowField) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, uint16(len(fields)))
	for _, f := range fields {
		body = append(body, []byte(f.Name)...)
		body = append(body, 0)

		buf4 := make([]byte, 4)
		buf2 := make([]byte, 2)

		binary.BigEndian.PutUint32(buf4, f.TableOID)
		body = append(body, buf4...)
		binary.BigEndian.PutUint16(buf2, uint16(f.Attribute))
		body = append(body, buf2...)
		binary.BigEndian.PutUint32(buf4, f.DataTypeOID)
		body = append(body, buf4...)
		binary.BigEndian.PutUint16(buf2, uint16(f.DataTypeSize))
		body = append(body, buf2...)
		binary.BigEndian.PutUint32(buf4, uint32(f.TypeModifier))
		body = append(body, buf4...)
		binary.BigEndian.PutUint16(buf2, uint16(f.FormatCode))
		body = append(body, buf2...)
	}
	return body
}

func TestParseRowDescription_Valid(t *testing.T) {
	want := []RowField{
		{Name: "id", TableOID: 16400, Attribute: 1, DataTypeOID: 23, DataTypeSize: 4, TypeModifier: -1, FormatCode: 0},
		{Name: "email", TableOID: 16400, Attribute: 2, DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, FormatCode: 0},
	}
	body := encodeRowDescriptionBody(want)

	got, err := ParseRowDescription(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Fields) != len(want) {
		t.Fatalf("expected %d fields, got %d", len(want), len(got.Fields))
	}
	for i, wf := range want {
		gf := got.Fields[i]
		if gf != wf {
			t.Errorf("field %d: got %+v, want %+v", i, gf, wf)
		}
	}
}

func TestParseRowDescription_ZeroFields(t *testing.T) {
	body := encodeRowDescriptionBody(nil)
	got, err := ParseRowDescription(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Fields) != 0 {
		t.Fatalf("expected 0 fields, got %d", len(got.Fields))
	}
}

func TestParseRowDescription_TooShort(t *testing.T) {
	_, err := ParseRowDescription([]byte{0x00})
	if err == nil {
		t.Fatal("expected an error for a body shorter than the field-count prefix")
	}
}

func TestParseRowDescription_TruncatedFieldName(t *testing.T) {
	// Alan sayisi 1 diyor ama sutun adi icin null sonlandirici yok.
	body := []byte{0x00, 0x01, 'e', 'm', 'a', 'i', 'l'}
	_, err := ParseRowDescription(body)
	if err == nil {
		t.Fatal("expected an error for an unterminated column name")
	}
}

func TestParseRowDescription_TruncatedFixedPart(t *testing.T) {
	// Sutun adi tamam ama sabit uzunluklu kisim (18 bayt) eksik.
	body := []byte{0x00, 0x01, 'e', 'm', 'a', 'i', 'l', 0x00, 0x00, 0x00, 0x00, 0x40}
	_, err := ParseRowDescription(body)
	if err == nil {
		t.Fatal("expected an error for a truncated fixed-length field section")
	}
}

func TestParseRowDescription_TrailingGarbage(t *testing.T) {
	valid := encodeRowDescriptionBody([]RowField{{Name: "id", DataTypeOID: 23, DataTypeSize: 4, TypeModifier: -1}})
	body := append(valid, 0xDE, 0xAD)
	_, err := ParseRowDescription(body)
	if err == nil {
		t.Fatal("expected an error for trailing bytes after the last field")
	}
}

func TestParseRowDescription_NeverPanics(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{0x00},
		{0xFF, 0xFF}, // buyuk bir alan sayisi iddia ediyor ama govde yok
		{0x00, 0x01},
		{0x00, 0x01, 0x00}, // isim bos + hemen govde sonu
		{0x7F, 0xFF, 0xFF},
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input %d: ParseRowDescription panicked: %v", i, r)
				}
			}()
			_, _ = ParseRowDescription(in)
		}()
	}
}

// FuzzParseRowDescription, ParseRowDescription'in guvenilmeyen govde
// baytlari uzerinde -asla panic etmeme- degismezini korur (bkz. gorev
// C/I). Tohum kumesi mevcut tablo tabanli testlerden alinmistir.
func FuzzParseRowDescription(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF, 0xFF})
	f.Add([]byte{0x00, 0x01})
	f.Add([]byte{0x00, 0x01, 0x00})
	f.Add([]byte{'e', 'm', 'a', 'i', 'l'})
	f.Add(encodeRowDescriptionBody([]RowField{
		{Name: "id", TableOID: 16400, Attribute: 1, DataTypeOID: 23, DataTypeSize: 4, TypeModifier: -1},
		{Name: "email", TableOID: 16400, Attribute: 2, DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1},
	}))

	f.Fuzz(func(t *testing.T, body []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseRowDescription panicked on input %v: %v", body, r)
			}
		}()
		_, _ = ParseRowDescription(body)
	})
}

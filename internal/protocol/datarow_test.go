package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func encodeDataRowBody(cells []DataCell) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, uint16(len(cells)))
	for _, c := range cells {
		lenBuf := make([]byte, 4)
		if c.Null {
			binary.BigEndian.PutUint32(lenBuf, 0xFFFFFFFF)
			body = append(body, lenBuf...)
			continue
		}
		binary.BigEndian.PutUint32(lenBuf, uint32(len(c.Value)))
		body = append(body, lenBuf...)
		body = append(body, c.Value...)
	}
	return body
}

func TestParseDataRow_NullEmptyAndNormalValues(t *testing.T) {
	cells := []DataCell{
		{Value: []byte("john@example.com")},
		{Null: true},
		{Value: []byte("")}, // bos string, NULL degil
		{Value: []byte("visible-value")},
	}
	body := encodeDataRowBody(cells)

	got, err := ParseDataRow(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Cells) != 4 {
		t.Fatalf("expected 4 cells, got %d", len(got.Cells))
	}
	if got.Cells[0].Null || string(got.Cells[0].Value) != "john@example.com" {
		t.Errorf("cell 0: got %+v", got.Cells[0])
	}
	if !got.Cells[1].Null {
		t.Errorf("cell 1: expected Null=true, got %+v", got.Cells[1])
	}
	if got.Cells[2].Null || got.Cells[2].Value == nil || len(got.Cells[2].Value) != 0 {
		t.Errorf("cell 2: expected non-null empty value, got %+v", got.Cells[2])
	}
	if got.Cells[3].Null || string(got.Cells[3].Value) != "visible-value" {
		t.Errorf("cell 3: got %+v", got.Cells[3])
	}
}

func TestDataRow_BuildRoundTrip(t *testing.T) {
	cells := []DataCell{
		{Value: []byte("john@example.com")},
		{Null: true},
		{Value: []byte("")},
		{Value: []byte("visible-value")},
	}
	body := encodeDataRowBody(cells)
	original := append([]byte{byte(MsgDataRow)}, mustLength(body)...)
	original = append(original, body...)

	row, err := ParseDataRow(body)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	rebuilt := row.Build()

	if !bytes.Equal(rebuilt, original) {
		t.Fatalf("round-trip mismatch:\ngot:  %v\nwant: %v", rebuilt, original)
	}
}

func mustLength(body []byte) []byte {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(body)+4))
	return length
}

func TestDataRow_WithCell_PreservesUnchangedCellsByteForByte(t *testing.T) {
	cells := []DataCell{
		{Value: []byte("john@example.com")},
		{Value: []byte("visible-value")},
		{Null: true},
	}
	body := encodeDataRowBody(cells)
	row, err := ParseDataRow(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	masked, err := row.WithCell(0, DataCell{Value: []byte("jo****@example.com")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(masked.Cells[0].Value) != "jo****@example.com" {
		t.Errorf("expected masked cell 0, got %+v", masked.Cells[0])
	}
	if string(masked.Cells[1].Value) != "visible-value" {
		t.Errorf("expected cell 1 unchanged, got %+v", masked.Cells[1])
	}
	if !masked.Cells[2].Null {
		t.Errorf("expected cell 2 to remain NULL, got %+v", masked.Cells[2])
	}
	// Orijinal DataRow degismemis olmali (WithCell bir kopya dondurur).
	if string(row.Cells[0].Value) != "john@example.com" {
		t.Errorf("expected original DataRow to remain unmodified, got %+v", row.Cells[0])
	}
}

func TestDataRow_WithCell_InvalidIndexRejected(t *testing.T) {
	row := &DataRow{Cells: []DataCell{{Value: []byte("a")}}}
	if _, err := row.WithCell(-1, DataCell{}); err == nil {
		t.Error("expected an error for a negative index")
	}
	if _, err := row.WithCell(1, DataCell{}); err == nil {
		t.Error("expected an error for an out-of-range index")
	}
}

func TestParseDataRow_Truncated(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"too short for field count", []byte{0x00}},
		{"length field cut off", []byte{0x00, 0x01, 0x00, 0x00}},
		{"value cut off", func() []byte {
			b := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x05} // 1 alan, uzunluk=5 ama deger yok
			return b
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDataRow(tc.body); err == nil {
				t.Fatal("expected an error for truncated input")
			}
		})
	}
}

func TestParseDataRow_TrailingGarbageRejected(t *testing.T) {
	body := encodeDataRowBody([]DataCell{{Value: []byte("x")}})
	body = append(body, 0xDE, 0xAD)
	if _, err := ParseDataRow(body); err == nil {
		t.Fatal("expected an error for trailing bytes after the last cell")
	}
}

func TestParseDataRow_OversizedValueRejected(t *testing.T) {
	body := []byte{0x00, 0x01, 0x00, 0x20, 0x00, 0x00} // 1 alan, uzunluk = 0x00200000 (2 MiB) > ust sinir
	if _, err := ParseDataRow(body); err == nil {
		t.Fatal("expected an error for an oversized cell length")
	}
}

func TestParseDataRow_NegativeLengthOtherThanNULLRejected(t *testing.T) {
	body := []byte{0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFE} // -2, gecersiz (-1 disinda negatif deger yok)
	if _, err := ParseDataRow(body); err == nil {
		t.Fatal("expected an error for a negative length other than -1 (NULL)")
	}
}

func TestParseDataRow_NeverPanics(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{0x00},
		{0xFF, 0xFF},
		{0x00, 0x01},
		{0x00, 0x01, 0xFF},
		{0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}, // NULL sonrasi fazladan bayt
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input %d: ParseDataRow panicked: %v", i, r)
				}
			}()
			_, _ = ParseDataRow(in)
		}()
	}
}

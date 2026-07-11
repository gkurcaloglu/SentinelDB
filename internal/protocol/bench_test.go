package protocol

import "testing"

// benchRowFields is a small, deterministic 3-column result shape (id, name,
// email) representative of the demo table used throughout the repository
// (see scripts/e2e-demo.ps1).
func benchRowFields() []RowField {
	return []RowField{
		{Name: "id", TableOID: 16400, Attribute: 1, DataTypeOID: 23, DataTypeSize: 4, TypeModifier: -1, FormatCode: 0},
		{Name: "name", TableOID: 16400, Attribute: 2, DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, FormatCode: 0},
		{Name: "email", TableOID: 16400, Attribute: 3, DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, FormatCode: 0},
	}
}

func benchDataCells() []DataCell {
	return []DataCell{
		{Value: []byte("42")},
		{Value: []byte("John Smith")},
		{Value: []byte("john.smith@example.com")},
	}
}

// BenchmarkParseRowDescription measures RowDescription ('T') body parsing
// for a fixed 3-column shape.
func BenchmarkParseRowDescription(b *testing.B) {
	body := encodeRowDescriptionBody(benchRowFields())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseRowDescription(body); err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

// BenchmarkParseDataRow measures DataRow ('D') body parsing for a fixed
// 3-cell row matching benchRowFields.
func BenchmarkParseDataRow(b *testing.B) {
	body := encodeDataRowBody(benchDataCells())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseDataRow(body); err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

// BenchmarkDataRowBuild measures re-serializing an already-parsed DataRow
// back into wire bytes (DataRow.Build) — the cost paid on the
// masking.Transformer hot path whenever at least one cell in a row changed
// and the row must be rebuilt before forwarding to the client.
func BenchmarkDataRowBuild(b *testing.B) {
	body := encodeDataRowBody(benchDataCells())
	row, err := ParseDataRow(body)
	if err != nil {
		b.Fatalf("unexpected error: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = row.Build()
	}
}

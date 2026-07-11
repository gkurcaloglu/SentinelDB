package masking

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// BenchmarkTransformerMaskEmailColumn measures the full response-side
// masking transformation path for a single configured email column: parsing
// RowDescription, parsing DataRow, invoking the Masker for the "email"
// column, and rebuilding the row. It uses the same fake, non-Wasm masker
// (emailLikeMasker, defined in transformer_test.go) used by the correctness
// tests, so this benchmark isolates internal/masking's own orchestration
// cost from Wasm call overhead — see internal/wasm's benchmarks for the
// Wasm mask_value invocation cost itself.
func BenchmarkTransformerMaskEmailColumn(b *testing.B) {
	cfg := NewConfig(true, []string{"email"})
	masker := emailLikeMasker()

	var stream bytes.Buffer
	stream.Write(encodeRowDescription(idAndEmailFields(0)))
	stream.Write(encodeDataRow([]protocol.DataCell{
		{Value: []byte("1")},
		{Value: []byte("john.smith@example.com")},
	}))
	data := stream.Bytes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr := NewTransformer(context.Background(), cfg, masker, io.Discard, nil, Hooks{})
		if err := tr.Run(bytes.NewReader(data)); err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

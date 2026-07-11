package wasm

import (
	"bytes"
	"testing"
)

func TestBoundedBuffer_WithinLimit(t *testing.T) {
	b := newBoundedBuffer(10)
	n, err := b.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("unexpected Write result: n=%d err=%v", n, err)
	}
	if b.exceeded {
		t.Fatal("expected exceeded=false within the limit")
	}
	if !bytes.Equal(b.Bytes(), []byte("hello")) {
		t.Fatalf("unexpected buffered content: %q", b.Bytes())
	}
}

func TestBoundedBuffer_StopsGrowingPastLimit(t *testing.T) {
	b := newBoundedBuffer(5)

	// Sinirdan cok daha fazla bayt yaz; Write yine de hata dondurmemeli
	// (eklenti calismasi kesintiye ugramasin), ama arabellek sinirin
	// UZERINE hic cikmamali.
	big := bytes.Repeat([]byte("x"), 1<<20) // 1 MiB
	n, err := b.Write(big)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(big) {
		t.Fatalf("expected Write to report success for all %d bytes, got n=%d", len(big), n)
	}
	if !b.exceeded {
		t.Fatal("expected exceeded=true after writing past the limit")
	}
	if b.buf.Len() != 5 {
		t.Fatalf("expected the underlying buffer to be capped at 5 bytes, got %d", b.buf.Len())
	}
	if b.written != len(big) {
		t.Fatalf("expected written to track the true total (%d), got %d", len(big), b.written)
	}
}

func TestBoundedBuffer_MultipleWritesAccumulateThenCap(t *testing.T) {
	b := newBoundedBuffer(8)
	b.Write([]byte("1234"))
	b.Write([]byte("5678"))
	if b.exceeded {
		t.Fatal("expected exceeded=false at exactly the limit")
	}
	b.Write([]byte("9"))
	if !b.exceeded {
		t.Fatal("expected exceeded=true after exceeding the limit across multiple writes")
	}
	if string(b.Bytes()) != "12345678" {
		t.Fatalf("expected buffered content capped at the limit, got %q", b.Bytes())
	}
}

package protocol

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

// TestSerializedWriter_NoInterleaving, birçok goroutine'in aynı anda
// yazdığı durumda hiçbir Write çağrısının baytlarının bölünüp başka bir
// goroutine'in baytlarıyla karışmadığını (interleave olmadığını) dogrular.
// Her goroutine kendine özgü bir bayt değeriyle dolu sabit boyutlu
// parçalar yazar; çıktıdaki her aynı-bayt "koşusu" (run) tam olarak parça
// boyutunun bir katı olmalıdır - değilse iki goroutine'in yazması
// kaynaşmış demektir.
func TestSerializedWriter_NoInterleaving(t *testing.T) {
	var buf bytes.Buffer
	sw := NewSerializedWriter(&buf)

	const goroutines = 20
	const writesPerGoroutine = 50
	const chunkSize = 97 // asal sayi, hizalama tesadufleriyle karismasin diye

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(marker byte) {
			defer wg.Done()
			chunk := bytes.Repeat([]byte{marker}, chunkSize)
			for i := 0; i < writesPerGoroutine; i++ {
				if _, err := sw.Write(chunk); err != nil {
					t.Errorf("unexpected write error: %v", err)
					return
				}
			}
		}(byte('A' + g))
	}
	wg.Wait()

	data := buf.Bytes()
	wantLen := goroutines * writesPerGoroutine * chunkSize
	if len(data) != wantLen {
		t.Fatalf("expected %d total bytes, got %d (bytes were dropped or duplicated)", wantLen, len(data))
	}

	i := 0
	for i < len(data) {
		marker := data[i]
		runStart := i
		for i < len(data) && data[i] == marker {
			i++
		}
		runLen := i - runStart
		if runLen%chunkSize != 0 {
			t.Fatalf("interleaved write detected at byte %d: run of %q has length %d, not a multiple of chunk size %d", runStart, marker, runLen, chunkSize)
		}
	}
}

func TestSerializedWriter_ForwardsWriteErrors(t *testing.T) {
	sw := NewSerializedWriter(errorWriter{})
	_, err := sw.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected the underlying writer's error to be forwarded")
	}
}

var errTestWrite = errors.New("simulated write failure")

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errTestWrite
}

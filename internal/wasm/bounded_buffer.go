package wasm

import "bytes"

// boundedBuffer, bir io.Writer'dır; alttaki arabellek modül YAZARKEN en
// fazla limit bayta kadar dolar (sınırsız büyüyen bir bytes.Buffer'ın
// sonradan kesilmesi DEĞİL). limit aşılırsa fazla baytlar sessizce
// atılır; Write yine de her zaman başarılı döner (len(p), nil) ki
// eklentinin normal çalışması bir yazma hatasıyla kesintiye uğramasın.
// exceeded alanı aşımı ayrıca bildirir ki çağıran taraf bunu fail-closed
// olarak ele alabilsin (bkz. Runtime.call).
type boundedBuffer struct {
	buf      bytes.Buffer
	limit    int
	written  int
	exceeded bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{limit: limit}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.written += len(p)
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		b.buf.Write(p[:remaining])
	}
	if b.written > b.limit {
		b.exceeded = true
	}
	return len(p), nil
}

// Bytes, şimdiye kadar (limit dahilinde) biriktirilen baytları döndürür.
func (b *boundedBuffer) Bytes() []byte {
	return b.buf.Bytes()
}

package protocol

import (
	"io"
	"sync"
)

// SerializedWriter, birden fazla goroutine'in aynı alttaki io.Writer'a
// (tipik olarak bir client net.Conn) güvenle yazmasını sağlayan, mutex
// korumalı bir sarmalayıcıdır.
//
// PostgreSQL wire protokolü mesajları bölünemez: iki farklı goroutine aynı
// anda (ör. gerçek bir backend yanıtını ileten kopyalama döngüsü ile
// sentetik bir firewall ErrorResponse'u yazan taraf) client'a yazarsa,
// baytlar iç içe geçip (interleave) protokolü bozabilir. Bu tip, tek bir
// bağlantı için oluşturulur (global bir kilit DEĞİLDİR); o bağlantıya
// yazan tüm yollar aynı SerializedWriter örneğini paylaşmalıdır.
type SerializedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewSerializedWriter, w'ye yazan mutex korumalı bir SerializedWriter
// döndürür.
func NewSerializedWriter(w io.Writer) *SerializedWriter {
	return &SerializedWriter{w: w}
}

// Write, io.Writer arayüzünü karşılar. Tek bir Write çağrısının tüm
// baytları, başka bir goroutine'in araya girmesi mümkün olmadan, atomik
// olarak alttaki writer'a yazılır.
func (s *SerializedWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

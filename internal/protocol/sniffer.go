package protocol

import "io"

// SniffReader, altındaki io.Reader'dan okunan baytları hiç değiştirmeden
// döndüren, ama aynı zamanda bir Decoder'a besleyen şeffaf bir sarmalayıcıdır.
// Bu sayede gateway'in io.Copy tabanlı yönlendirme davranışı birebir aynı
// kalır; protokol ayrıştırma yalnızca bir yan etki (gözlem) olarak eklenir.
type SniffReader struct {
	r   io.Reader
	dec *Decoder
}

// NewSniffReader, r'den okunan veriyi dec'e besleyen bir SniffReader oluşturur.
func NewSniffReader(r io.Reader, dec *Decoder) *SniffReader {
	return &SniffReader{r: r, dec: dec}
}

func (s *SniffReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.dec.Write(p[:n])
	}
	return n, err
}

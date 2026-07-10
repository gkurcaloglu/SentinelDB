package masking

import "errors"

// ErrMaskingFailed, Transformer bir backend mesajını ayrıştıramadığında,
// desteklenmeyen bir durumla (ikili format, COPY protokolü, alan sayısı
// uyuşmazlığı) karşılaştığında ya da Wasm mask_value çağrısı başarısız/
// geçersiz bir yanıt döndürdüğünde Run tarafından döndürülür.
//
// Bu durumların hepsinde Transformer, işlemeye devam edip potansiyel
// olarak maskelenmemiş bir PII değerini sessizce istemciye geçirmek
// yerine bağlantıyı güvenli şekilde kapatır (fail-closed): maskeleme
// başarısızlığında "güvenli" varsayılan, orijinal değeri olduğu gibi
// göndermek değil, hiçbir şey göndermemektir.
var ErrMaskingFailed = errors.New("masking: yanit islenirken hata olustu, baglanti kapatildi")

// IsFailClosed, err'nin Transformer'ın bilerek (istemciye bir
// ErrorResponse yazıp) bağlantıyı kapattığı bir durumu mu temsil ettiğini
// bildirir.
func IsFailClosed(err error) bool {
	return errors.Is(err, ErrMaskingFailed)
}

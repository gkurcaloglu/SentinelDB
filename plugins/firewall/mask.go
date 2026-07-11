package main

import "strings"

// maskEmail, bir e-posta değerini şu sabit kurallarla maskeler:
//
//   - alan adı (domain, '@' dahil) olduğu gibi korunur
//   - yerel kısımdan (local part) en fazla ilk İKİ UNICODE KOD NOKTASI
//     (rune) korunur - bayt değil, çünkü çok baytlı UTF-8 karakterlerde
//     (ör. "你好") bayt bazlı dilimleme geçersiz UTF-8 üretebilirdi
//   - tek rune'luk yerel kısımlarda o tek rune korunur
//   - gizlenen kısım, gerçek uzunluğunu sızdırmayan sabit "****" ile
//     temsil edilir (ör. "john" -> "jo****", "johnsmith" -> "jo****")
//
// value e-posta şeklinde değilse (bkz. looksLikeEmail) DEĞİŞTİRİLMEDEN
// döndürülür. Hesaplanan maskelenmiş değer girdiyle AYNIYSA (ör. değer
// zaten "jo****@example.com" gibi maskelenmiş görünüyorsa) da
// changed=false döner - host tarafı, changed=true iken değerin girdiden
// FARKLI olmasını zorunlu kılar (bkz. internal/wasm.validateMaskResponse).
func maskEmail(value string) (masked string, changed bool) {
	if !looksLikeEmail(value) {
		return value, false
	}

	// '@' ASCII (tek bayt) olduğundan IndexByte'ın bulduğu konum her
	// zaman geçerli bir UTF-8 sınırıdır; value[:at] ve value[at:] tam,
	// bozulmamış UTF-8 alt dizeleridir.
	at := strings.IndexByte(value, '@')
	local := value[:at]
	domainWithAt := value[at:]

	localRunes := []rune(local)
	keep := 2
	if len(localRunes) < keep {
		keep = len(localRunes)
	}

	result := string(localRunes[:keep]) + "****" + domainWithAt
	if result == value {
		return value, false
	}
	return result, true
}

// looksLikeEmail, value üzerinde yalnızca saf string işlemleriyle (regex
// yok) basit bir şekil kontrolü yapar: tam olarak bir '@', boş olmayan
// yerel/alan adı kısımları, alan adında en az bir nokta (baş/sonda değil)
// ve hiçbir kısımda boşluk karakteri yok.
func looksLikeEmail(s string) bool {
	if strings.Count(s, "@") != 1 {
		return false
	}
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}

	local, domain := s[:at], s[at+1:]
	if containsWhitespace(local) || containsWhitespace(domain) {
		return false
	}

	dot := strings.LastIndexByte(domain, '.')
	if dot <= 0 || dot == len(domain)-1 {
		return false
	}
	return true
}

func containsWhitespace(s string) bool {
	return strings.ContainsAny(s, " \t\r\n")
}

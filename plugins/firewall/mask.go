package main

import "strings"

// maskEmail, bir e-posta değerini şu sabit kurallarla maskeler:
//
//   - alan adı (domain, '@' dahil) olduğu gibi korunur
//   - yerel kısımdan (local part) en fazla ilk iki karakter korunur
//   - tek karakterlik yerel kısımlarda o tek karakter korunur
//   - gizlenen kısım, gerçek uzunluğunu sızdırmayan sabit "****" ile
//     temsil edilir (ör. "john" -> "jo****", "johnsmith" -> "jo****")
//
// value e-posta şeklinde değilse (bkz. looksLikeEmail), değiştirilmeden
// (changed=false) döndürülür.
func maskEmail(value string) (masked string, changed bool) {
	if !looksLikeEmail(value) {
		return value, false
	}

	at := strings.IndexByte(value, '@')
	local := value[:at]

	keep := 2
	if len(local) < keep {
		keep = len(local)
	}
	return local[:keep] + "****" + value[at:], true
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

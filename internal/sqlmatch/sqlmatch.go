// Package sqlmatch, SQL metni içinde yasaklı ifadeleri arayan saf (I/O
// içermeyen) eşleştirme mantığını barındırır. Hem native firewall
// politikası (internal/firewall.DenyKeywords) hem de firewall Wasm
// eklentisi (plugins/firewall) tarafından kullanılır; böylece "yasaklı
// kelime" mantığı tek bir yerde tanımlanır ve iki taraf birbirinden
// sapmaz.
//
// Bu, gerçek bir SQL ayrıştırıcı değil, saf metin eşleştirmesidir: yorum
// satırları ya da string literalleri içindeki eşleşmeleri de yakalar
// (yanlış pozitif verebilir) ve göreli olarak kolay atlatılabilir. Üretimde
// kullanmak için gerçek bir SQL ayrıştırıcıya dayanan bir eşleştirici
// yazılmalı.
package sqlmatch

import "strings"

// Normalize, büyük/küçük harf ve boşluk farklarını (fazla boşluk, tab,
// yeni satır) ortadan kaldırarak karşılaştırmaya hazır hale getirir.
func Normalize(s string) string {
	return strings.Join(strings.Fields(strings.ToUpper(s)), " ")
}

// MatchAny, query içinde phrases listesindeki ifadelerden ilk eşleşeni
// (orijinal yazımıyla) döndürür. Hiçbiri eşleşmezse "" döner.
func MatchAny(query string, phrases []string) string {
	q := Normalize(query)
	for _, phrase := range phrases {
		if phrase == "" {
			continue
		}
		if strings.Contains(q, Normalize(phrase)) {
			return phrase
		}
	}
	return ""
}

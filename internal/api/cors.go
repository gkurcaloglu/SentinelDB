package api

import "net/http"

// WithCORS, next'i cross-origin GET isteklerine (ör. Vite dev server'da
// çalışan React dashboard) izin veren bir middleware ile sarmalar. /api
// altındaki endpoint'ler salt okunur ve gizli veri içermediğinden (sayaçlar,
// config.yaml'da zaten görünür olan kural listesi) köken kısıtlaması
// uygulanmıyor.
func WithCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

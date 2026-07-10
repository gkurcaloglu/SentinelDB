// Command firewall, SentinelDB gateway'inin çalışma zamanında yüklediği
// bir Wasm politika eklentisidir. WASI "command" modeliyle çalışır: stdin'den
// tek bir JSON isteği (wasmproto.Request) okur, kararı stdin'de gelen
// blocked_phrases listesine göre verir ve JSON yanıtı (wasmproto.Response)
// stdout'a yazıp çıkar.
//
// Derleme:
//
//	GOOS=wasip1 GOARCH=wasm go build -o plugins/firewall/v2.wasm ./plugins/firewall
package main

import (
	"encoding/json"
	"io"
	"os"

	"github.com/gkurcaloglu/sentineldb/internal/sqlmatch"
	"github.com/gkurcaloglu/sentineldb/internal/wasmproto"
)

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		// Beklenmeyen bir hata (ör. bozuk JSON): host bunu Evaluate hatası
		// olarak görüp "fail closed" (Block) davranacak.
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
}

func run(in io.Reader, out io.Writer) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	var req wasmproto.Request
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	resp := evaluate(req)

	return json.NewEncoder(out).Encode(resp)
}

// evaluate, host'tan gelen sorguyu ve yasaklı ifade listesini
// internal/sqlmatch ile değerlendirir. Aynı eşleştirme mantığı
// internal/firewall.DenyKeywords tarafından da (native fallback için)
// kullanılır.
func evaluate(req wasmproto.Request) wasmproto.Response {
	if matched := sqlmatch.MatchAny(req.Query, req.BlockedPhrases); matched != "" {
		return wasmproto.Response{
			Verdict: wasmproto.VerdictBlock,
			Reason:  "SentinelDB policy (wasm): query engellendi (yasaklı ifade: \"" + matched + "\")",
		}
	}
	return wasmproto.Response{Verdict: wasmproto.VerdictAllow}
}

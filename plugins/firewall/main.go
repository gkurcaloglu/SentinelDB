// Command firewall, SentinelDB gateway'inin çalışma zamanında yüklediği
// tek Wasm eklentisidir. WASI "command" modeliyle çalışır: stdin'den tek
// bir JSON isteği (wasmproto.Envelope) okur, Op alanına göre işler
// (evaluate_query: firewall kararı, mask_value: PII maskeleme) ve JSON
// yanıtını (wasmproto.Result) stdout'a yazıp çıkar.
//
// Derleme:
//
//	GOOS=wasip1 GOARCH=wasm go build -o plugins/firewall/v2.wasm ./plugins/firewall
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/gkurcaloglu/sentineldb/internal/sqlmatch"
	"github.com/gkurcaloglu/sentineldb/internal/wasmproto"
)

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		// Beklenmeyen bir hata (ör. bozuk JSON): host bunu calistirma
		// hatasi olarak gorup "fail closed" davranacak.
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
}

func run(in io.Reader, out io.Writer) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	var req wasmproto.Envelope
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	resp := dispatch(req)

	return json.NewEncoder(out).Encode(resp)
}

// dispatch, istegi Op alanina gore ilgili isleyiciye yonlendirir. Protokol
// versiyonu ve operasyon adi burada dogrulanir; bilinmeyen/uyumsuz olan
// her sey Result.Error dolu bir yanit olarak doner (host bunu fail-closed
// olarak yorumlar), sureç asla panic etmez ya da sessizce yanlis bir
// varsayilan uretmez.
func dispatch(req wasmproto.Envelope) wasmproto.Result {
	if req.Version != wasmproto.ProtocolVersion {
		return errorResult(req.Op, fmt.Sprintf("desteklenmeyen protokol versiyonu: %d (beklenen %d)", req.Version, wasmproto.ProtocolVersion))
	}

	switch req.Op {
	case wasmproto.OpEvaluateQuery:
		return evaluateQuery(req)
	case wasmproto.OpMaskValue:
		return maskValueOp(req)
	default:
		return errorResult(req.Op, fmt.Sprintf("bilinmeyen operasyon: %q", req.Op))
	}
}

func errorResult(op, msg string) wasmproto.Result {
	return wasmproto.Result{Version: wasmproto.ProtocolVersion, Op: op, Error: msg}
}

// evaluateQuery, host'tan gelen sorguyu ve yasaklı ifade listesini
// internal/sqlmatch ile değerlendirir. Aynı eşleştirme mantığı
// internal/firewall.DenyKeywords tarafından da (native fallback için)
// kullanılır.
func evaluateQuery(req wasmproto.Envelope) wasmproto.Result {
	resp := wasmproto.Result{Version: wasmproto.ProtocolVersion, Op: wasmproto.OpEvaluateQuery}

	if matched := sqlmatch.MatchAny(req.Query, req.BlockedPhrases); matched != "" {
		resp.Verdict = wasmproto.VerdictBlock
		resp.Reason = "SentinelDB policy (wasm): query engellendi (yasaklı ifade: \"" + matched + "\")"
		return resp
	}
	resp.Verdict = wasmproto.VerdictAllow
	return resp
}

// maskValueOp, tek bir hücre değerini istenen türe (kind) göre maskeler.
// Gerekli alanları (column, kind) ve girdi/çıktının geçerli UTF-8
// olduğunu doğrular; bilinmeyen bir kind fail-closed bir Error ile
// sonuçlanır.
func maskValueOp(req wasmproto.Envelope) wasmproto.Result {
	if req.Column == "" {
		return errorResult(req.Op, "column alani bos olamaz")
	}
	if !utf8.ValidString(req.Value) {
		return errorResult(req.Op, "value gecerli UTF-8 degil")
	}

	resp := wasmproto.Result{Version: wasmproto.ProtocolVersion, Op: wasmproto.OpMaskValue}

	switch req.Kind {
	case wasmproto.KindEmail:
		masked, changed := maskEmail(req.Value)
		resp.Value = masked
		resp.Changed = changed
		return resp
	default:
		return errorResult(req.Op, fmt.Sprintf("bilinmeyen maskeleme turu: %q", req.Kind))
	}
}

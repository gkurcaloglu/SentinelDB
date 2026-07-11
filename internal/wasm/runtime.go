// Package wasm, SentinelDB gateway'inin firewall karar mantığını VE PII
// maskeleme mantığını yerleşik (native) Go kodu yerine, çalışma zamanında
// yüklenen TEK bir Wasm eklentisi (bkz. plugins/firewall) içinde
// çalıştırmasını sağlayan host tarafı altyapıyı barındırır. Wasm runtime
// olarak, cgo/C toolchain gerektirmeyen saf Go implementasyonu
// github.com/tetratelabs/wazero kullanılır.
//
// Firewall (evaluate_query) ve maskeleme (mask_value) operasyonları AYNI
// yüklü CompiledModule üzerinden, sürümlü tek bir istek/yanıt zarfı
// (bkz. internal/wasmproto) ile çalışır; ikinci bir runtime ya da ikinci
// bir ayrı yüklenen eklenti yoktur.
package wasm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
	"unicode/utf8"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"github.com/gkurcaloglu/sentineldb/internal/wasmproto"
)

// defaultTimeout, tek bir eklenti çağrısına tanınan azami süredir. Eklenti
// bu süreyi aşarsa çağrı context iptaliyle zorla sonlandırılır (bkz.
// wazero.RuntimeConfig.WithCloseOnContextDone); böylece bozuk ya da kötü
// niyetli bir eklenti gateway'i sonsuza dek bloklayamaz.
const defaultTimeout = 2 * time.Second

// maxMaskedValueSize, mask_value yanıtında kabul edilen azami değer
// boyutudur. Bunun üzerindeki bir çıktı, bozuk ya da kötü niyetli bir
// eklentinin işareti sayılır ve reddedilir (fail-closed).
const maxMaskedValueSize = 64 * 1024 // 64 KiB - e-posta gibi degerler icin cok comert bir sinir

// maxStdoutBytes ve maxStderrBytes, eklentinin tek bir çağrıda
// stdout/stderr'e yazabileceği azami bayt sayısıdır. Bu protokolün tek bir
// küçük JSON nesnesi taşıdığı göz önüne alındığında cömert ama küçük
// sınırlardır; eklenti bunları aşarsa (bozuk döngü, kötü niyetli büyük
// çıktı) çağrı fail-closed olarak reddedilir (bkz. Runtime.call). Sınır,
// modül YAZARKEN uygulanır (bkz. boundedBuffer) - sınırsız bir arabellek
// toplayıp SONRADAN kesilmez.
const (
	maxStdoutBytes = 8 * 1024 // 8 KiB
	maxStderrBytes = 4 * 1024 // 4 KiB
)

// Runtime, derlenmiş, tek bir firewall/masking Wasm eklentisini yöneten
// host tarafı çalışma zamanıdır. Eklenti WASI "command" modeliyle (main()
// bir kez çalışıp çıkar) derlendiğinden, aynı CompiledModule her çağrıda
// taze bir instance olarak çalıştırılır; bir instance'ı ikinci kez
// çağırmak WASI command modülleri için tanımsızdır.
type Runtime struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	timeout  time.Duration
}

// NewRuntime, wasmPath'teki .wasm dosyasını okuyup derleyerek yeni bir
// Runtime oluşturur.
func NewRuntime(ctx context.Context, wasmPath string) (*Runtime, error) {
	data, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, fmt.Errorf("wasm eklentisi okunamadi (%s): %w", wasmPath, err)
	}

	rConfig := wazero.NewRuntimeConfig().WithCloseOnContextDone(true)
	r := wazero.NewRuntimeWithConfig(ctx, rConfig)

	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("WASI baglami kurulamadi: %w", err)
	}

	compiled, err := r.CompileModule(ctx, data)
	if err != nil {
		_ = r.Close(ctx)
		return nil, fmt.Errorf("wasm eklentisi derlenemedi (%s): %w", wasmPath, err)
	}

	return &Runtime{runtime: r, compiled: compiled, timeout: defaultTimeout}, nil
}

// Close, Runtime'in ayırdığı tüm kaynakları (derlenmiş modül dahil) serbest
// bırakır.
func (rt *Runtime) Close(ctx context.Context) error {
	return rt.runtime.Close(ctx)
}

// Evaluate, query'yi ve blockedPhrases listesini bir evaluate_query
// isteği olarak eklentiye gönderir ve dönen kararı ayrıştırır. Yalnızca
// tam olarak "ALLOW" ya da "BLOCK" geçerli bir karardır; başka herhangi
// bir şey (eksik, boş, hatalı yazılmış) bir eklenti protokolü hatası
// sayılır.
func (rt *Runtime) Evaluate(ctx context.Context, query string, blockedPhrases []string) (verdict, reason string, err error) {
	resp, err := rt.call(ctx, wasmproto.Envelope{
		Version:        wasmproto.ProtocolVersion,
		Op:             wasmproto.OpEvaluateQuery,
		Query:          query,
		BlockedPhrases: blockedPhrases,
	})
	if err != nil {
		return "", "", err
	}
	return validateEvaluateResponse(resp)
}

// validateEvaluateResponse, eklentiden gelen ham yanıtın evaluate_query
// sözleşmesine uyduğunu doğrular: yalnızca tam olarak "ALLOW" ya da
// "BLOCK" geçerli bir karardır. Saf bir fonksiyondur (Wasm çalıştırmadan
// doğrudan test edilebilir).
func validateEvaluateResponse(resp wireResult) (verdict, reason string, err error) {
	if resp.Verdict != wasmproto.VerdictAllow && resp.Verdict != wasmproto.VerdictBlock {
		return "", "", errors.New("eklenti gecersiz verdict dondurdu")
	}
	return resp.Verdict, resp.Reason, nil
}

// MaskResult, bir mask_value çağrısının doğrulanmış sonucudur.
type MaskResult struct {
	Value   string
	Changed bool
	Reason  string
}

// Mask, tek bir hücre değerini eklentiye mask_value isteği olarak
// gönderir ve dönen yanıtı sıkı şekilde doğrular (bkz. validateMaskResponse):
// value/changed alanlarının ikisi de açıkça mevcut olmalı, değer geçerli
// UTF-8 ve boyut sınırı içinde olmalı, ve changed alanı değerle tutarlı
// olmalıdır. Herhangi biri sağlanmazsa (ya da eklenti çağrısının kendisi
// başarısız olursa) bir hata döner - çağıran (internal/masking) bunu
// fail-closed olarak ele almalıdır.
func (rt *Runtime) Mask(ctx context.Context, column, kind, value string) (MaskResult, error) {
	resp, err := rt.call(ctx, wasmproto.Envelope{
		Version: wasmproto.ProtocolVersion,
		Op:      wasmproto.OpMaskValue,
		Column:  column,
		Kind:    kind,
		Value:   value,
	})
	if err != nil {
		return MaskResult{}, err
	}
	return validateMaskResponse(value, resp)
}

// validateMaskResponse, eklentiden gelen ham (varlık-farkında) yanıtın
// mask_value sözleşmesine uyduğunu doğrular. Saf bir fonksiyondur (Wasm
// çalıştırmadan doğrudan test edilebilir).
func validateMaskResponse(original string, resp wireResult) (MaskResult, error) {
	if resp.Value == nil {
		return MaskResult{}, errors.New("eklenti yanitinda 'value' alani eksik")
	}
	if resp.Changed == nil {
		return MaskResult{}, errors.New("eklenti yanitinda 'changed' alani eksik")
	}
	if !utf8.ValidString(*resp.Value) {
		return MaskResult{}, errors.New("eklenti gecersiz UTF-8 dondurdu")
	}
	if len(*resp.Value) > maxMaskedValueSize {
		return MaskResult{}, fmt.Errorf("eklenti cok buyuk bir deger dondurdu: %d bayt (ust sinir %d)", len(*resp.Value), maxMaskedValueSize)
	}
	if *resp.Changed && *resp.Value == original {
		return MaskResult{}, errors.New("eklenti tutarsiz yanit: changed=true ama deger degismedi")
	}
	if !*resp.Changed && *resp.Value != original {
		return MaskResult{}, errors.New("eklenti tutarsiz yanit: changed=false ama deger degisti")
	}
	return MaskResult{Value: *resp.Value, Changed: *resp.Changed, Reason: resp.Reason}, nil
}

// wireResult, eklentiden gelen ham JSON yanıtının "varlık-farkında"
// (presence-aware) temsilidir. Value/Changed alanları için işaretçi
// kullanılır ki alanın JSON'da HİÇ olmaması ("eksik") ile açıktan sıfır
// değer (ör. changed=false, value="") olması ayırt edilebilsin (bkz.
// internal/wasmproto.Result'ın karşılığı - o alan isaretci degildir,
// cunku hem host hem eklenti tarafinda "mantiksal" tip olarak kullanilir;
// bu tip yalnizca host'un SIKI kod-cozme/dogrulama adiminda kullanilir).
type wireResult struct {
	Version int     `json:"version"`
	Op      string  `json:"op"`
	Error   string  `json:"error,omitempty"`
	Verdict string  `json:"verdict,omitempty"`
	Reason  string  `json:"reason,omitempty"`
	Value   *string `json:"value,omitempty"`
	Changed *bool   `json:"changed,omitempty"`
}

// decodeStrictResult, eklentinin stdout çıktısını (data) sıkı kurallarla
// bir wireResult'a ayrıştırır:
//   - Result şemasında olmayan hiçbir JSON alanına izin verilmez.
//   - İlk JSON değerinden sonra, json.Encoder'ın eklediği tek '\n' hariç,
//     boşluk olmayan hiçbir fazladan (trailing) veriye izin verilmez.
//
// Güvenilmeyen eklenti çıktısı üzerinde çalışır; hiçbir girişte panic
// etmez.
func decodeStrictResult(data []byte) (wireResult, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var resp wireResult
	if err := dec.Decode(&resp); err != nil {
		return wireResult{}, errors.New("JSON semasi gecersiz ya da beklenmeyen alan iceriyor")
	}

	// json.Encoder.Encode, tek bir JSON degerinden sonra daima bir '\n'
	// ekler; bu normaldir ve kabul edilir. Bunun disinda, bosluk olmayan
	// HERHANGI bir fazladan veri (ör. ikinci bir JSON degeri ya da
	// gecersiz artik baytlar) reddedilir.
	rest := bytes.TrimSpace(data[dec.InputOffset():])
	if len(rest) != 0 {
		return wireResult{}, errors.New("ciktida fazladan (trailing) veri var")
	}

	return resp, nil
}

// call, verilen isteği JSON olarak eklentiye (stdin) yazar, eklentiyi taze
// bir instance olarak çalıştırır ve stdout'tan dönen zarfı sıkı şekilde
// ayrıştırıp doğrular. Bu, Evaluate ve Mask tarafından paylaşılan tek
// düşük seviyeli çağrı mekanizmasıdır (tek yüklü CompiledModule, tek
// runtime).
//
// Güvenlik: dönen hiçbir hata, eklentinin ham stdout/stderr içeriğini,
// istek sorgu metnini ya da hücre değerlerini İÇERMEZ - yalnızca
// operasyon adı, bayt sayıları ve zaman aşımı/iptal durumu gibi güvenli
// metadata (bkz. görev B). Bozuk ya da kötü niyetli bir eklenti,
// stdout/stderr'e ne yazarsa yazsın bu asla loglara/hata mesajlarına
// sızmaz.
func (rt *Runtime) call(ctx context.Context, req wasmproto.Envelope) (wireResult, error) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return wireResult{}, fmt.Errorf("istek serilestirilemedi (op=%q)", req.Op)
	}

	callCtx, cancel := context.WithTimeout(ctx, rt.timeout)
	defer cancel()

	// stdout/stderr, MODUL YAZARKEN sinirlanir (bkz. boundedBuffer) -
	// sinirsiz bir bytes.Buffer toplayip sonradan kesmiyoruz.
	stdout := newBoundedBuffer(maxStdoutBytes)
	stderr := newBoundedBuffer(maxStderrBytes)
	modConfig := wazero.NewModuleConfig().
		WithName(""). // ayni CompiledModule'u tekrar tekrar instantiate edebilmek icin
		WithStdin(bytes.NewReader(reqBytes)).
		WithStdout(stdout).
		WithStderr(stderr)

	mod, instErr := rt.runtime.InstantiateModule(callCtx, rt.compiled, modConfig)
	if mod != nil {
		defer mod.Close(context.Background())
	}
	if instErr != nil {
		if ctxErr := callCtx.Err(); ctxErr != nil {
			return wireResult{}, fmt.Errorf("eklenti calistirilamadi (op=%q): zaman asimina ugradi ya da iptal edildi: %w", req.Op, ctxErr)
		}
		return wireResult{}, fmt.Errorf("eklenti calistirilamadi (op=%q): calisma zamani hatasi", req.Op)
	}
	if stdout.exceeded || stderr.exceeded {
		return wireResult{}, fmt.Errorf("eklenti cikti sinirini asti (op=%q, stdout=%d/%d bayt, stderr=%d/%d bayt)",
			req.Op, stdout.written, maxStdoutBytes, stderr.written, maxStderrBytes)
	}

	resp, err := decodeStrictResult(stdout.Bytes())
	if err != nil {
		return wireResult{}, fmt.Errorf("eklenti ciktisi gecersiz (op=%q, stdout=%d bayt): %w", req.Op, len(stdout.Bytes()), err)
	}
	if err := validateEnvelopeMeta(resp, req.Op); err != nil {
		return wireResult{}, fmt.Errorf("eklenti ciktisi gecersiz (op=%q): %w", req.Op, err)
	}

	return resp, nil
}

// validateEnvelopeMeta, eklentiden gelen ham yanıtın Evaluate/Mask'ten
// BAĞIMSIZ, ortak zarf kurallarına uyduğunu doğrular: Error alanı boş
// olmalı, Version/Op ise isteğinkiyle eşleşmelidir. Saf bir fonksiyondur
// (Wasm çalıştırmadan doğrudan test edilebilir).
func validateEnvelopeMeta(resp wireResult, wantOp string) error {
	if resp.Error != "" {
		return errors.New("eklenti hata dondurdu")
	}
	if resp.Version != wasmproto.ProtocolVersion {
		return fmt.Errorf("eklenti protokol versiyonu uyusmuyor: got %d want %d", resp.Version, wasmproto.ProtocolVersion)
	}
	if resp.Op != wantOp {
		return fmt.Errorf("eklenti yaniti beklenmeyen operasyon iceriyor: got %q want %q", resp.Op, wantOp)
	}
	return nil
}

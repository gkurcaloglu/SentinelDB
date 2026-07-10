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
// isteği olarak eklentiye gönderir ve dönen kararı ayrıştırır. verdict,
// eklentinin döndürdüğü ham dizgidir (ör. "ALLOW"/"BLOCK"); bunun tam
// olarak geçerli bir değer olup olmadığının doğrulanması wasm.Policy'nin
// sorumluluğundadır (bkz. policy.go).
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
	if err := validateResult(resp, wasmproto.OpEvaluateQuery); err != nil {
		return "", "", err
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
// gönderir. Dönen değerin geçerli UTF-8 olduğu ve boyutunun makul bir
// sınırı aşmadığı doğrulanır; aksi halde (ya da eklenti bir Error
// döndürürse) bir hata döner - çağıran (internal/masking) bunu
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
	if err := validateResult(resp, wasmproto.OpMaskValue); err != nil {
		return MaskResult{}, err
	}
	if !utf8.ValidString(resp.Value) {
		return MaskResult{}, fmt.Errorf("eklenti gecersiz UTF-8 dondurdu")
	}
	if len(resp.Value) > maxMaskedValueSize {
		return MaskResult{}, fmt.Errorf("eklenti cok buyuk bir deger dondurdu: %d bayt (ust sinir %d)", len(resp.Value), maxMaskedValueSize)
	}
	return MaskResult{Value: resp.Value, Changed: resp.Changed, Reason: resp.Reason}, nil
}

// validateResult, eklentinin döndürdüğü ortak zarf alanlarını (Error,
// Version, Op) doğrular. Bu, hem Evaluate hem Mask için ortak olan
// "eklenti sözleşmeye uydu mu" kontrolüdür.
func validateResult(resp wasmproto.Result, wantOp string) error {
	if resp.Error != "" {
		return fmt.Errorf("eklenti hata dondurdu: %s", resp.Error)
	}
	if resp.Version != wasmproto.ProtocolVersion {
		return fmt.Errorf("eklenti protokol versiyonu uyusmuyor: got %d want %d", resp.Version, wasmproto.ProtocolVersion)
	}
	if resp.Op != wantOp {
		return fmt.Errorf("eklenti yaniti beklenmeyen operasyon iceriyor: got %q want %q", resp.Op, wantOp)
	}
	return nil
}

// call, verilen isteği JSON olarak eklentiye (stdin) yazar, eklentiyi taze
// bir instance olarak çalıştırır ve stdout'tan dönen zarfı ayrıştırır. Bu,
// Evaluate ve Mask tarafından paylaşılan tek düşük seviyeli çağrı
// mekanizmasıdır (tek yüklü CompiledModule, tek runtime).
func (rt *Runtime) call(ctx context.Context, req wasmproto.Envelope) (wasmproto.Result, error) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return wasmproto.Result{}, fmt.Errorf("istek serilestirilemedi: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, rt.timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	modConfig := wazero.NewModuleConfig().
		WithName(""). // ayni CompiledModule'u tekrar tekrar instantiate edebilmek icin
		WithStdin(bytes.NewReader(reqBytes)).
		WithStdout(&stdout).
		WithStderr(&stderr)

	mod, instErr := rt.runtime.InstantiateModule(callCtx, rt.compiled, modConfig)
	if mod != nil {
		defer mod.Close(context.Background())
	}
	if instErr != nil {
		return wasmproto.Result{}, fmt.Errorf("wasm eklentisi calistirilamadi: %w (stderr=%q)", instErr, stderr.String())
	}

	var resp wasmproto.Result
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return wasmproto.Result{}, fmt.Errorf("eklenti ciktisi ayristirilamadi: %w (stdout=%q, stderr=%q)", err, stdout.String(), stderr.String())
	}

	return resp, nil
}

// Package wasm, SentinelDB gateway'inin firewall karar mantığını yerleşik
// (native) Go kodu yerine, çalışma zamanında yüklenen bir Wasm eklentisi
// (bkz. plugins/firewall) içinde çalıştırmasını sağlayan host tarafı
// altyapıyı barındırır. Wasm runtime olarak, cgo/C toolchain gerektirmeyen
// saf Go implementasyonu github.com/tetratelabs/wazero kullanılır.
package wasm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"github.com/gkurcaloglu/sentineldb/internal/wasmproto"
)

// defaultTimeout, tek bir Evaluate çağrısına tanınan azami süredir. Eklenti
// bu süreyi aşarsa çağrı context iptaliyle zorla sonlandırılır (bkz.
// wazero.RuntimeConfig.WithCloseOnContextDone); böylece bozuk ya da kötü
// niyetli bir eklenti gateway'i sonsuza dek bloklayamaz.
const defaultTimeout = 2 * time.Second

// Runtime, derlenmiş bir firewall Wasm eklentisini yöneten host tarafı
// çalışma zamanıdır. Eklenti WASI "command" modeliyle (main() bir kez
// çalışıp çıkar) derlendiğinden, aynı CompiledModule her Evaluate
// çağrısında taze bir instance olarak çalıştırılır; bir instance'ı ikinci
// kez çağırmak WASI command modülleri için tanımsızdır.
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

// Evaluate, query'yi ve blockedPhrases listesini JSON isteği olarak
// eklentiye (stdin) yazar, eklentiyi taze bir instance olarak çalıştırır ve
// stdout'tan dönen kararı ayrıştırır. verdict wasmproto.VerdictAllow ya da
// wasmproto.VerdictBlock olur.
func (rt *Runtime) Evaluate(ctx context.Context, query string, blockedPhrases []string) (verdict, reason string, err error) {
	reqBytes, err := json.Marshal(wasmproto.Request{Query: query, BlockedPhrases: blockedPhrases})
	if err != nil {
		return "", "", fmt.Errorf("istek serilestirilemedi: %w", err)
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
		return "", "", fmt.Errorf("wasm eklentisi calistirilamadi: %w (stderr=%q)", instErr, stderr.String())
	}

	var resp wasmproto.Response
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return "", "", fmt.Errorf("eklenti ciktisi ayristirilamadi: %w (stdout=%q, stderr=%q)", err, stdout.String(), stderr.String())
	}

	return resp.Verdict, resp.Reason, nil
}

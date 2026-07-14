package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/gkurcaloglu/sentineldb/internal/api"
	"github.com/gkurcaloglu/sentineldb/internal/config"
	"github.com/gkurcaloglu/sentineldb/internal/firewall"
	"github.com/gkurcaloglu/sentineldb/internal/gateway"
	"github.com/gkurcaloglu/sentineldb/internal/masking"
	"github.com/gkurcaloglu/sentineldb/internal/metrics"
	"github.com/gkurcaloglu/sentineldb/internal/protocol"
	"github.com/gkurcaloglu/sentineldb/internal/wasm"
)

const configPath = "config.yaml"

const (
	// dialTimeout, upstream Postgres'e baglanmak icin tanınan azami süredir.
	// Bu olmadan net.Dial, upstream yanit vermediginde sonsuza kadar
	// bekleyebilir ve handleConn goroutine'i asla sonlanmaz.
	dialTimeout = 5 * time.Second
	// httpShutdownTimeout, kapatma sirasinda metrics/API sunucularinin
	// bekleyen istekleri tamamlamasi icin tanınan azami süredir.
	httpShutdownTimeout = 5 * time.Second
	// httpReadHeaderTimeout, metrics/API sunucularinin istek basliklarini
	// okumak icin tanidigi azami süredir. Bu olmadan http.Server varsayilan
	// olarak sinirsiz bekler; yavas ya da kasitli olarak baslik göndermeyi
	// geciktiren bir istemci (Slowloris tarzi) bir dinleyici goroutine'ini
	// sonsuza kadar mesgul tutabilirdi.
	httpReadHeaderTimeout = 5 * time.Second
	// httpReadTimeout/httpWriteTimeout, tüm istek/yanit dongusu icin tanınan
	// azami süredir (bu endpoint'ler kucuk, sabit boyutlu JSON/metin
	// dondurdugu icin comert bir sinirdir).
	httpReadTimeout  = 10 * time.Second
	httpWriteTimeout = 10 * time.Second
	// httpIdleTimeout, keep-alive baglantilarin istek beklerken acik
	// kalabilecegi azami süredir.
	httpIdleTimeout = 60 * time.Second
)

// listenAddr/targetAddr/metricsAddr/apiAddr, varsayilan olarak lokal
// (non-Docker) gelistirmedeki degerleriyle sabittir; ilgili ortam
// degiskeni set edilmisse (ör. Docker Compose'ta) onu kullanir. Bu, gateway'in
// Postgres'e Docker servis adiyla ("postgres:5432" gibi) baglanabilmesini ve
// container icinde tum arayuzlerde dinleyebilmesini ("0.0.0.0:5432")
// saglar; localhost disi bir deger verilmedigi surece davranis oncekiyle
// birebir aynidir.
var (
	listenAddr  = envOrDefault("SENTINELDB_LISTEN_ADDR", "localhost:5432")
	targetAddr  = envOrDefault("SENTINELDB_TARGET_ADDR", "localhost:5433")
	metricsAddr = envOrDefault("SENTINELDB_METRICS_ADDR", ":9090")
	apiAddr     = envOrDefault("SENTINELDB_API_ADDR", ":8080")
)

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var connCounter atomic.Uint64

// logFullQueries, main() basinda config.yaml'daki logging.log_full_queries
// degerinden bir kere set edilir. Varsayilan (false) durumda loglar tam SQL
// sorgu metnini icermez; yalnizca verdict, mesaj tipi, sure ve baglanti
// kimligi gibi guvenli metadata loglanir (bkz. logGateDecision). Bu bayrak
// yalnizca lokal gelistirme/hata ayiklama icin acikca etkinlestirilmelidir.
var logFullQueries bool

// activeConns, kapatma sirasinda hala acik olan client/upstream
// baglantilarini izler. handleConn zaten kendi defer'lariyla baglantilarini
// kapatir; bu tip, sinyal geldiginde bunlari DISARIDAN zorla kapatarak
// bloklu Read/io.Copy cagrilarinin hemen bir hata ile donmesini ve
// goroutine'lerin sizmadan sonlanmasini saglar.
type activeConns struct {
	mu    sync.Mutex
	conns map[uint64][]net.Conn
}

func newActiveConns() *activeConns {
	return &activeConns{conns: make(map[uint64][]net.Conn)}
}

func (a *activeConns) add(id uint64, conns ...net.Conn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.conns[id] = conns
}

func (a *activeConns) remove(id uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.conns, id)
}

// closeAll, izlenen tum baglantilari kapatir (Close cagrisi net.Conn icin
// idempotent'tir; handleConn'un kendi defer'lariyla cakismasi zararsizdir).
func (a *activeConns) closeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, conns := range a.conns {
		for _, c := range conns {
			c.Close()
		}
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("config yuklenemedi: %v", err)
	}
	logFullQueries = cfg.Logging.LogFullQueries
	if logFullQueries {
		log.Println("UYARI: logging.log_full_queries=true - tam SQL sorgu metni loglara yaziliyor. Bu yalnizca lokal gelistirme icin kullanilmalidir.")
	}

	// Firewall karar mantigi VE PII maskeleme mantigi, calisma zamaninda
	// yuklenen TEK bir sandbox'li Wasm eklentisi (bkz. plugins/firewall)
	// icinde calisir - ikinci bir runtime ya da ikinci bir ayrica yuklenen
	// eklenti yoktur (bkz. internal/wasm.Runtime.Evaluate/Mask, ayni
	// CompiledModule'u paylasir).
	wasmRuntime, err := wasm.NewRuntime(ctx, cfg.Wasm.PluginPath)
	if err != nil {
		log.Fatalf("wasm eklentisi yuklenemedi: %v", err)
	}
	defer wasmRuntime.Close(context.Background())

	policy := wasm.NewPolicy(wasmRuntime, cfg.Firewall.BlockedPhrases, func(err error) {
		log.Printf("wasm politika hatasi: %v", err)
	})
	log.Printf("firewall politikasi yuklendi (eklenti: %s): %d yasakli ifade %v", cfg.Wasm.PluginPath, len(cfg.Firewall.BlockedPhrases), cfg.Firewall.BlockedPhrases)

	masker := wasm.NewMasker(wasmRuntime)
	maskCfg := masking.NewConfig(cfg.Masking.Enabled, cfg.Masking.Columns)
	if maskCfg.Enabled {
		log.Printf("PII maskeleme aktif: sutunlar=%v", cfg.Masking.Columns)
	} else {
		log.Println("PII maskeleme kapali (masking.enabled=false)")
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	metricsServer := &http.Server{
		Addr:              metricsAddr,
		Handler:           metricsMux,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
	}

	go func() {
		log.Printf("metrics sunucusu %s adresinde /metrics uzerinden yayinda", metricsAddr)
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("metrics sunucusu durdu: %v", err)
		}
	}()

	// React dashboard'unun okudugu salt okunur JSON API. CORS acik: bu
	// endpoint gizli veri icermiyor (config.yaml'da zaten gorunen sayac ve
	// kural listesi).
	apiMux := http.NewServeMux()
	apiMux.Handle("/api/status", api.WithCORS(api.NewStatusHandler(m, cfg.Firewall.BlockedPhrases)))
	apiServer := &http.Server{
		Addr:              apiAddr,
		Handler:           apiMux,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
	}

	go func() {
		log.Printf("API sunucusu %s adresinde /api/status uzerinden yayinda", apiAddr)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("API sunucusu durdu: %v", err)
		}
	}()

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", listenAddr, err)
	}
	log.Printf("gateway listening on %s, forwarding to %s", listenAddr, targetAddr)

	conns := newActiveConns()
	var wg sync.WaitGroup

	go func() {
		<-ctx.Done()
		log.Println("shutting down...")

		// Yeni baglanti kabul etmeyi durdur.
		listener.Close()
		// Aktif baglantilari zorla kapat: gate.Run/transformer.Run icindeki
		// bloklu Read cagrilari boylece hata ile doner ve handleConn
		// goroutine'leri sonlanip wg.Wait()'in altta ilerlemesine izin verir.
		conns.closeAll()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		var httpWG sync.WaitGroup
		httpWG.Add(2)
		go func() {
			defer httpWG.Done()
			if err := metricsServer.Shutdown(shutdownCtx); err != nil {
				log.Printf("metrics sunucusu duzgun kapanmadi: %v", err)
			}
		}()
		go func() {
			defer httpWG.Done()
			if err := apiServer.Shutdown(shutdownCtx); err != nil {
				log.Printf("API sunucusu duzgun kapanmadi: %v", err)
			}
		}()
		httpWG.Wait()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				log.Println("shutdown complete")
				return
			default:
				log.Printf("accept error: %v", err)
				continue
			}
		}

		m.ConnectionsTotal.Inc()

		wg.Add(1)
		go func() {
			defer wg.Done()
			handleConn(ctx, conn, cfg, policy, masker, maskCfg, m, conns)
		}()
	}
}

// handleConn, backend'e baglanip her iki baglantiyi da activeConns'a
// kaydeden PAYLASILAN on hazirligi yapar, ardindan cfg.Protocol.
// ExtendedQueryEnabled'a gore TAM OLARAK iki yoldan birine (runSimpleConnection
// - varsayilan/degismemis mevcut davranis - ya da opt-in
// runExtendedConnection) dagitir. Ayni baglantida bu ikisi arasinda hicbir
// karisik yonlendirme/gecis YOKTUR - bkz. docs/design/0001-extended-query.md.
func handleConn(ctx context.Context, client net.Conn, cfg *config.Config, policy firewall.Policy, masker masking.Masker, maskCfg masking.Config, m *metrics.Metrics, conns *activeConns) {
	defer client.Close()

	connID := connCounter.Add(1)

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var dialer net.Dialer
	target, err := dialer.DialContext(dialCtx, "tcp", targetAddr)
	if err != nil {
		log.Printf("[conn %d] failed to connect to target %s: %v", connID, targetAddr, err)
		return
	}
	defer target.Close()

	conns.add(connID, client, target)
	defer conns.remove(connID)

	if cfg.Protocol.ExtendedQueryEnabled {
		runExtendedConnection(ctx, client, target, connID, policy, masker, maskCfg, m)
		return
	}
	runSimpleConnection(ctx, client, target, connID, policy, masker, maskCfg, m)
}

// runSimpleConnection, mevcut (varsayilan) Simple Query yolunun TAM OLARAK
// AYNI davranisidir - yalnizca handleConn'dan bagimsiz, testable bir
// fonksiyona cikarilmistir. Hicbir mantik degistirilmedi: ayni Gate/
// masking.Transformer/SerializedWriter/TxState kurulumu, ayni iki yonlu
// goroutine yapisi, ayni SSL/GSS reddi (bkz. firewall.Gate.handle), ayni
// Simple Query politika/maskeleme davranisi, ayni yari-kapanma (half-close)
// kurallari, ayni metrics/logging geri cagirimlari.
func runSimpleConnection(ctx context.Context, client, target net.Conn, connID uint64, policy firewall.Policy, masker masking.Masker, maskCfg masking.Config, m *metrics.Metrics) {
	// Butun client yazmalari (gercek backend yanitlarinin/maskelenmis
	// DataRow'larin iletilmesi, SSL red baytı, sentetik firewall
	// ErrorResponse/ReadyForQuery) TEK bir mutex korumali yazici uzerinden
	// gecer; boylece iki farkli goroutine PostgreSQL protokol baytlarini
	// asla ic ice yazamaz (bkz. gorev F).
	clientWriter := protocol.NewSerializedWriter(client)

	// Baglantinin en son bilinen ReadyForQuery islem durumu (I/T/E).
	// Sunucudan gelen gercek ReadyForQuery'ler bunu gunceller
	// (masking.Transformer); firewall.Gate sentetik ReadyForQuery
	// uretirken bunu okur (bkz. gorev G).
	txState := protocol.NewTxState()

	// client -> server yonu: Gate, her mesaji politikaya gore
	// degerlendirip izin verilenleri target'a oldugu gibi iletir,
	// engellenenleri ise target'a hic ulastirmadan dogrudan client'a
	// sentetik bir ErrorResponse+ReadyForQuery ile yanitlar. Ayrica V1
	// sinirlarini da uygular: SSLRequest'i hic iletmeden 'N' ile yanitlar
	// ve genisletilmis sorgu protokolu mesajlarini reddeder.
	gate := firewall.NewGate(policy, target, clientWriter,
		func(msg protocol.Message, v firewall.Verdict, reason string, duration time.Duration) {
			if v == firewall.Block {
				m.BlockedQueriesTotal.Inc()
			}
			logGateDecision(connID, msg, v, reason, duration)
		},
		func(err error) { log.Printf("[conn %d] client->server protokol ayristirma durdu: %v", connID, err) },
	)
	gate.SetTxState(txState)

	// server -> client yonu: eskiden salt gozlemci SniffReader kullanan bu
	// yon, artik yapilandirilmis sutunlari (ör. email) maskeleyen aktif
	// bir Transformer'dir (bkz. internal/masking). Degismeyen mesajlar
	// (Authentication, ParameterStatus, CommandComplete, vb.) oldugu gibi
	// iletilir.
	transformer := masking.NewTransformer(ctx, maskCfg, masker, clientWriter, txState, masking.Hooks{
		OnMessage: func(msg protocol.Message) { logMessage(connID, msg) },
		OnMaskAttempt: func(column string, changed bool, maskErr error, duration time.Duration) {
			// Wasm cagrisinin suresi, basarili/basarisiz her denemede
			// gozlemlenir. sentineldb_masking_errors_total BURADA
			// ARTIRILMAZ: bir maskeleme hatasi her zaman Transformer'in
			// failClosed() cagirmasina ve dolayisiyla OnError'un TAM
			// OLARAK BIR KEZ tetiklenmesine yol acar (bkz. asagidaki
			// OnError). Sayaci burada da artirmak, ayni hatayi iki kez
			// saymaya (OnMaskAttempt + OnError) neden olurdu.
			m.MaskingPluginDuration.Observe(duration.Seconds())
			if maskErr != nil {
				// Guvenlik: yalnizca sutun adi ve hata loglanir, hicbir
				// zaman hucre degeri (orijinal ya da maskelenmis) loglanmaz.
				log.Printf("[conn %d] S->C sutun maskeleme hatasi (sutun=%q): %v", connID, column, maskErr)
				return
			}
			if changed {
				m.MaskedCellsTotal.Inc()
			}
		},
		// OnError, Transformer'in fail-closed kapattigi HER durum icin
		// (maskeleme hatasi, bozuk RowDescription/DataRow, alan sayisi
		// uyumsuzlugu, ikili sutun, desteklenmeyen COPY, ayristirma
		// hatasi) TAM OLARAK BIR KEZ tetiklenir (Transformer, t.err zaten
		// doluysa OnError'u tekrar cagirmaz). Bu yuzden
		// sentineldb_masking_errors_total'i artirmak icin tek ve dogru yer
		// burasidir.
		OnError: func(err error) {
			m.MaskingErrorsTotal.Inc()
			log.Printf("[conn %d] server->client isleme durdu: %v", connID, err)
		},
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		runErr := gate.Run(client)
		if firewall.IsFailClosed(runErr) {
			// Gate bilerek kapatti (desteklenmeyen protokol ya da
			// ayristirma hatasi); target'a hic bir sey iletilmemis olabilir,
			// bu yuzden yarim kapanmanin (CloseWrite) Postgres tarafindan
			// fark edilmesini beklemek yerine dogrudan tam kapatiyoruz ki
			// karsi yondeki bloklu okuma da hemen sonlansin.
			target.Close()
			return
		}
		if tcpConn, ok := target.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		runErr := transformer.Run(target)
		if masking.IsFailClosed(runErr) {
			// Transformer bilerek kapatti (ayristirma/maskeleme hatasi,
			// desteklenmeyen ikili format ya da COPY protokolu); client'a
			// zaten bir FATAL ErrorResponse yazildi (bkz. Transformer).
			// Karsi yondeki bloklu okumanin da hemen sonlanmasi icin
			// client'i tam kapatiyoruz.
			client.Close()
			return
		}
		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}

// runExtendedConnection, opt-in Extended Query yoludur (bkz.
// protocol.extended_query_enabled: true). Tam yasam dongusu (bkz. gorev 19):
//
//  1. internal/gateway.RunStartupHandoff, client/target'i MUNHASIRAN
//     sahiplenip duz metin startup/authentication'i tamamlar (SSLRequest/
//     GSSENCRequest'e 'N', CancelRequest'i tek seferlik iletir, aksi halde
//     ilk GERCEK ReadyForQuery'e kadar authentication'i relay eder);
//  2. basarisizlikta ya da CancelRequest'te hicbir ExtendedRuntime
//     olusturulmadan doner (her iki baglanti da handleConn'un kendi
//     defer'lariyla kapanir);
//  3. basarili, CancelRequest-olmayan handoff'tan SONRA: tek bir taze
//     protocol.State, tek bir ExtendedRuntime (masking.enabled'a gore
//     NewExtendedRuntimeWithMasking ya da NewExtendedRuntime) ve tek bir
//     ExtendedFrontend olusturulur;
//  4. ExtendedRuntime.Run baslatilir, WaitStarted ile olay dongusunun
//     GERCEKTEN hazir oldugu POLLING olmadan dogrulanir;
//  5. ANCAK BUNDAN SONRA Gate.RunExtended cagirilir (ayni client
//     baglantisi uzerinde, TEK okuyucu/yazici artik ExtendedRuntime'dir);
//  6. her iki taraf da (frontend okuyucusu, runtime) donene kadar
//     sirayla beklenir.
//
// Bu baglantida Simple Query ('Q') YOKTUR - ExtendedFrontend bunu zaten
// fail-closed reddeder (bkz. firewall.ExtendedFrontend). Masking.Transformer
// bu yolda HIC olusturulmaz; TEK client yazicisi ExtendedRuntime'in olay
// dongusudur (bkz. gorev 14).
func runExtendedConnection(ctx context.Context, client, target net.Conn, connID uint64, policy firewall.Policy, masker masking.Masker, maskCfg masking.Config, m *metrics.Metrics) {
	handoffResult, err := gateway.RunStartupHandoff(ctx, client, target, gateway.DefaultStartupLimits())
	if err != nil {
		logStartupOutcome(connID, err)
		return
	}
	if handoffResult.CancelOnly {
		logExtConn(connID, "CancelRequest tamamlandi, baglanti kapatiliyor")
		return
	}

	state := protocol.NewState()
	seqLimits := protocol.DefaultSequencerLimits()
	runtimeLimits := gateway.DefaultRuntimeLimits()

	var rt *gateway.ExtendedRuntime
	if maskCfg.Enabled {
		rt, err = gateway.NewExtendedRuntimeWithMasking(state, target, client, seqLimits, runtimeLimits,
			maskCfg, masker, masking.DefaultExtendedLimits(), extendedMaskingHooks(connID, m))
	} else {
		rt, err = gateway.NewExtendedRuntime(state, target, client, seqLimits, runtimeLimits)
	}
	if err != nil {
		log.Printf("[conn %d] Extended runtime olusturulamadi: %v", connID, err)
		return
	}

	frontend, err := firewall.NewExtendedFrontend(rt, policy, extendedOnDecide(connID, m))
	if err != nil {
		log.Printf("[conn %d] Extended frontend olusturulamadi: %v", connID, err)
		return
	}

	runDone := make(chan error, 1)
	go func() { runDone <- rt.Run(ctx) }()

	if err := rt.WaitStarted(ctx); err != nil {
		// Runtime hic kullanilabilir olamadan durdu/iptal edildi -
		// Gate.RunExtended ASLA baslatilmaz (bkz. gorev 12). Run'in
		// goroutine'ini kesinlikle katilmadan (join etmeden) donmuyoruz.
		runErr := <-runDone
		logExtendedRuntimeOutcome(connID, runErr, m)
		return
	}

	gate := &firewall.Gate{}
	frontendErr := gate.RunExtended(ctx, client, frontend)
	logExtendedFrontendOutcome(connID, frontendErr)

	runErr := <-runDone
	logExtendedRuntimeOutcome(connID, runErr, m)
}

// extendedOnDecide, ExtendedFrontend'in Policy.Evaluate cagrisi SADECE
// Parse mesajlari icin tetikledigi karar geri cagirimidir (bkz. gorev 15).
// Gecirilen protocol.Message HICBIR ZAMAN Raw ya da Query alani tasimaz
// (bkz. firewall.NewExtendedFrontend) - bu yuzden SQL/isim/deger burada
// ZATEN loglanamaz; mevcut Simple Query logGateDecision ile AYNI güvenli
// "engellendiyse neden logla" sözleşmesi izlenir.
func extendedOnDecide(connID uint64, m *metrics.Metrics) func(protocol.Message, firewall.Verdict, string, time.Duration) {
	return func(msg protocol.Message, v firewall.Verdict, reason string, duration time.Duration) {
		if v == firewall.Block {
			m.BlockedQueriesTotal.Inc()
			log.Printf("[conn %d] C->S %s (Extended) ENGELLENDI verdict=%s sure=%s neden=%s", connID, msg.Name, v, duration.Round(time.Microsecond), reason)
			return
		}
		log.Printf("[conn %d] C->S %s (Extended) verdict=%s sure=%s", connID, msg.Name, v, duration.Round(time.Microsecond))
	}
}

// extendedMaskingHooks, ExtendedRuntime'in DataRow maskeleme kancalaridir
// (bkz. gorev 16). OnMaskAttempt, Simple Query Transformer'la AYNI iki
// metrigi besler (sure gozlemi + basarili degisim sayaci); Masker'in
// dondurdugu HAM hata metni (guvenli ifsa garantisi olmadigindan) ASLA
// loglanmaz - yalnizca sutun adi + sabit bir metin. Terminal (baglanti
// sonlandirici) bir maskeleme hatasi icin sentineldb_masking_errors_total,
// BURADA DEGIL, rt.Run()'un DONDURDUGU nihai hatadan (bkz.
// logExtendedRuntimeOutcome) TAM OLARAK BIR KEZ artirilir - boylece
// OnMaskAttempt ile runtime sonlanmasi arasinda cifte sayim olmaz (bkz.
// mevcut Simple Query yolundaki AYNI ilke).
func extendedMaskingHooks(connID uint64, m *metrics.Metrics) masking.Hooks {
	return masking.Hooks{
		OnMaskAttempt: func(column string, changed bool, maskErr error, duration time.Duration) {
			m.MaskingPluginDuration.Observe(duration.Seconds())
			if maskErr != nil {
				log.Printf("[conn %d] Extended S->C sutun maskeleme hatasi (sutun=%q)", connID, column)
				return
			}
			if changed {
				m.MaskedCellsTotal.Inc()
			}
		},
	}
}

// logExtConn, Extended Query yolu icin genel, guvenli (deger icermeyen) bir
// durum log satiridir.
func logExtConn(connID uint64, msg string) {
	log.Printf("[conn %d] Extended: %s", connID, msg)
}

// logStartupOutcome, RunStartupHandoff'un dondurdugu SABIT, guvenli hata
// kategorisini (bkz. internal/gateway/startup_handoff.go) siniflandirip
// loglar - hicbir startup parametresi/kullanici adi/sifre/SASL verisi/
// backend ErrorResponse alani ASLA loglanmaz (bu garantiyi zaten
// RunStartupHandoff'un kendisi saglar; burada yalnizca o SABIT hata
// SINIFLANDIRILIR).
func logStartupOutcome(connID uint64, err error) {
	switch {
	case errors.Is(err, gateway.ErrStartupClientEOF):
		logExtConn(connID, "istemci startup/authentication sirasinda baglantiyi kapatti (EOF)")
	case errors.Is(err, gateway.ErrStartupBackendErrorResponse):
		logExtConn(connID, "backend authentication sirasinda bir ErrorResponse dondurdu (istemciye iletildi)")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		logExtConn(connID, "global kapanma nedeniyle startup/authentication yarida kesildi")
	default:
		log.Printf("[conn %d] Extended: startup/authentication basarisiz: %v", connID, err)
	}
}

// logExtendedFrontendOutcome, Gate.RunExtended'in dondurdugu SABIT, guvenli
// hatayi loglar (bkz. internal/firewall/extended_frontend.go - tum donen
// hatalar zaten sabit, deger icermeyen kategorilerdir).
func logExtendedFrontendOutcome(connID uint64, err error) {
	if err == nil {
		return
	}
	log.Printf("[conn %d] Extended frontend sonlandi: %v", connID, err)
}

// logExtendedRuntimeOutcome, ExtendedRuntime.Run'in dondurdugu SABIT,
// guvenli hatayi siniflandirip loglar VE - yalnizca burada, TAM OLARAK BIR
// KEZ - terminal bir maskeleme hatasi icin sentineldb_masking_errors_total'i
// artirir (bkz. extendedMaskingHooks'un doc yorumu).
func logExtendedRuntimeOutcome(connID uint64, err error, m *metrics.Metrics) {
	switch {
	case err == nil:
		logExtConn(connID, "baglanti normal sekilde sonlandi")
	case errors.Is(err, gateway.ErrExtendedMaskingFailed):
		m.MaskingErrorsTotal.Inc()
		logExtConn(connID, "maskeleme hatasi nedeniyle baglanti fail-closed sonlandirildi")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		logExtConn(connID, "global kapanma nedeniyle sonlandi")
	default:
		log.Printf("[conn %d] Extended runtime sonlandi: %v", connID, err)
	}
}

// logMessage, genel (politika kararina bagli olmayan) mesaj loglamasidir.
// Guvenlik: hicbir kosulda SQL sorgu metnini ya da DataRow hucre
// degerlerini basmaz (bkz. logGateDecision, Query mesajlari icin tek
// yetkili log noktasidir; DataRow ise burada hic loglanmaz).
func logMessage(connID uint64, m protocol.Message) {
	dir := "C->S"
	if m.Direction == protocol.Backend {
		dir = "S->C"
	}
	switch m.Name {
	case protocol.NameStartupMessage:
		log.Printf("[conn %d] %s StartupMessage protokol=%d.%d params=%v", connID, dir, m.ProtocolMajor, m.ProtocolMinor, m.StartupParams)
	case "DataRow", "CopyData":
		// yuksek hacimli VE potansiyel olarak hassas veri tasiyan
		// mesajlar; log gurultusunu ve PII sizintisini onlemek icin atlanir.
	default:
		log.Printf("[conn %d] %s %s (uzunluk=%d)", connID, dir, m.Name, m.Length)
	}
}

// logGateDecision, Gate'in her karari (politika Allow/Block, desteklenmeyen
// protokol reddi, SSLRequest yaniti) icin cagrilir.
//
// Guvenlik: varsayilan olarak tam SQL sorgu metni LOGLANMAZ. Yalnizca
// verdict, mesaj tipi, degerlendirme suresi ve baglanti kimligi gibi
// guvenli metadata loglanir. Tam metni gormek icin config.yaml'da
// logging.log_full_queries acikca true yapilmalidir (varsayilan: false) -
// bu yalnizca lokal gelistirme/hata ayiklama icindir, cunku sorgu metni
// PII/hassas veri icerebilir.
func logGateDecision(connID uint64, m protocol.Message, v firewall.Verdict, reason string, duration time.Duration) {
	if m.Name != "Query" {
		if v == firewall.Block {
			log.Printf("[conn %d] C->S %s ENGELLENDI verdict=%s sure=%s neden=%s", connID, m.Name, v, duration.Round(time.Microsecond), reason)
			return
		}
		logMessage(connID, m)
		return
	}

	if v == firewall.Block {
		log.Printf("[conn %d] C->S Query ENGELLENDI verdict=%s sure=%s neden=%s", connID, v, duration.Round(time.Microsecond), reason)
	} else {
		log.Printf("[conn %d] C->S Query verdict=%s sure=%s (uzunluk=%d)", connID, v, duration.Round(time.Microsecond), m.Length)
	}
	if logFullQueries {
		log.Printf("[conn %d] C->S sorgu metni (log_full_queries=true): %s", connID, m.Query)
	}
}

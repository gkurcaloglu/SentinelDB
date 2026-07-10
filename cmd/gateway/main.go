package main

import (
	"context"
	"io"
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
	"github.com/gkurcaloglu/sentineldb/internal/metrics"
	"github.com/gkurcaloglu/sentineldb/internal/protocol"
	"github.com/gkurcaloglu/sentineldb/internal/wasm"
)

const (
	listenAddr = "localhost:5432"
	targetAddr = "localhost:5433"
	configPath = "config.yaml"

	metricsAddr = ":9090"
	apiAddr     = ":8080"

	// dialTimeout, upstream Postgres'e baglanmak icin tanınan azami süredir.
	// Bu olmadan net.Dial, upstream yanit vermediginde sonsuza kadar
	// bekleyebilir ve handleConn goroutine'i asla sonlanmaz.
	dialTimeout = 5 * time.Second
	// httpShutdownTimeout, kapatma sirasinda metrics/API sunucularinin
	// bekleyen istekleri tamamlamasi icin tanınan azami süredir.
	httpShutdownTimeout = 5 * time.Second
)

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

	// Firewall karar mantigi artik native Go kodu (firewall.DenyKeywords)
	// olarak degil, calisma zamaninda yuklenen sandbox'li bir Wasm eklentisi
	// (bkz. plugins/firewall) icinde calisiyor. wasm.Policy, mevcut
	// firewall.Policy arayuzunu bu eklentiden besler; firewall.Gate hic
	// degismedi.
	wasmRuntime, err := wasm.NewRuntime(ctx, cfg.Wasm.PluginPath)
	if err != nil {
		log.Fatalf("wasm eklentisi yuklenemedi: %v", err)
	}
	defer wasmRuntime.Close(context.Background())

	policy := wasm.NewPolicy(wasmRuntime, cfg.Firewall.BlockedPhrases, func(err error) {
		log.Printf("wasm politika hatasi: %v", err)
	})
	log.Printf("firewall politikasi yuklendi (eklenti: %s): %d yasakli ifade %v", cfg.Wasm.PluginPath, len(cfg.Firewall.BlockedPhrases), cfg.Firewall.BlockedPhrases)

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	metricsServer := &http.Server{Addr: metricsAddr, Handler: metricsMux}

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
	apiServer := &http.Server{Addr: apiAddr, Handler: apiMux}

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
		// Aktif baglantilari zorla kapat: gate.Run/io.Copy icindeki bloklu
		// Read cagrilari boylece hata ile doner ve handleConn goroutine'leri
		// sonlanip wg.Wait()'in altta ilerlemesine izin verir.
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
			handleConn(ctx, conn, policy, m, conns)
		}()
	}
}

func handleConn(ctx context.Context, client net.Conn, policy firewall.Policy, m *metrics.Metrics, conns *activeConns) {
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

	// client -> server yonu artik salt gozlemci degil: Gate, her mesaji
	// politikaya gore degerlendirip izin verilenleri target'a oldugu gibi
	// iletir, engellenenleri ise target'a hic ulastirmadan dogrudan
	// client'a sentetik bir ErrorResponse+ReadyForQuery ile yanitlar. Ayrica
	// V1 sinirlarini da uygular: SSLRequest'i hic iletmeden 'N' ile yanitlar
	// ve genisletilmis sorgu protokolu mesajlarini reddeder (bkz. Gate doc).
	gate := firewall.NewGate(policy, target, client,
		func(msg protocol.Message, v firewall.Verdict, reason string, duration time.Duration) {
			if v == firewall.Block {
				m.BlockedQueriesTotal.Inc()
			}
			logGateDecision(connID, msg, v, reason, duration)
		},
		func(err error) { log.Printf("[conn %d] client->server protokol ayristirma durdu: %v", connID, err) },
	)

	// server -> client yonu hala salt gozlemci SniffReader ile izleniyor;
	// io.Copy'nin davranisi bu yonde degismedi.
	serverDec := protocol.NewServerDecoder(
		func(m protocol.Message) { logMessage(connID, m) },
		func(err error) { log.Printf("[conn %d] server->client protokol ayristirma durdu: %v", connID, err) },
	)

	serverReader := protocol.NewSniffReader(target, serverDec)

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
		target.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, serverReader)
		client.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
}

// logMessage, genel (politika kararina bagli olmayan) mesaj loglamasidir.
// Guvenlik: hicbir kosulda SQL sorgu metnini basmaz (bkz. logGateDecision,
// Query mesajlari icin tek yetkili log noktasidir).
func logMessage(connID uint64, m protocol.Message) {
	dir := "C->S"
	if m.Direction == protocol.Backend {
		dir = "S->C"
	}
	switch m.Name {
	case protocol.NameStartupMessage:
		log.Printf("[conn %d] %s StartupMessage protokol=%d.%d params=%v", connID, dir, m.ProtocolMajor, m.ProtocolMinor, m.StartupParams)
	case "DataRow", "CopyData":
		// yuksek hacimli mesajlar; log gurultusunu onlemek icin atlanir
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

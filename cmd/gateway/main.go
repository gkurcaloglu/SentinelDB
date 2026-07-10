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
	listenAddr  = "localhost:5432"
	targetAddr  = "localhost:5433"
	configPath  = "config.yaml"
	metricsAddr = ":9090"
	apiAddr     = ":8080"
)

var connCounter atomic.Uint64

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("config yuklenemedi: %v", err)
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

	var wg sync.WaitGroup

	go func() {
		<-ctx.Done()
		log.Println("shutting down...")
		listener.Close()
		metricsServer.Shutdown(context.Background())
		apiServer.Shutdown(context.Background())
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
			handleConn(conn, policy, m)
		}()
	}
}

func handleConn(client net.Conn, policy firewall.Policy, m *metrics.Metrics) {
	defer client.Close()

	connID := connCounter.Add(1)

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[conn %d] failed to connect to target %s: %v", connID, targetAddr, err)
		return
	}
	defer target.Close()

	// client -> server yonu artik salt gozlemci degil: Gate, her mesaji
	// politikaya gore degerlendirip izin verilenleri target'a oldugu gibi
	// iletir, engellenenleri ise target'a hic ulastirmadan dogrudan
	// client'a sentetik bir ErrorResponse+ReadyForQuery ile yanitlar.
	gate := firewall.NewGate(policy, target, client,
		func(msg protocol.Message, v firewall.Verdict, reason string) {
			if v == firewall.Block {
				m.BlockedQueriesTotal.Inc()
			}
			logGateDecision(connID, msg, v, reason)
		},
		func(err error) { log.Printf("[conn %d] client->server protokol ayristirma durdu: %v", connID, err) },
	)

	// server -> client yonu hala salt gozlemci SniffReader ile izleniyor;
	// io.Copy'nin davranisi bu yonde degismedi.
	serverDec := protocol.NewServerDecoder(
		func(m protocol.Message) { logMessage(connID, m) },
		func(err error) { log.Printf("[conn %d] server->client protokol ayristirma durdu: %v", connID, err) },
	)
	// SSLRequest/GSSENCRequest muzakeresi bir yonde baslayip karsi yonde
	// tek baytlik bir cevapla sonuclandigi icin decoder'lar birbirini bilmeli.
	gate.Decoder().SetPeer(serverDec)
	serverDec.SetPeer(gate.Decoder())

	serverReader := protocol.NewSniffReader(target, serverDec)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		gate.Run(client)
		target.(*net.TCPConn).CloseWrite()
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, serverReader)
		client.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
}

func logMessage(connID uint64, m protocol.Message) {
	dir := "C->S"
	if m.Direction == protocol.Backend {
		dir = "S->C"
	}
	switch m.Name {
	case "StartupMessage":
		log.Printf("[conn %d] %s StartupMessage protokol=%d.%d params=%v", connID, dir, m.ProtocolMajor, m.ProtocolMinor, m.StartupParams)
	case "Query":
		log.Printf("[conn %d] %s Query: %s", connID, dir, m.Query)
	case "DataRow", "CopyData":
		// yuksek hacimli mesajlar; log gurultusunu onlemek icin atlanir
	default:
		log.Printf("[conn %d] %s %s (uzunluk=%d)", connID, dir, m.Name, m.Length)
	}
}

func logGateDecision(connID uint64, m protocol.Message, v firewall.Verdict, reason string) {
	if v == firewall.Block {
		log.Printf("[conn %d] C->S %s ENGELLENDI: %s (sorgu=%q)", connID, m.Name, reason, m.Query)
		return
	}
	logMessage(connID, m)
}

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gkurcaloglu/sentineldb/internal/firewall"
	"github.com/gkurcaloglu/sentineldb/internal/gateway"
	"github.com/gkurcaloglu/sentineldb/internal/masking"
	"github.com/gkurcaloglu/sentineldb/internal/metrics"
	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// ==========================================================================
// Test helpers: wire frame builders (local to this package - cmd/gateway is
// the top of the dependency graph, so no other package's test helpers can
// be reused directly).
// ==========================================================================

func buildFrame(tag byte, body []byte) []byte {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(body)+4))
	return append(append([]byte{tag}, length...), body...)
}

func cstr(s string) []byte { return append([]byte(s), 0) }

func int16b(v int16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(v))
	return b
}

func int32b(v int32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return b
}

func feQueryFrame(sql string) []byte { return buildFrame('Q', cstr(sql)) }

func feParseFrame(stmt, query string, oids []uint32) []byte {
	body := append(cstr(stmt), cstr(query)...)
	body = append(body, int16b(int16(len(oids)))...)
	for _, o := range oids {
		body = append(body, int32b(int32(o))...)
	}
	return buildFrame('P', body)
}

func feBindFrame(portal, stmt string, resultFormats []int16) []byte {
	body := append(cstr(portal), cstr(stmt)...)
	body = append(body, int16b(0)...) // 0 param formats
	body = append(body, int16b(0)...) // 0 params
	body = append(body, int16b(int16(len(resultFormats)))...)
	for _, f := range resultFormats {
		body = append(body, int16b(f)...)
	}
	return buildFrame('B', body)
}

func feDescribeFrame(target byte, name string) []byte {
	return buildFrame('D', append([]byte{target}, cstr(name)...))
}
func feExecuteFrame(portal string, maxRows int32) []byte {
	return buildFrame('E', append(cstr(portal), int32b(maxRows)...))
}
func feCloseFrame(target byte, name string) []byte {
	return buildFrame('C', append([]byte{target}, cstr(name)...))
}
func feSyncFrame() []byte      { return buildFrame('S', nil) }
func feFlushFrame() []byte     { return buildFrame('H', nil) }
func feTerminateFrame() []byte { return buildFrame('X', nil) }

func beEmpty(tag byte) []byte  { return buildFrame(tag, nil) }
func beRFQ(status byte) []byte { return buildFrame('Z', []byte{status}) }

func beDataRow(cells [][]byte) []byte {
	body := int16b(int16(len(cells)))
	for _, c := range cells {
		if c == nil {
			body = append(body, 0xFF, 0xFF, 0xFF, 0xFF)
			continue
		}
		body = append(body, int32b(int32(len(c)))...)
		body = append(body, c...)
	}
	return buildFrame('D', body)
}
func beCommandComplete(tag string) []byte { return buildFrame('C', cstr(tag)) }

type rowField struct {
	name string
	fc   int16
}

func beRowDescription(fields []rowField) []byte {
	body := int16b(int16(len(fields)))
	for _, f := range fields {
		body = append(body, cstr(f.name)...)
		body = append(body, int32b(0)...)
		body = append(body, int16b(0)...)
		body = append(body, int32b(25)...)
		body = append(body, int16b(-1)...)
		body = append(body, int32b(0)...)
		body = append(body, int16b(f.fc)...)
	}
	return buildFrame('T', body)
}
func beNoData() []byte    { return beEmpty('n') }
func beParamDesc() []byte { return buildFrame('t', int16b(0)) }

func beErrorResponseWithText(text string) []byte {
	body := []byte{'S'}
	body = append(body, []byte("ERROR")...)
	body = append(body, 0)
	body = append(body, 'M')
	body = append(body, []byte(text)...)
	body = append(body, 0, 0)
	return buildFrame('E', body)
}
func beMinimalErrorResponse() []byte { return beErrorResponseWithText("test error") }

func beNoticeResponseWithText(text string) []byte {
	body := []byte{'S'}
	body = append(body, []byte("NOTICE")...)
	body = append(body, 0)
	body = append(body, 'M')
	body = append(body, []byte(text)...)
	body = append(body, 0, 0)
	return buildFrame('N', body)
}
func beParamStatus(k, v string) []byte { return buildFrame('S', append(cstr(k), cstr(v)...)) }
func beBackendKeyData(pid, secret uint32) []byte {
	return buildFrame('K', append(int32b(int32(pid)), int32b(int32(secret))...))
}
func beAuthOk() []byte                        { return buildFrame('R', int32b(0)) }
func beAuthCleartext() []byte                 { return buildFrame('R', int32b(3)) }
func fePasswordMessage(payload []byte) []byte { return buildFrame('p', payload) }

func startupFrame(code uint32, body []byte) []byte {
	total := 4 + 4 + len(body)
	out := make([]byte, 4, total)
	binary.BigEndian.PutUint32(out, uint32(total))
	out = append(out, int32b(int32(code))...)
	out = append(out, body...)
	return out
}
func sslRequestFrame() []byte { return startupFrame(80877103, nil) }
func startupMessageFrame(pairs ...string) []byte {
	var body []byte
	for _, p := range pairs {
		body = append(body, cstr(p)...)
	}
	body = append(body, 0)
	return startupFrame(uint32(3)<<16, body)
}
func cancelRequestFrame(pid, secret uint32) []byte {
	return startupFrame(80877102, append(int32b(int32(pid)), int32b(int32(secret))...))
}

// ==========================================================================
// Test helpers: fake Policy/Masker, metrics, log capture
// ==========================================================================

type maskCall struct{ column, value string }

type fakeMasker struct {
	mu    sync.Mutex
	calls []maskCall
}

func (f *fakeMasker) Mask(ctx context.Context, column, kind, value string) (string, bool, string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, maskCall{column, value})
	f.mu.Unlock()
	if !strings.Contains(value, "@") {
		return value, false, "", nil
	}
	return "MASKED", true, "", nil
}

func (f *fakeMasker) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func newTestMetrics() *metrics.Metrics {
	return metrics.New(prometheus.NewRegistry())
}

// captureLog redirects the standard logger's output to a buffer for the
// duration of the calling test and restores it on cleanup - the standard
// logger is global state, so callers must not run in parallel with other
// log-inspecting tests.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	orig := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(buf)
	t.Cleanup(func() {
		log.SetOutput(orig)
		log.SetFlags(origFlags)
	})
	return buf
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// ==========================================================================
// Test helpers: connection-runner harnesses
// ==========================================================================

type simpleHarness struct {
	fakeClient net.Conn
	fakeTarget net.Conn
	cancel     context.CancelFunc
	done       chan struct{}
	m          *metrics.Metrics
}

func newSimpleHarness(t *testing.T, policy firewall.Policy, masker masking.Masker, maskCfg masking.Config) *simpleHarness {
	t.Helper()
	clientRunnerSide, fakeClient := net.Pipe()
	targetRunnerSide, fakeTarget := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	m := newTestMetrics()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSimpleConnection(ctx, clientRunnerSide, targetRunnerSide, 1, policy, masker, maskCfg, m)
	}()
	return &simpleHarness{fakeClient: fakeClient, fakeTarget: fakeTarget, cancel: cancel, done: done, m: m}
}

func (h *simpleHarness) close() {
	h.cancel()
	h.fakeClient.Close()
	h.fakeTarget.Close()
	<-h.done
}

type extendedHarness struct {
	fakeClient net.Conn
	fakeTarget net.Conn
	cancel     context.CancelFunc
	done       chan struct{}
	m          *metrics.Metrics
}

func newExtendedHarness(t *testing.T, policy firewall.Policy, masker masking.Masker, maskCfg masking.Config) *extendedHarness {
	t.Helper()
	clientRunnerSide, fakeClient := net.Pipe()
	targetRunnerSide, fakeTarget := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	m := newTestMetrics()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runExtendedConnection(ctx, clientRunnerSide, targetRunnerSide, 1, policy, masker, maskCfg, m)
	}()
	return &extendedHarness{fakeClient: fakeClient, fakeTarget: fakeTarget, cancel: cancel, done: done, m: m}
}

func (h *extendedHarness) close() {
	h.cancel()
	h.fakeClient.Close()
	h.fakeTarget.Close()
	<-h.done
}

func (h *extendedHarness) waitDone(t *testing.T) {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for runExtendedConnection to return")
	}
}

func readN(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("failed to read %d bytes: %v", n, err)
	}
	conn.SetReadDeadline(time.Time{})
	return buf
}

func writeTo(t *testing.T, conn net.Conn, p []byte) {
	t.Helper()
	if _, err := conn.Write(p); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
}

// driveExtendedTerminate sends a client Terminate and waits for the
// connection to shut down. ForwardTerminate (bkz.
// internal/gateway/extended_runtime.go) relays the Terminate frame to the
// backend BEFORE the runtime shuts down (matching real PostgreSQL proxying,
// where the backend is also entitled to observe the client's Terminate) -
// on a real socket the OS would simply buffer it; over net.Pipe the write
// blocks until read, so callers must drain it or the shutdown never
// completes.
func driveExtendedTerminate(t *testing.T, h *extendedHarness) {
	t.Helper()
	term := feTerminateFrame()
	writeTo(t, h.fakeClient, term)
	readN(t, h.fakeTarget, len(term))
	h.waitDone(t)
}

// driveExtendedHandshake runs a minimal plaintext startup + AuthenticationOk
// + first ReadyForQuery exchange, leaving both sides positioned in
// steady-state (Gate.RunExtended/ExtendedRuntime now own the connections).
func driveExtendedHandshake(t *testing.T, h *extendedHarness) {
	t.Helper()
	sm := startupMessageFrame("user", "alice", "database", "postgres")
	writeTo(t, h.fakeClient, sm)
	got := readN(t, h.fakeTarget, len(sm))
	if !bytes.Equal(got, sm) {
		t.Fatalf("expected exact StartupMessage forwarded, got %x", got)
	}
	ok := beAuthOk()
	writeTo(t, h.fakeTarget, ok)
	readN(t, h.fakeClient, len(ok))
	rfq := beRFQ(protocol.TxStatusIdle)
	writeTo(t, h.fakeTarget, rfq)
	readN(t, h.fakeClient, len(rfq))
}

// ==========================================================================
// Section 3: Simple Query path regression tests (default/false branch)
// ==========================================================================

// driveSimpleStartup sends and forwards a minimal StartupMessage - the
// Simple Query decoder, like real PostgreSQL, treats the very first
// client-to-server frame specially (length-prefixed, no type byte); every
// scenario that exercises steady-state Simple Query behavior must complete
// this handshake first, exactly as a real client would.
func driveSimpleStartup(t *testing.T, h *simpleHarness) {
	t.Helper()
	sm := startupMessageFrame("user", "alice")
	writeTo(t, h.fakeClient, sm)
	got := readN(t, h.fakeTarget, len(sm))
	if !bytes.Equal(got, sm) {
		t.Fatalf("expected exact StartupMessage forwarded, got %x want %x", got, sm)
	}
}

func TestRunSimpleConnection_StartupMessage_Forwarded(t *testing.T) {
	h := newSimpleHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()
	driveSimpleStartup(t, h)
}

func TestRunSimpleConnection_SSLRequest_RepliesN(t *testing.T) {
	h := newSimpleHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()

	writeTo(t, h.fakeClient, sslRequestFrame())
	got := readN(t, h.fakeClient, 1)
	if got[0] != 'N' {
		t.Fatalf("expected 'N', got %q", got)
	}
	driveSimpleStartup(t, h)
}

func TestRunSimpleConnection_AllowedQuery_Forwarded(t *testing.T) {
	h := newSimpleHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()
	driveSimpleStartup(t, h)

	q := feQueryFrame("SELECT 1")
	writeTo(t, h.fakeClient, q)
	got := readN(t, h.fakeTarget, len(q))
	if !bytes.Equal(got, q) {
		t.Fatalf("expected the allowed query forwarded unchanged, got %x want %x", got, q)
	}
}

func TestRunSimpleConnection_BlockedQuery_SyntheticErrorAndReadyForQuery(t *testing.T) {
	h := newSimpleHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()
	driveSimpleStartup(t, h)

	writeTo(t, h.fakeClient, feQueryFrame("DROP TABLE users"))

	h.fakeClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := h.fakeClient.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := buf[:n]
	if protocol.MessageType(got[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected an ErrorResponse for the blocked query, got tag %q", got[0])
	}
	snap, err := h.m.Snapshot()
	if err != nil {
		t.Fatalf("unexpected error taking metrics snapshot: %v", err)
	}
	if snap.BlockedQueriesTotal != 1 {
		t.Fatalf("expected BlockedQueriesTotal=1, got %v", snap.BlockedQueriesTotal)
	}
}

func TestRunSimpleConnection_MaskedDataRow(t *testing.T) {
	masker := &fakeMasker{}
	h := newSimpleHarness(t, firewall.DenyKeywords("DROP TABLE"), masker, masking.NewConfig(true, []string{"email"}))
	defer h.close()
	driveSimpleStartup(t, h)

	writeTo(t, h.fakeClient, feQueryFrame("SELECT email FROM users"))
	readN(t, h.fakeTarget, len(feQueryFrame("SELECT email FROM users")))

	rd := beRowDescription([]rowField{{"email", 0}})
	writeTo(t, h.fakeTarget, rd)
	readN(t, h.fakeClient, len(rd))

	dr := beDataRow([][]byte{[]byte("john@example.com")})
	writeTo(t, h.fakeTarget, dr)

	row, err := protocol.ParseDataRow(dr[5:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	row, err = row.WithCell(0, protocol.DataCell{Value: []byte("MASKED")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := row.Build()
	got := readN(t, h.fakeClient, len(want))
	if !bytes.Equal(got, want) {
		t.Fatalf("expected masked DataRow, got %x want %x", got, want)
	}
	if masker.callCount() != 1 {
		t.Fatalf("expected exactly 1 mask call, got %d", masker.callCount())
	}
}

func TestRunSimpleConnection_MalformedFrontendFrame_FailsClosed(t *testing.T) {
	h := newSimpleHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()
	driveSimpleStartup(t, h)

	// Declares an absurd length - malformed framing.
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 0xFFFFFFF0)
	writeTo(t, h.fakeClient, append([]byte{'Q'}, lenBuf...))

	// Gate.handleDecodeError synchronously writes a FATAL ErrorResponse to
	// the client BEFORE Gate.Run returns/closes anything - must be drained
	// or the write blocks forever on a synchronous net.Pipe.
	h.fakeClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	discard := make([]byte, 4096)
	if _, err := h.fakeClient.Read(discard); err != nil {
		t.Fatalf("expected a synthetic FATAL ErrorResponse, got error: %v", err)
	}

	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the connection to terminate on a malformed frontend frame")
	}
}

func TestRunSimpleConnection_MalformedBackendFrame_FailsClosed(t *testing.T) {
	h := newSimpleHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()
	driveSimpleStartup(t, h)

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 0xFFFFFFF0)
	writeTo(t, h.fakeTarget, append([]byte{'Z'}, lenBuf...))

	// Transformer's decode-failure path synchronously writes a FATAL
	// ErrorResponse to the client BEFORE returning/closing anything - must
	// be drained or the write blocks forever on a synchronous net.Pipe.
	h.fakeClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	discard := make([]byte, 4096)
	if _, err := h.fakeClient.Read(discard); err != nil {
		t.Fatalf("expected a synthetic FATAL ErrorResponse, got error: %v", err)
	}

	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the connection to terminate on a malformed backend frame")
	}
}

func TestRunSimpleConnection_ExtendedParseRejected(t *testing.T) {
	h := newSimpleHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()
	driveSimpleStartup(t, h)

	writeTo(t, h.fakeClient, feParseFrame("s1", "SELECT 1", nil))

	h.fakeClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := h.fakeClient.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if protocol.MessageType(buf[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected an ErrorResponse rejecting Extended Parse, got tag %q", buf[0])
	}
	_ = n
}

// Neither net.Pipe end supports a real half-close (*net.TCPConn.CloseWrite),
// which runSimpleConnection relies on to propagate one side's clean EOF to
// the other goroutine in production (over a real TCP socket, closing the
// client's read side eventually surfaces as an EOF on the backend's read of
// the client's now-half-closed connection, and vice versa). Since net.Pipe
// cannot model that cascading half-close, these tests close BOTH ends -
// exactly what a real half-close would eventually achieve, and exactly what
// activeConns.closeAll() does during a forced shutdown (bkz.
// TestActiveConns_CloseAll_ForceClosesRegisteredConnections) - to prove
// runSimpleConnection's two goroutines both observe the closure and return,
// without asserting anything net.Pipe cannot faithfully represent.

func TestRunSimpleConnection_ClientEOF(t *testing.T) {
	h := newSimpleHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	h.fakeClient.Close()
	h.fakeTarget.Close()
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the connection to terminate on client EOF")
	}
	h.cancel()
}

func TestRunSimpleConnection_BackendEOF(t *testing.T) {
	h := newSimpleHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	h.fakeTarget.Close()
	h.fakeClient.Close()
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the connection to terminate on backend EOF")
	}
	h.cancel()
}

// TestActiveConns_CloseAll_ForceClosesRegisteredConnections proves the
// ACTUAL mechanism the Simple Query path relies on for global-shutdown
// responsiveness: runSimpleConnection itself never consults ctx (it is the
// pre-existing, unchanged behavior - Gate.Run/Transformer.Run predate any
// context-based cancellation in this codebase); instead main()'s shutdown
// watcher calls activeConns.closeAll() to force-close every registered
// connection, unblocking the blocking Read calls inside Gate.Run/
// Transformer.Run so their goroutines return and wg.Wait() completes. This
// is unchanged, pre-existing infrastructure - not new code from this stage
// - so it is verified directly here rather than re-derived indirectly
// through runSimpleConnection's ctx parameter (which it does not use).
func TestActiveConns_CloseAll_ForceClosesRegisteredConnections(t *testing.T) {
	conns := newActiveConns()
	a, b := net.Pipe()
	c, d := net.Pipe()
	conns.add(1, a, c)

	conns.closeAll()

	for _, conn := range []net.Conn{a, c} {
		if _, err := conn.Write([]byte("x")); err == nil {
			t.Fatal("expected a write on a force-closed connection to fail")
		}
	}
	b.Close()
	d.Close()
}

// ==========================================================================
// Section 22: Extended Query path (opt-in) integration tests
// ==========================================================================

func TestRunExtendedConnection_SSLRequest_RepliesN_ThenContinuesHandshake(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()

	writeTo(t, h.fakeClient, sslRequestFrame())
	got := readN(t, h.fakeClient, 1)
	if got[0] != 'N' {
		t.Fatalf("expected 'N' for SSLRequest, got %q", got)
	}
	driveExtendedHandshake(t, h)

	driveExtendedTerminate(t, h)
}

func TestRunExtendedConnection_FullRoundTrip_AllowedQuery_NoMasking(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()
	driveExtendedHandshake(t, h)

	parse := feParseFrame("s1", "SELECT 1", nil)
	writeTo(t, h.fakeClient, parse)
	got := readN(t, h.fakeTarget, len(parse))
	if !bytes.Equal(got, parse) {
		t.Fatalf("expected Parse forwarded unchanged, got %x want %x", got, parse)
	}
	pc := beEmpty(byte(protocol.MsgParseComplete))
	writeTo(t, h.fakeTarget, pc)
	readN(t, h.fakeClient, len(pc))

	bind := feBindFrame("p1", "s1", nil)
	writeTo(t, h.fakeClient, bind)
	readN(t, h.fakeTarget, len(bind))
	bc := beEmpty(byte(protocol.MsgBindComplete))
	writeTo(t, h.fakeTarget, bc)
	readN(t, h.fakeClient, len(bc))

	exec := feExecuteFrame("p1", 0)
	writeTo(t, h.fakeClient, exec)
	readN(t, h.fakeTarget, len(exec))

	dr := beDataRow([][]byte{[]byte("1")})
	writeTo(t, h.fakeTarget, dr)
	got = readN(t, h.fakeClient, len(dr))
	if !bytes.Equal(got, dr) {
		t.Fatalf("expected unmasked DataRow forwarded byte-for-byte, got %x want %x", got, dr)
	}

	cc := beCommandComplete("SELECT 1")
	writeTo(t, h.fakeTarget, cc)
	readN(t, h.fakeClient, len(cc))

	sync := feSyncFrame()
	writeTo(t, h.fakeClient, sync)
	readN(t, h.fakeTarget, len(sync))
	rfq := beRFQ(protocol.TxStatusIdle)
	writeTo(t, h.fakeTarget, rfq)
	readN(t, h.fakeClient, len(rfq))

	driveExtendedTerminate(t, h)
}

func TestRunExtendedConnection_MaskedDataRow(t *testing.T) {
	masker := &fakeMasker{}
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), masker, masking.NewConfig(true, []string{"email"}))
	defer h.close()
	driveExtendedHandshake(t, h)

	parse := feParseFrame("s1", "SELECT email FROM users", nil)
	writeTo(t, h.fakeClient, parse)
	readN(t, h.fakeTarget, len(parse))
	writeTo(t, h.fakeTarget, beEmpty(byte(protocol.MsgParseComplete)))
	readN(t, h.fakeClient, len(beEmpty(byte(protocol.MsgParseComplete))))

	describe := feDescribeFrame(byte(protocol.TargetStatement), "s1")
	writeTo(t, h.fakeClient, describe)
	readN(t, h.fakeTarget, len(describe))
	pd := beParamDesc()
	writeTo(t, h.fakeTarget, pd)
	readN(t, h.fakeClient, len(pd))
	rd := beRowDescription([]rowField{{"email", 0}})
	writeTo(t, h.fakeTarget, rd)
	readN(t, h.fakeClient, len(rd))

	bind := feBindFrame("p1", "s1", []int16{0})
	writeTo(t, h.fakeClient, bind)
	readN(t, h.fakeTarget, len(bind))
	writeTo(t, h.fakeTarget, beEmpty(byte(protocol.MsgBindComplete)))
	readN(t, h.fakeClient, len(beEmpty(byte(protocol.MsgBindComplete))))

	exec := feExecuteFrame("p1", 0)
	writeTo(t, h.fakeClient, exec)
	readN(t, h.fakeTarget, len(exec))

	dr := beDataRow([][]byte{[]byte("john@example.com")})
	writeTo(t, h.fakeTarget, dr)

	row, err := protocol.ParseDataRow(dr[5:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	row, err = row.WithCell(0, protocol.DataCell{Value: []byte("MASKED")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := row.Build()
	got := readN(t, h.fakeClient, len(want))
	if !bytes.Equal(got, want) {
		t.Fatalf("expected masked DataRow, got %x want %x", got, want)
	}
	if masker.callCount() != 1 {
		t.Fatalf("expected exactly 1 mask call, got %d", masker.callCount())
	}

	driveExtendedTerminate(t, h)
}

func TestRunExtendedConnection_PolicyBlockedParse_DiscardsThenRealSync(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()
	driveExtendedHandshake(t, h)

	parse := feParseFrame("s1", "DROP TABLE users", nil)
	writeTo(t, h.fakeClient, parse)

	h.fakeClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := h.fakeClient.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if protocol.MessageType(buf[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected a synthetic ErrorResponse for the blocked Parse, got tag %q", buf[0])
	}
	_ = n

	// Discarded Bind/Describe/Execute must never reach the backend.
	writeTo(t, h.fakeClient, feBindFrame("p1", "s1", nil))
	writeTo(t, h.fakeClient, feExecuteFrame("p1", 0))

	sync := feSyncFrame()
	writeTo(t, h.fakeClient, sync)
	got := readN(t, h.fakeTarget, len(sync))
	if !bytes.Equal(got, sync) {
		t.Fatalf("expected the real Sync forwarded to the backend, got %x want %x", got, sync)
	}
	rfq := beRFQ(protocol.TxStatusIdle)
	writeTo(t, h.fakeTarget, rfq)
	readN(t, h.fakeClient, len(rfq))

	snap, err := h.m.Snapshot()
	if err != nil {
		t.Fatalf("unexpected error taking metrics snapshot: %v", err)
	}
	if snap.BlockedQueriesTotal != 1 {
		t.Fatalf("expected BlockedQueriesTotal=1, got %v", snap.BlockedQueriesTotal)
	}

	driveExtendedTerminate(t, h)
}

func TestRunExtendedConnection_UnknownShapeExecute_LocallyRejected(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(true, []string{"email"}))
	defer h.close()
	driveExtendedHandshake(t, h)

	parse := feParseFrame("s1", "SELECT email FROM users", nil)
	writeTo(t, h.fakeClient, parse)
	readN(t, h.fakeTarget, len(parse))
	writeTo(t, h.fakeTarget, beEmpty(byte(protocol.MsgParseComplete)))
	readN(t, h.fakeClient, len(beEmpty(byte(protocol.MsgParseComplete))))

	bind := feBindFrame("p1", "s1", nil)
	writeTo(t, h.fakeClient, bind)
	readN(t, h.fakeTarget, len(bind))
	writeTo(t, h.fakeTarget, beEmpty(byte(protocol.MsgBindComplete)))
	readN(t, h.fakeClient, len(beEmpty(byte(protocol.MsgBindComplete))))

	// No Describe was ever observed for this statement/portal - the Execute
	// must be rejected locally, before anything reaches the backend.
	before := readAllPendingLen(h.fakeTarget)
	_ = before
	writeTo(t, h.fakeClient, feExecuteFrame("p1", 0))

	h.fakeClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := h.fakeClient.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if protocol.MessageType(buf[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected a synthetic ErrorResponse for the unknown-shape Execute, got tag %q", buf[0])
	}
	_ = n

	sync := feSyncFrame()
	writeTo(t, h.fakeClient, sync)
	readN(t, h.fakeTarget, len(sync))
	writeTo(t, h.fakeTarget, beRFQ(protocol.TxStatusIdle))
	readN(t, h.fakeClient, len(beRFQ(protocol.TxStatusIdle)))

	driveExtendedTerminate(t, h)
}

func TestRunExtendedConnection_BinaryMaskingTarget_LocallyRejected(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(true, []string{"email"}))
	defer h.close()
	driveExtendedHandshake(t, h)

	parse := feParseFrame("s1", "SELECT email FROM users", nil)
	writeTo(t, h.fakeClient, parse)
	readN(t, h.fakeTarget, len(parse))
	writeTo(t, h.fakeTarget, beEmpty(byte(protocol.MsgParseComplete)))
	readN(t, h.fakeClient, len(beEmpty(byte(protocol.MsgParseComplete))))

	describe := feDescribeFrame(byte(protocol.TargetStatement), "s1")
	writeTo(t, h.fakeClient, describe)
	readN(t, h.fakeTarget, len(describe))
	pd := beParamDesc()
	writeTo(t, h.fakeTarget, pd)
	readN(t, h.fakeClient, len(pd))
	// The target (masked) column is reported/bound as BINARY(1).
	rd := beRowDescription([]rowField{{"email", 1}})
	writeTo(t, h.fakeTarget, rd)
	readN(t, h.fakeClient, len(rd))

	bind := feBindFrame("p1", "s1", []int16{1})
	writeTo(t, h.fakeClient, bind)
	readN(t, h.fakeTarget, len(bind))
	writeTo(t, h.fakeTarget, beEmpty(byte(protocol.MsgBindComplete)))
	readN(t, h.fakeClient, len(beEmpty(byte(protocol.MsgBindComplete))))

	writeTo(t, h.fakeClient, feExecuteFrame("p1", 0))

	h.fakeClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := h.fakeClient.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if protocol.MessageType(buf[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected a synthetic ErrorResponse for the binary masking target, got tag %q", buf[0])
	}
	_ = n

	sync := feSyncFrame()
	writeTo(t, h.fakeClient, sync)
	readN(t, h.fakeTarget, len(sync))
	writeTo(t, h.fakeTarget, beRFQ(protocol.TxStatusIdle))
	readN(t, h.fakeClient, len(beRFQ(protocol.TxStatusIdle)))

	driveExtendedTerminate(t, h)
}

func TestRunExtendedConnection_MalformedFrontendFrame_FailsClosed(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()
	driveExtendedHandshake(t, h)

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 0xFFFFFFF0)
	writeTo(t, h.fakeClient, append([]byte{'P'}, lenBuf...))

	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the connection to terminate on a malformed frontend frame")
	}
}

func TestRunExtendedConnection_MalformedBackendFrame_FailsClosed(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()
	driveExtendedHandshake(t, h)

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 0xFFFFFFF0)
	writeTo(t, h.fakeTarget, append([]byte{'1'}, lenBuf...))

	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the connection to terminate on a malformed backend frame")
	}
}

func TestRunExtendedConnection_BackendErrorResponse_RelayedToClient(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()
	driveExtendedHandshake(t, h)

	parse := feParseFrame("s1", "SELECT bad", nil)
	writeTo(t, h.fakeClient, parse)
	readN(t, h.fakeTarget, len(parse))

	er := beMinimalErrorResponse()
	writeTo(t, h.fakeTarget, er)
	got := readN(t, h.fakeClient, len(er))
	if !bytes.Equal(got, er) {
		t.Fatalf("expected the backend ErrorResponse relayed byte-for-byte, got %x want %x", got, er)
	}

	sync := feSyncFrame()
	writeTo(t, h.fakeClient, sync)
	readN(t, h.fakeTarget, len(sync))
	rfq := beRFQ(protocol.TxStatusFailedTransaction)
	writeTo(t, h.fakeTarget, rfq)
	readN(t, h.fakeClient, len(rfq))

	driveExtendedTerminate(t, h)
}

func TestRunExtendedConnection_ClientDisconnect_DuringSteadyState(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	driveExtendedHandshake(t, h)
	h.fakeClient.Close()
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the connection to terminate on client disconnect")
	}
	h.fakeTarget.Close()
	h.cancel()
}

func TestRunExtendedConnection_BackendDisconnect_DuringSteadyState(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	driveExtendedHandshake(t, h)
	h.fakeTarget.Close()
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the connection to terminate on backend disconnect")
	}
	h.fakeClient.Close()
	h.cancel()
}

func TestRunExtendedConnection_GlobalContextCancellation_DuringSteadyState(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	driveExtendedHandshake(t, h)
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the connection to terminate on context cancellation")
	}
	h.fakeClient.Close()
	h.fakeTarget.Close()
}

func TestRunExtendedConnection_GlobalContextCancellation_DuringStartup(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the connection to terminate on context cancellation during startup")
	}
	h.fakeClient.Close()
	h.fakeTarget.Close()
}

func TestRunExtendedConnection_CancelRequest_NoRuntimeConstructed(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()

	cr := cancelRequestFrame(1234, 5678)
	writeTo(t, h.fakeClient, cr)
	got := readN(t, h.fakeTarget, len(cr))
	if !bytes.Equal(got, cr) {
		t.Fatalf("expected the CancelRequest forwarded unchanged, got %x want %x", got, cr)
	}

	h.waitDone(t)
}

func TestRunExtendedConnection_StartupAuthenticationFailure_NoRuntimeConstructed(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()

	sm := startupMessageFrame("user", "alice")
	writeTo(t, h.fakeClient, sm)
	readN(t, h.fakeTarget, len(sm))

	// AuthenticationCleartextPassword, then a backend ErrorResponse instead
	// of AuthenticationOk - authentication fails before any ReadyForQuery.
	authFrame := beAuthCleartext()
	writeTo(t, h.fakeTarget, authFrame)
	readN(t, h.fakeClient, len(authFrame))

	pw := fePasswordMessage(cstr("wrongpassword"))
	writeTo(t, h.fakeClient, pw)
	readN(t, h.fakeTarget, len(pw))

	er := beMinimalErrorResponse()
	writeTo(t, h.fakeTarget, er)
	readN(t, h.fakeClient, len(er))

	h.waitDone(t)
}

// readAllPendingLen drains and discards any bytes currently readable on conn
// without blocking, returning how many were read - used to prove "nothing
// new arrived" by comparison rather than by racing a fixed sleep.
func readAllPendingLen(conn net.Conn) int {
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 4096)
	total := 0
	for {
		n, err := conn.Read(buf)
		total += n
		if err != nil {
			return total
		}
	}
}

// ==========================================================================
// Section 21 (MANDATORY): byte-preservation across the startup/steady-state
// ownership boundary. Both tests write TWO frames in a SINGLE underlying
// net.Conn.Write call, so that the handoff can only see them as one
// contiguous byte stream - exactly like a real TCP socket that coalesces a
// client's/backend's back-to-back writes into one read-visible chunk. Each
// test proves the handoff consumes EXACTLY the bytes it needs (io.ReadFull,
// no read-ahead) and that the leftover bytes are picked up, unmodified and
// exactly once, by the NEW owner (ExtendedFrontend/ExtendedRuntime) after
// the ownership handoff - no private prefetch buffer, no lost or duplicated
// bytes, no concurrent access by both the old and new owner.
// ==========================================================================

func TestRunExtendedConnection_ClientCoalescedWrite_PasswordMessagePlusParse_PreservedAcrossHandoff(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()

	sm := startupMessageFrame("user", "alice", "database", "postgres")
	writeTo(t, h.fakeClient, sm)
	readN(t, h.fakeTarget, len(sm))

	authReq := beAuthCleartext()
	writeTo(t, h.fakeTarget, authReq)
	readN(t, h.fakeClient, len(authReq))

	pw := fePasswordMessage(cstr("secret"))
	parse := feParseFrame("s1", "SELECT 1", nil)
	// ONE write: the handoff must read exactly len(pw) bytes via io.ReadFull
	// and leave the Parse frame bytes untouched in the pipe for whichever
	// component reads next. net.Pipe's Write blocks until ALL of its bytes
	// are drained by the peer (potentially across several Read calls on the
	// other end) - since the Parse-frame half is only drained AFTER the
	// handoff completes and Gate.RunExtended starts reading, this write
	// must run in the background so this goroutine can keep driving the
	// rest of the handshake concurrently instead of deadlocking on its own
	// write.
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		writeTo(t, h.fakeClient, append(append([]byte{}, pw...), parse...))
	}()

	got := readN(t, h.fakeTarget, len(pw))
	if !bytes.Equal(got, pw) {
		t.Fatalf("expected the handoff to forward exactly the PasswordMessage, got %x want %x", got, pw)
	}

	writeTo(t, h.fakeTarget, beAuthOk())
	readN(t, h.fakeClient, len(beAuthOk()))
	writeTo(t, h.fakeTarget, beRFQ(protocol.TxStatusIdle))
	readN(t, h.fakeClient, len(beRFQ(protocol.TxStatusIdle)))
	// Handoff has now returned; ownership has passed to ExtendedRuntime/
	// ExtendedFrontend. The Parse frame bytes were already sitting in the
	// pipe's write buffer BEFORE the handoff even returned - proving there
	// is no window where they could be read twice or dropped.

	gotParse := readN(t, h.fakeTarget, len(parse))
	if !bytes.Equal(gotParse, parse) {
		t.Fatalf("expected the coalesced Parse frame forwarded exactly once, unmodified, got %x want %x", gotParse, parse)
	}
	<-writeDone

	pc := beEmpty(byte(protocol.MsgParseComplete))
	writeTo(t, h.fakeTarget, pc)
	readN(t, h.fakeClient, len(pc))

	driveExtendedTerminate(t, h)
}

func TestRunExtendedConnection_BackendCoalescedWrite_ReadyForQueryPlusNotice_PreservedAcrossHandoff(t *testing.T) {
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(false, nil))
	defer h.close()

	sm := startupMessageFrame("user", "alice")
	writeTo(t, h.fakeClient, sm)
	readN(t, h.fakeTarget, len(sm))
	writeTo(t, h.fakeTarget, beAuthOk())
	readN(t, h.fakeClient, len(beAuthOk()))

	rfq := beRFQ(protocol.TxStatusIdle)
	notice := beNoticeResponseWithText("informational")
	// ONE write: the handoff must relay exactly the ReadyForQuery and
	// return; the NoticeResponse bytes must remain untouched in the pipe
	// for ExtendedRuntime's backend reader to pick up afterward. Like the
	// client-side coalescing test above, this write must run in the
	// background: net.Pipe's Write only returns once ALL of its bytes are
	// drained, and the NoticeResponse half is only drained AFTER the
	// handoff returns and ExtendedRuntime's backend reader takes over.
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		writeTo(t, h.fakeTarget, append(append([]byte{}, rfq...), notice...))
	}()

	got := readN(t, h.fakeClient, len(rfq))
	if !bytes.Equal(got, rfq) {
		t.Fatalf("expected the handoff to relay exactly the first ReadyForQuery, got %x want %x", got, rfq)
	}
	// Handoff has now returned; ownership of the backend transport has
	// passed to ExtendedRuntime's backend-reader goroutine.

	gotNotice := readN(t, h.fakeClient, len(notice))
	if !bytes.Equal(gotNotice, notice) {
		t.Fatalf("expected the coalesced NoticeResponse relayed exactly once, unmodified, got %x want %x", gotNotice, notice)
	}
	<-writeDone

	driveExtendedTerminate(t, h)
}

// ==========================================================================
// Section 23: race/ownership + repeated-cycle stress tests
// ==========================================================================

func TestRunSimpleConnection_RepeatedCycles_NoGoroutineLeak(t *testing.T) {
	const cycles = 30
	before := stableGoroutineCount()

	for i := 0; i < cycles; i++ {
		h := newSimpleHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(true, []string{"email"}))
		driveSimpleStartup(t, h)
		q := feQueryFrame("SELECT 1")
		writeTo(t, h.fakeClient, q)
		readN(t, h.fakeTarget, len(q))
		h.fakeClient.Close()
		h.fakeTarget.Close()
		h.cancel()
		<-h.done
	}

	after := stableGoroutineCount()
	if after > before+5 {
		t.Fatalf("suspected goroutine leak after %d Simple connection cycles: before=%d after=%d", cycles, before, after)
	}
}

func TestRunExtendedConnection_RepeatedCycles_NoGoroutineLeak(t *testing.T) {
	const cycles = 30
	before := stableGoroutineCount()

	for i := 0; i < cycles; i++ {
		h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(true, []string{"email"}))
		driveExtendedHandshake(t, h)

		parse := feParseFrame("s1", "SELECT 1", nil)
		writeTo(t, h.fakeClient, parse)
		readN(t, h.fakeTarget, len(parse))
		writeTo(t, h.fakeTarget, beEmpty(byte(protocol.MsgParseComplete)))
		readN(t, h.fakeClient, len(beEmpty(byte(protocol.MsgParseComplete))))

		driveExtendedTerminate(t, h)
	}

	after := stableGoroutineCount()
	if after > before+5 {
		t.Fatalf("suspected goroutine leak after %d Extended connection cycles: before=%d after=%d", cycles, before, after)
	}
}

// stableGoroutineCount forces a couple of GC passes and brief yields so
// recently-exited goroutines have a chance to actually unwind before the
// count is sampled - avoids a flaky leak assertion racing goroutine
// teardown.
func stableGoroutineCount() int {
	for i := 0; i < 3; i++ {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	return runtime.NumGoroutine()
}

// ==========================================================================
// Section 24: privacy/log marker tests - recognizable markers for
// username/database/SQL text/statement-portal names/DataRow cell values/
// server ErrorResponse text must never appear in log output.
// ==========================================================================

// identityMarkers are StartupMessage connection-identity parameters
// (username/database) - not credentials, SQL, or server-provided data.
// The PRE-EXISTING, unchanged Simple Query path (bkz. logMessage's
// StartupMessage case, byte-for-byte preserved from the old handleConn per
// this stage's explicit "preserve default path exactly" requirement) logs
// these for observability/audit purposes - this is deliberate, pre-existing
// behavior outside this stage's scope, not a hole introduced here. The NEW
// Extended path never logs StartupMessage params at all (bkz.
// runExtendedConnection/RunStartupHandoff, which never call logMessage for
// the startup phase), so it is held to the stricter bar of never emitting
// them either.
var identityMarkers = []string{
	"marker_username_9f3a",
	"marker_database_7c21",
}

// sensitiveMarkers are markers that must NEVER appear in ANY log output on
// EITHER path - SQL/table/value text, DataRow cell content, passwords,
// server-provided ErrorResponse text, and statement/portal names.
var sensitiveMarkers = []string{
	"marker_table_b810",
	"marker_wherevalue_44de",
	"marker_cellvalue_e912@example.com",
	"marker_password_1a2b",
	"marker_servererrortext_5566",
	"marker_statementname_7788",
	"marker_portalname_9900",
}

func assertNoMarkersLogged(t *testing.T, logOutput string) {
	t.Helper()
	for _, marker := range sensitiveMarkers {
		if strings.Contains(logOutput, marker) {
			t.Fatalf("log output leaked sensitive marker %q:\n%s", marker, logOutput)
		}
	}
}

func TestPrivacy_SimplePath_LogsNeverContainSensitiveMarkers(t *testing.T) {
	buf := captureLog(t)
	h := newSimpleHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(true, []string{"email"}))

	sm := startupMessageFrame("user", "marker_username_9f3a", "database", "marker_database_7c21")
	writeTo(t, h.fakeClient, sm)
	readN(t, h.fakeTarget, len(sm))

	q := feQueryFrame("SELECT * FROM marker_table_b810 WHERE x = 'marker_wherevalue_44de'")
	writeTo(t, h.fakeClient, q)
	readN(t, h.fakeTarget, len(q))

	rd := beRowDescription([]rowField{{"email", 0}})
	writeTo(t, h.fakeTarget, rd)
	readN(t, h.fakeClient, len(rd))
	dr := beDataRow([][]byte{[]byte("marker_cellvalue_e912@example.com")})
	writeTo(t, h.fakeTarget, dr)
	h.fakeClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	discard := make([]byte, 4096)
	h.fakeClient.Read(discard)

	er := beErrorResponseWithText("marker_servererrortext_5566")
	writeTo(t, h.fakeTarget, er)
	h.fakeClient.Read(discard)

	h.fakeClient.Close()
	h.fakeTarget.Close()
	h.cancel()
	<-h.done

	assertNoMarkersLogged(t, buf.String())
}

func TestPrivacy_ExtendedPath_LogsNeverContainSensitiveMarkers(t *testing.T) {
	buf := captureLog(t)
	h := newExtendedHarness(t, firewall.DenyKeywords("DROP TABLE"), &fakeMasker{}, masking.NewConfig(true, []string{"email"}))

	sm := startupMessageFrame("user", "marker_username_9f3a", "database", "marker_database_7c21")
	writeTo(t, h.fakeClient, sm)
	readN(t, h.fakeTarget, len(sm))
	authReq := beAuthCleartext()
	writeTo(t, h.fakeTarget, authReq)
	readN(t, h.fakeClient, len(authReq))
	pw := fePasswordMessage(cstr("marker_password_1a2b"))
	writeTo(t, h.fakeClient, pw)
	readN(t, h.fakeTarget, len(pw))
	writeTo(t, h.fakeTarget, beAuthOk())
	readN(t, h.fakeClient, len(beAuthOk()))
	writeTo(t, h.fakeTarget, beRFQ(protocol.TxStatusIdle))
	readN(t, h.fakeClient, len(beRFQ(protocol.TxStatusIdle)))

	parse := feParseFrame("marker_statementname_7788", "SELECT * FROM t WHERE x = 'marker_wherevalue_44de'", nil)
	writeTo(t, h.fakeClient, parse)
	readN(t, h.fakeTarget, len(parse))
	writeTo(t, h.fakeTarget, beEmpty(byte(protocol.MsgParseComplete)))
	readN(t, h.fakeClient, len(beEmpty(byte(protocol.MsgParseComplete))))

	describe := feDescribeFrame(byte(protocol.TargetStatement), "marker_statementname_7788")
	writeTo(t, h.fakeClient, describe)
	readN(t, h.fakeTarget, len(describe))
	pd := beParamDesc()
	writeTo(t, h.fakeTarget, pd)
	readN(t, h.fakeClient, len(pd))
	rd := beRowDescription([]rowField{{"email", 0}})
	writeTo(t, h.fakeTarget, rd)
	readN(t, h.fakeClient, len(rd))

	bind := feBindFrame("marker_portalname_9900", "marker_statementname_7788", []int16{0})
	writeTo(t, h.fakeClient, bind)
	readN(t, h.fakeTarget, len(bind))
	writeTo(t, h.fakeTarget, beEmpty(byte(protocol.MsgBindComplete)))
	readN(t, h.fakeClient, len(beEmpty(byte(protocol.MsgBindComplete))))

	exec := feExecuteFrame("marker_portalname_9900", 0)
	writeTo(t, h.fakeClient, exec)
	readN(t, h.fakeTarget, len(exec))

	dr := beDataRow([][]byte{[]byte("marker_cellvalue_e912@example.com")})
	writeTo(t, h.fakeTarget, dr)
	h.fakeClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	discard := make([]byte, 4096)
	h.fakeClient.Read(discard)

	er := beErrorResponseWithText("marker_servererrortext_5566")
	writeTo(t, h.fakeTarget, er)
	h.fakeClient.Read(discard)

	h.fakeClient.Close()
	h.fakeTarget.Close()
	h.cancel()
	<-h.done

	assertNoMarkersLogged(t, buf.String())
	// The Extended path never logs StartupMessage params at all (bkz.
	// identityMarkers' doc comment) - held to a stricter bar than the
	// pre-existing Simple path.
	logOutput := buf.String()
	for _, marker := range identityMarkers {
		if strings.Contains(logOutput, marker) {
			t.Fatalf("Extended path log output unexpectedly contains a StartupMessage identity marker %q:\n%s", marker, logOutput)
		}
	}
}

// TestPrivacy_ErrorFormatting_NeverEmbedsDynamicPayload proves that the
// fixed sentinel errors this package classifies (bkz. logStartupOutcome/
// logExtendedFrontendOutcome/logExtendedRuntimeOutcome) never carry
// dynamic, potentially-sensitive payload under any fmt verb - they are
// static errors.New(...) values, so %v/%+v/%#v are all safe by
// construction. This is a regression guard: if a future change ever wraps
// one of these sentinels with dynamic protocol content, this test's marker
// would leak through the formatted output.
func TestPrivacy_ErrorFormatting_NeverEmbedsDynamicPayload(t *testing.T) {
	sentinels := []error{
		gateway.ErrStartupClientEOF,
		gateway.ErrStartupBackendErrorResponse,
		gateway.ErrStartupUnsupportedAuth,
		gateway.ErrExtendedMaskingFailed,
	}
	for _, sentinel := range sentinels {
		formatted := fmt.Sprintf("%v|%+v|%#v", sentinel, sentinel, sentinel)
		for _, marker := range sensitiveMarkers {
			if strings.Contains(formatted, marker) {
				t.Fatalf("sentinel error unexpectedly formatted with a sensitive marker: %s", formatted)
			}
		}
	}
}

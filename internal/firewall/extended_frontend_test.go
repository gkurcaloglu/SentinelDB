package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/gateway"
	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// --- Test helpers: wire frame builders --------------------------------

func buildFrame(t protocol.MessageType, body []byte) []byte {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(body)+4))
	raw := append([]byte{byte(t)}, length...)
	raw = append(raw, body...)
	return raw
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

func feParseFrame(stmt, query string, oids []uint32) []byte {
	body := append(cstr(stmt), cstr(query)...)
	body = append(body, int16b(int16(len(oids)))...)
	for _, o := range oids {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, o)
		body = append(body, b...)
	}
	return buildFrame(protocol.MsgParse, body)
}

func feBindFrame(portal, stmt string, paramFormats []int16, params []protocol.BindParam, resultFormats []int16) []byte {
	body := append(cstr(portal), cstr(stmt)...)
	body = append(body, int16b(int16(len(paramFormats)))...)
	for _, f := range paramFormats {
		body = append(body, int16b(f)...)
	}
	body = append(body, int16b(int16(len(params)))...)
	for _, p := range params {
		if p.Null {
			body = append(body, int32b(-1)...)
			continue
		}
		body = append(body, int32b(int32(len(p.Value)))...)
		body = append(body, p.Value...)
	}
	body = append(body, int16b(int16(len(resultFormats)))...)
	for _, f := range resultFormats {
		body = append(body, int16b(f)...)
	}
	return buildFrame(protocol.MsgBind, body)
}

func feDescribeFrame(target protocol.TargetType, name string) []byte {
	return buildFrame(protocol.MsgDescribe, append([]byte{byte(target)}, cstr(name)...))
}

func feExecuteFrame(portal string, maxRows int32) []byte {
	return buildFrame(protocol.MsgExecute, append(cstr(portal), int32b(maxRows)...))
}

func feCloseFrame(target protocol.TargetType, name string) []byte {
	return buildFrame(protocol.MsgClose, append([]byte{byte(target)}, cstr(name)...))
}

func feSyncFrame() []byte      { return buildFrame(protocol.MsgSync, nil) }
func feFlushFrame() []byte     { return buildFrame(protocol.MsgFlush, nil) }
func feTerminateFrame() []byte { return buildFrame(protocol.MsgTerminate, nil) }
func feQueryFrame(sql string) []byte {
	return buildFrame(protocol.MsgQuery, cstr(sql))
}

// --- Test helpers: COMPLETELY FRAMED but semantically malformed bodies ----
//
// Each of these builds a frame whose OUTER tag+length framing is fully
// self-consistent (buildFrame always derives the declared length from the
// actual body) - the framing-only decoder (bkz. gorev 1) accepts every one
// of these as a single complete frame. Only the INNER body is deliberately
// invalid, so only ExtendedFrontend's own typed body parser (bkz. gorev 2)
// - never the decoder - can detect and reject it.

// malformedParseFrame omits the query string's terminating NUL.
func malformedParseFrame(stmt string) []byte {
	body := append(cstr(stmt), []byte("SELECT 1")...) // no trailing NUL
	return buildFrame(protocol.MsgParse, body)
}

// malformedBindFrame declares an out-of-range parameter format code
// (neither 0 nor 1).
func malformedBindFrame(portal, stmt string) []byte {
	body := append(cstr(portal), cstr(stmt)...)
	body = append(body, int16b(1)...) // 1 format code follows
	body = append(body, int16b(7)...) // invalid code
	body = append(body, int16b(0)...) // 0 params
	body = append(body, int16b(0)...) // 0 result formats
	return buildFrame(protocol.MsgBind, body)
}

// malformedDescribeFrame uses an invalid target selector byte.
func malformedDescribeFrame(name string) []byte {
	body := append([]byte{'X'}, cstr(name)...)
	return buildFrame(protocol.MsgDescribe, body)
}

// malformedExecuteFrame omits the trailing 4-byte MaxRows field.
func malformedExecuteFrame(portal string) []byte {
	body := cstr(portal) // missing Int32 MaxRows
	return buildFrame(protocol.MsgExecute, body)
}

// malformedCloseFrame uses an invalid target selector byte.
func malformedCloseFrame(name string) []byte {
	body := append([]byte{'X'}, cstr(name)...)
	return buildFrame(protocol.MsgClose, body)
}

// malformedFlushFrame has a non-empty body (Flush must be empty).
func malformedFlushFrame() []byte { return buildFrame(protocol.MsgFlush, []byte{1}) }

// malformedSyncFrame has a non-empty body (Sync must be empty).
func malformedSyncFrame() []byte { return buildFrame(protocol.MsgSync, []byte{1}) }

// malformedTerminateFrame has a non-empty body (Terminate must be empty).
func malformedTerminateFrame() []byte { return buildFrame(protocol.MsgTerminate, []byte{1}) }

func beEmpty(t protocol.MessageType) []byte { return buildFrame(t, nil) }
func beRFQ(status byte) []byte              { return buildFrame(protocol.MsgReadyForQuery, []byte{status}) }
func beDataRow() []byte                     { return buildFrame(protocol.MsgDataRow, []byte{0, 0}) }
func beCommandComplete(tag string) []byte {
	return buildFrame(protocol.MsgCommandComplete, append([]byte(tag), 0))
}

// minimalErrorFrame is the minimal VALID backend ErrorResponse used to
// simulate a genuine backend-side failure (distinct from the bridge's own
// LOCALLY generated synthetic ErrorResponse).
func minimalErrorFrame() []byte {
	body := []byte{'S'}
	body = append(body, []byte("ERROR")...)
	body = append(body, 0, 0)
	return buildFrame(protocol.MsgErrorResponse, body)
}

// --- Test helpers: connection accumulator -------------------------------

// connAccumulator continuously drains a net.Conn in the background,
// accumulating every byte read - needed because net.Pipe() is synchronous
// (a Write blocks until a matching Read consumes it), so the runtime's
// event-loop writer would stall forever without a concurrent reader.
type connAccumulator struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func newConnAccumulator(conn net.Conn) *connAccumulator {
	acc := &connAccumulator{}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				acc.mu.Lock()
				acc.buf.Write(buf[:n])
				acc.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return acc
}

func (a *connAccumulator) Snapshot() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.buf.Bytes()...)
}

func waitForAccumulated(t *testing.T, acc *connAccumulator, want []byte) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := acc.Snapshot()
		if bytes.Equal(got, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for bytes: got %x want %x", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// --- Test helpers: harness (bridge + real ExtendedRuntime + net.Pipe) -----

type harness struct {
	t        *testing.T
	rt       *gateway.ExtendedRuntime
	frontend *ExtendedFrontend

	clientTest  net.Conn // test writes simulated client bytes, reads client-bound responses
	backendTest net.Conn // test reads forwarded-upstream bytes, writes simulated backend responses

	clientBound *connAccumulator
	upstream    *connAccumulator

	cancel  context.CancelFunc
	rtDone  chan error
	runDone chan error

	rtOnce    sync.Once
	rtResult  error
	runOnce   sync.Once
	runResult error
}

// waitRuntimeStarted blocks (short poll) until rt.Run has genuinely begun
// processing events - probed via a mutation-free, always-rejected Bind (the
// runtime has no exported "started" signal outside its own package).
func waitRuntimeStarted(t *testing.T, rt *gateway.ExtendedRuntime) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := rt.RegisterAndForwardFrontendOperation(context.Background(),
			gateway.FrontendOperationRequest{Kind: protocol.OpBind, PortalName: "__probe__", StatementName: "__probe_unknown__"},
			feBindFrame("__probe__", "__probe_unknown__", nil, nil, nil))
		if !errors.Is(err, gateway.ErrNotRunning) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the runtime to start")
		}
		time.Sleep(time.Millisecond)
	}
}

func newHarness(t *testing.T, policy Policy, onDecide func(protocol.Message, Verdict, string, time.Duration)) *harness {
	t.Helper()
	clientRuntimeSide, clientTestSide := net.Pipe()
	backendRuntimeSide, backendTestSide := net.Pipe()

	s := protocol.NewState()
	limits := gateway.RuntimeLimits{FrontendEventBuffer: 8, BackendEventBuffer: 8, MaxFrontendFrameBytes: 64 * 1024}
	rt, err := gateway.NewExtendedRuntime(s, backendRuntimeSide, clientRuntimeSide, protocol.DefaultSequencerLimits(), limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frontend, err := NewExtendedFrontend(rt, policy, onDecide)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rtDone := make(chan error, 1)
	go func() { rtDone <- rt.Run(ctx) }()
	waitRuntimeStarted(t, rt)

	gate := &Gate{}
	runDone := make(chan error, 1)
	go func() { runDone <- gate.RunExtended(ctx, clientRuntimeSide, frontend) }()

	h := &harness{
		t: t, rt: rt, frontend: frontend,
		clientTest: clientTestSide, backendTest: backendTestSide,
		clientBound: newConnAccumulator(clientTestSide),
		upstream:    newConnAccumulator(backendTestSide),
		cancel:      cancel, rtDone: rtDone, runDone: runDone,
	}
	return h
}

func (h *harness) sendClient(frame []byte) {
	h.t.Helper()
	if _, err := h.clientTest.Write(frame); err != nil {
		h.t.Fatalf("unexpected error writing a client frame: %v", err)
	}
}

func (h *harness) sendBackend(frame []byte) {
	h.t.Helper()
	if _, err := h.backendTest.Write(frame); err != nil {
		h.t.Fatalf("unexpected error writing a backend frame: %v", err)
	}
}

// waitRuntimeDone/waitGateDone are IDEMPOTENT (bkz. sync.Once): a test may
// call either explicitly to assert on the result AND rely on the deferred
// h.close() for cleanup - without caching, the second receive on an
// already-drained, unbuffered-in-practice channel would block forever.
func (h *harness) waitRuntimeDone() error {
	h.t.Helper()
	h.rtOnce.Do(func() {
		select {
		case h.rtResult = <-h.rtDone:
		case <-time.After(5 * time.Second):
			h.t.Fatal("timed out waiting for runtime.Run to return")
		}
	})
	return h.rtResult
}

func (h *harness) waitGateDone() error {
	h.t.Helper()
	h.runOnce.Do(func() {
		select {
		case h.runResult = <-h.runDone:
		case <-time.After(5 * time.Second):
			h.t.Fatal("timed out waiting for Gate.RunExtended to return")
		}
	})
	return h.runResult
}

func (h *harness) close() {
	h.cancel()
	h.waitRuntimeDone()
	h.waitGateDone()
}

// ==========================================================================
// Default/live-preservation
// ==========================================================================

func TestGate_RunExtended_DoesNotAffectExistingRunBehavior(t *testing.T) {
	// Gate.Run (the LIVE, existing entry point) must remain source- and
	// behavior-compatible: it still rejects Extended Query fail-closed,
	// with no dependency on RunExtended/ExtendedFrontend whatsoever (bkz.
	// gorev 2). Full existing-behavior coverage lives in gate_test.go
	// (intentionally untouched, e.g. TestGate_ParseMessageCannotBypassInspection)
	// - this is a light spot-check using the SAME post-startup framing
	// gate_test.go's own helpers already establish (encodeStartupMessage/
	// encodeParse), proving a Gate{} zero-value's Run is unaffected by
	// this stage's additions.
	var target, respond bytes.Buffer
	g := NewGate(nil, &target, &respond, nil, nil)
	stream := append(append([]byte{}, encodeStartupMessage()...), encodeParse("s1", "SELECT 1")...)
	err := g.Run(bytes.NewReader(stream))
	if !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("expected live Gate.Run to still reject Extended Query fail-closed, got %v", err)
	}
	if bytes.Contains(target.Bytes(), []byte("SELECT 1")) {
		t.Fatalf("expected the Parse never forwarded to the real server, got %x", target.Bytes())
	}
}

func TestNewExtendedFrontend_NilRuntimeRejected(t *testing.T) {
	if _, err := NewExtendedFrontend(nil, nil, nil); !errors.Is(err, ErrNilExtendedRuntime) {
		t.Fatalf("expected ErrNilExtendedRuntime, got %v", err)
	}
}

func TestGate_RunExtended_NilFrontendRejected(t *testing.T) {
	g := &Gate{}
	err := g.RunExtended(context.Background(), bytes.NewReader(nil), nil)
	if !errors.Is(err, ErrNilExtendedFrontend) {
		t.Fatalf("expected ErrNilExtendedFrontend, got %v", err)
	}
}

// ==========================================================================
// Parse-time policy evaluation (bkz. gorev 8)
// ==========================================================================

func TestExtendedFrontend_Policy_AllowedParseForwarded(t *testing.T) {
	h := newHarness(t, DenyKeywords("DROP TABLE"), nil)
	defer h.close()

	frame := feParseFrame("s1", "SELECT 1", nil)
	h.sendClient(frame)
	waitForAccumulated(t, h.upstream, frame)
}

func TestExtendedFrontend_Policy_BlockedParseNeverForwarded(t *testing.T) {
	h := newHarness(t, DenyKeywords("DROP TABLE"), nil)
	defer h.close()

	h.sendClient(feParseFrame("s1", "DROP TABLE users;", nil))
	// A synthetic ErrorResponse must appear client-bound; nothing must
	// ever reach the upstream test peer.
	deadline := time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(h.clientBound.Snapshot()) == 0 {
		t.Fatal("expected a synthetic ErrorResponse written to the client")
	}
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the blocked Parse never forwarded upstream, got %x", h.upstream.Snapshot())
	}
	got := h.clientBound.Snapshot()
	if protocol.MessageType(got[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected an ErrorResponse frame, got tag %q", got[0])
	}
}

func TestExtendedFrontend_Policy_InvokedExactlyOnceForParse(t *testing.T) {
	var calls int
	var mu sync.Mutex
	policy := PolicyFunc(func(m protocol.Message) (Verdict, string) {
		mu.Lock()
		calls++
		mu.Unlock()
		return Allow, ""
	})
	h := newHarness(t, policy, nil)
	defer h.close()

	frame := feParseFrame("s1", "SELECT 1", nil)
	h.sendClient(frame)
	waitForAccumulated(t, h.upstream, frame)

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("expected policy invoked exactly once, got %d", got)
	}
}

func TestExtendedFrontend_Policy_NotInvokedForNonParseMessages(t *testing.T) {
	var calls int
	var mu sync.Mutex
	policy := PolicyFunc(func(m protocol.Message) (Verdict, string) {
		mu.Lock()
		calls++
		mu.Unlock()
		return Allow, ""
	})
	h := newHarness(t, policy, nil)
	defer h.close()

	h.sendClient(feParseFrame("s1", "SELECT 1", nil))
	waitForAccumulated(t, h.upstream, feParseFrame("s1", "SELECT 1", nil))

	bind := feBindFrame("p1", "s1", nil, nil, nil)
	h.sendClient(bind)
	waitForAccumulated(t, h.upstream, append(feParseFrame("s1", "SELECT 1", nil), bind...))

	desc := feDescribeFrame(protocol.TargetPortal, "p1")
	h.sendClient(desc)
	execFrame := feExecuteFrame("p1", 0)
	h.sendClient(execFrame)
	closeFrame := feCloseFrame(protocol.TargetPortal, "p1")
	h.sendClient(closeFrame)
	flush := feFlushFrame()
	h.sendClient(flush)
	sync := feSyncFrame()
	h.sendClient(sync)

	want := append([]byte{}, feParseFrame("s1", "SELECT 1", nil)...)
	want = append(want, bind...)
	want = append(want, desc...)
	want = append(want, execFrame...)
	want = append(want, closeFrame...)
	want = append(want, flush...)
	want = append(want, sync...)
	waitForAccumulated(t, h.upstream, want)

	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("expected policy invoked exactly once (Parse only), got %d", got)
	}
}

func TestExtendedFrontend_Policy_OnDecideReceivesNoSQLOrRaw(t *testing.T) {
	const secretSQL = "SECRET_ONDECIDE_SQL_MARKER"
	var got protocol.Message
	var gotVerdict Verdict
	onDecide := func(m protocol.Message, v Verdict, reason string, d time.Duration) {
		got = m
		gotVerdict = v
	}
	h := newHarness(t, DenyKeywords("DROP TABLE"), onDecide)
	defer h.close()

	frame := feParseFrame("s1", secretSQL, nil)
	h.sendClient(frame)
	waitForAccumulated(t, h.upstream, frame)

	if gotVerdict != Allow {
		t.Fatalf("expected Allow, got %v", gotVerdict)
	}
	if got.Query != "" {
		t.Fatalf("expected onDecide to receive no SQL text, got %q", got.Query)
	}
	if got.Raw != nil {
		t.Fatalf("expected onDecide to receive no Raw bytes, got %x", got.Raw)
	}
	if got.Type != protocol.MsgParse {
		t.Fatalf("expected the sanitized message type to be MsgParse, got %v", got.Type)
	}
}

// ==========================================================================
// Local rejection (bkz. gorev 10)
// ==========================================================================

func TestExtendedFrontend_LocalRejection_MalformedParseBody(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	// A REAL, wire-accurate, COMPLETELY framed Parse frame whose body is
	// deliberately invalid (bkz. gorev 1/2/7: "real raw-byte tests through
	// Gate.RunExtended, not only direct calls to ExtendedFrontend.handle").
	// The framing-only decoder accepts this as one complete frame; only
	// ExtendedFrontend's own body parser rejects it.
	h.sendClient(malformedParseFrame("s1"))

	deadline := time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	got := h.clientBound.Snapshot()
	if len(got) == 0 || protocol.MessageType(got[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected a synthetic ErrorResponse, got %x", got)
	}
	if !h.frontend.discarding() {
		t.Fatal("expected the bridge to enter discard-until-Sync after a malformed body")
	}
	// The decoder must NOT have failed closed (bkz. gorev 1) - the
	// runtime/RunExtended must both remain alive and usable.
	if h.frontend.isTerminal() {
		t.Fatal("expected the bridge to remain non-terminal after a recoverable malformed body")
	}
}

func TestExtendedFrontend_LocalRejection_UnknownStatementBind(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	h.sendClient(feBindFrame("p1", "does-not-exist", nil, nil, nil))

	deadline := time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	got := h.clientBound.Snapshot()
	if len(got) == 0 || protocol.MessageType(got[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected a synthetic ErrorResponse for the unknown statement, got %x", got)
	}
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the rejected Bind never forwarded, got %x", h.upstream.Snapshot())
	}
}

func TestExtendedFrontend_LocalRejection_UnknownPortalExecute(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	h.sendClient(feExecuteFrame("does-not-exist", 0))

	deadline := time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	got := h.clientBound.Snapshot()
	if len(got) == 0 || protocol.MessageType(got[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected a synthetic ErrorResponse for the unknown portal, got %x", got)
	}
}

func TestExtendedFrontend_LocalRejection_RejectedRawNeverReachesBackend(t *testing.T) {
	h := newHarness(t, DenyKeywords("DROP TABLE"), nil)
	defer h.close()

	frame := feParseFrame("s1", "DROP TABLE users;", nil)
	h.sendClient(frame)

	deadline := time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if bytes.Contains(h.upstream.Snapshot(), frame) {
		t.Fatal("expected the rejected Raw frame to never reach the backend")
	}
}

func TestExtendedFrontend_LocalRejection_NoSyntheticReadyForQuery(t *testing.T) {
	h := newHarness(t, DenyKeywords("DROP TABLE"), nil)
	defer h.close()

	h.sendClient(feParseFrame("s1", "DROP TABLE users;", nil))

	deadline := time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	got := h.clientBound.Snapshot()
	if bytes.Contains(got, []byte{byte(protocol.MsgReadyForQuery)}) {
		// Weak byte-level check refined below by full frame scan.
	}
	// A stronger check: walk frames and ensure none is ReadyForQuery.
	for len(got) > 0 {
		if len(got) < 5 {
			break
		}
		length := int(got[1])<<24 | int(got[2])<<16 | int(got[3])<<8 | int(got[4])
		total := 1 + length
		if total > len(got) {
			break
		}
		if protocol.MessageType(got[0]) == protocol.MsgReadyForQuery {
			t.Fatal("expected no synthetic ReadyForQuery to be generated locally")
		}
		got = got[total:]
	}
}

// ==========================================================================
// Discard-until-Sync (bkz. gorev 11, 12)
// ==========================================================================

func TestExtendedFrontend_Discard_BlockedFirstThenSyncClears(t *testing.T) {
	h := newHarness(t, DenyKeywords("DROP TABLE"), nil)
	defer h.close()

	h.sendClient(feParseFrame("s1", "DROP TABLE users;", nil))
	deadline := time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	// Bind/Execute/Flush must be silently discarded - no upstream bytes.
	h.sendClient(feBindFrame("p1", "s1", nil, nil, nil))
	h.sendClient(feExecuteFrame("p1", 0))
	h.sendClient(feFlushFrame())
	time.Sleep(20 * time.Millisecond) // allow the (absence of) processing to settle
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected discarded messages to produce no upstream bytes, got %x", h.upstream.Snapshot())
	}

	// Sync must still be forwarded and clear discard.
	sync := feSyncFrame()
	h.sendClient(sync)
	waitForAccumulated(t, h.upstream, sync)

	deadline = time.Now().Add(2 * time.Second)
	for h.frontend.discarding() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.frontend.discarding() {
		t.Fatal("expected discard to clear after Sync was forwarded")
	}
}

func TestExtendedFrontend_Discard_TerminateStillForwardedDuringDiscard(t *testing.T) {
	h := newHarness(t, DenyKeywords("DROP TABLE"), nil)
	defer h.close()

	h.sendClient(feParseFrame("s1", "DROP TABLE users;", nil))
	deadline := time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	term := feTerminateFrame()
	h.sendClient(term)
	waitForAccumulated(t, h.upstream, term)

	runErr := h.waitRuntimeDone()
	if !errors.Is(runErr, gateway.ErrFrontendTerminateRequested) {
		t.Fatalf("expected ErrFrontendTerminateRequested, got %v", runErr)
	}
	gateErr := h.waitGateDone()
	if gateErr != nil {
		t.Fatalf("expected RunExtended to return nil on a client-initiated Terminate, got %v", gateErr)
	}
}

func TestExtendedFrontend_Discard_PipelinedNextCycleBeforePriorReadyForQuery(t *testing.T) {
	h := newHarness(t, DenyKeywords("DROP TABLE"), nil)
	defer h.close()

	h.sendClient(feParseFrame("s1", "DROP TABLE users;", nil)) // cycle 1 blocked
	deadline := time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	sync1 := feSyncFrame()
	h.sendClient(sync1)
	waitForAccumulated(t, h.upstream, sync1)

	// Cycle 2's Parse must be accepted/forwarded WITHOUT waiting for
	// cycle 1's real ReadyForQuery (which the test never sends).
	parse2 := feParseFrame("s2", "SELECT 2", nil)
	h.sendClient(parse2)
	waitForAccumulated(t, h.upstream, append(sync1, parse2...))
}

// ==========================================================================
// Flush and Terminate via the bridge (bkz. gorev 6)
// ==========================================================================

func TestExtendedFrontend_Flush_ForwardedNoAckExpected(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	flush := feFlushFrame()
	h.sendClient(flush)
	waitForAccumulated(t, h.upstream, flush)
	// No backend acknowledgement exists for Flush - the runtime must
	// remain healthy without one; proven by a subsequent Parse working.
	parse := feParseFrame("s1", "SELECT 1", nil)
	h.sendClient(parse)
	waitForAccumulated(t, h.upstream, append(flush, parse...))
}

func TestExtendedFrontend_Terminate_ShutsDownCleanly(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	term := feTerminateFrame()
	h.sendClient(term)
	waitForAccumulated(t, h.upstream, term)

	runErr := h.waitRuntimeDone()
	if !errors.Is(runErr, gateway.ErrFrontendTerminateRequested) {
		t.Fatalf("expected ErrFrontendTerminateRequested, got %v", runErr)
	}
	gateErr := h.waitGateDone()
	if gateErr != nil {
		t.Fatalf("expected RunExtended nil on client Terminate, got %v", gateErr)
	}
}

// ==========================================================================
// Frontend closure (bkz. gorev 7)
// ==========================================================================

func TestExtendedFrontend_Closure_CleanEOFNotifiesRuntime(t *testing.T) {
	h := newHarness(t, nil, nil)

	if err := h.clientTest.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gateErr := h.waitGateDone()
	if gateErr != nil {
		t.Fatalf("expected RunExtended nil on clean client EOF, got %v", gateErr)
	}
	runErr := h.waitRuntimeDone()
	if !errors.Is(runErr, gateway.ErrFrontendClosed) {
		t.Fatalf("expected ErrFrontendClosed, got %v", runErr)
	}
	h.cancel()
}

func TestExtendedFrontend_Closure_DecoderFramingErrorFailsClosed(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	// A corrupted length field (< 4) triggers the decoder's onError.
	bad := []byte{byte(protocol.MsgParse), 0, 0, 0, 1}
	h.sendClient(bad)

	gateErr := h.waitGateDone()
	if gateErr == nil {
		t.Fatal("expected RunExtended to return a non-nil fail-closed error")
	}
	if !errors.Is(gateErr, ErrExtendedFrontendDecodeFailed) {
		t.Fatalf("expected ErrExtendedFrontendDecodeFailed, got %v", gateErr)
	}
	runErr := h.waitRuntimeDone()
	if !errors.Is(runErr, gateway.ErrFrontendProtocolFailure) {
		t.Fatalf("expected ErrFrontendProtocolFailure, got %v", runErr)
	}
}

// ==========================================================================
// Unsupported/mixed messages (bkz. gorev 13)
// ==========================================================================

func TestExtendedFrontend_MixedProtocol_SimpleQueryFailsClosed(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	h.sendClient(feQueryFrame("SELECT 1"))

	gateErr := h.waitGateDone()
	if !errors.Is(gateErr, ErrExtendedFrontendUnsupportedMessage) {
		t.Fatalf("expected ErrExtendedFrontendUnsupportedMessage, got %v", gateErr)
	}
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected MsgQuery never forwarded, got %x", h.upstream.Snapshot())
	}
	runErr := h.waitRuntimeDone()
	if !errors.Is(runErr, gateway.ErrFrontendProtocolFailure) {
		t.Fatalf("expected ErrFrontendProtocolFailure, got %v", runErr)
	}
}

func TestExtendedFrontend_MixedProtocol_CopyFrontendMessageFailsClosed(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	h.sendClient(buildFrame(protocol.MsgCopyData, []byte{1, 2, 3}))

	gateErr := h.waitGateDone()
	if !errors.Is(gateErr, ErrExtendedFrontendUnsupportedMessage) {
		t.Fatalf("expected ErrExtendedFrontendUnsupportedMessage, got %v", gateErr)
	}
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the COPY message never forwarded, got %x", h.upstream.Snapshot())
	}
}

// ==========================================================================
// Ordering integration (bkz. gorev 12, 18 "Ordering integration")
// ==========================================================================

func TestExtendedFrontend_Ordering_ParseParseCompletePassThrough(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	parse := feParseFrame("s1", "SELECT 1", nil)
	h.sendClient(parse)
	waitForAccumulated(t, h.upstream, parse)

	pc := beEmpty(protocol.MsgParseComplete)
	h.sendBackend(pc)
	waitForAccumulated(t, h.clientBound, pc)
}

func TestExtendedFrontend_Ordering_BindExecuteDataRowCommandCompletePassThrough(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	parse := feParseFrame("s1", "SELECT 1", nil)
	h.sendClient(parse)
	waitForAccumulated(t, h.upstream, parse)
	h.sendBackend(beEmpty(protocol.MsgParseComplete))
	waitForAccumulated(t, h.clientBound, beEmpty(protocol.MsgParseComplete))

	bind := feBindFrame("p1", "s1", nil, nil, nil)
	h.sendClient(bind)
	waitForAccumulated(t, h.upstream, append(parse, bind...))
	h.sendBackend(beEmpty(protocol.MsgBindComplete))
	waitForAccumulated(t, h.clientBound, append(beEmpty(protocol.MsgParseComplete), beEmpty(protocol.MsgBindComplete)...))

	exec := feExecuteFrame("p1", 0)
	h.sendClient(exec)
	waitForAccumulated(t, h.upstream, append(append(parse, bind...), exec...))

	dr := beDataRow()
	cc := beCommandComplete("SELECT 1")
	h.sendBackend(dr)
	h.sendBackend(cc)
	want := append(append([]byte{}, beEmpty(protocol.MsgParseComplete)...), beEmpty(protocol.MsgBindComplete)...)
	want = append(want, dr...)
	want = append(want, cc...)
	waitForAccumulated(t, h.clientBound, want)
}

func TestExtendedFrontend_Ordering_BlockedParseBehindRealOperation_RealThenSynthetic(t *testing.T) {
	h := newHarness(t, DenyKeywords("DROP TABLE"), nil)
	defer h.close()

	// A: allowed Parse, still pending (no ParseComplete yet).
	parseA := feParseFrame("a", "SELECT 1", nil)
	h.sendClient(parseA)
	waitForAccumulated(t, h.upstream, parseA)

	// B: blocked Parse, queued behind A.
	h.sendClient(feParseFrame("b", "DROP TABLE users;", nil))

	// B's synthetic rejection must be accepted (bridge enters discard)
	// WITHOUT requiring A's backend completion first.
	deadline := time.Now().Add(2 * time.Second)
	for !h.frontend.discarding() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !h.frontend.discarding() {
		t.Fatal("expected the bridge to enter discard for the blocked Parse without waiting on A")
	}
	// Nothing must be client-visible yet (A hasn't completed).
	if len(h.clientBound.Snapshot()) != 0 {
		t.Fatalf("expected no client-bound bytes before A completes, got %x", h.clientBound.Snapshot())
	}

	// A's real completion is relayed FIRST, B's synthetic error SECOND.
	// The sequencer emits BOTH in the same processActions batch (A's real
	// terminal frame, immediately followed by draining B's now-unblocked
	// synthetic unit) - bkz. protocol.ResponseSequencer.drain - so there
	// is no meaningful intermediate "pc alone" state to observe; wait for
	// the combined bytes and assert the ORDER directly.
	pc := beEmpty(protocol.MsgParseComplete)
	h.sendBackend(pc)
	deadline = time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) <= len(pc) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	got := h.clientBound.Snapshot()
	if len(got) <= len(pc) {
		t.Fatalf("expected B's synthetic error to follow A's ParseComplete, got %x", got)
	}
	if !bytes.Equal(got[:len(pc)], pc) {
		t.Fatalf("expected A's real ParseComplete first, got %x", got)
	}
	if protocol.MessageType(got[len(pc)]) != protocol.MsgErrorResponse {
		t.Fatalf("expected B's synthetic ErrorResponse second, got %x", got[len(pc):])
	}
}

func TestExtendedFrontend_Ordering_AsyncBackendMessagesRelayedInOrder(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	notice := buildFrame(protocol.MsgNoticeResponse, []byte{'S', 'N', 0, 0})
	h.sendBackend(notice)
	waitForAccumulated(t, h.clientBound, notice)
}

// ==========================================================================
// Non-disclosure spot checks specific to the bridge layer (bkz. gorev 17)
// ==========================================================================

func TestExtendedFrontend_NonDisclosure_ErrorsNeverContainNames(t *testing.T) {
	const secretStmt = "SECRET_FRONTEND_STMT_MARKER"
	h := newHarness(t, nil, nil)
	defer h.close()

	h.sendClient(feBindFrame("p1", secretStmt, nil, nil, nil))

	deadline := time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	got := h.clientBound.Snapshot()
	if bytes.Contains(got, []byte(secretStmt)) {
		t.Fatalf("synthetic ErrorResponse leaked the statement name marker: %x", got)
	}
}

func TestExtendedFrontend_NonDisclosure_BindValuesNeverInErrors(t *testing.T) {
	const secretValue = "SECRET_FRONTEND_BIND_VALUE_MARKER"
	h := newHarness(t, nil, nil)
	defer h.close()

	parse := feParseFrame("s1", "SELECT 1", nil)
	h.sendClient(parse)
	waitForAccumulated(t, h.upstream, parse)
	h.sendBackend(beEmpty(protocol.MsgParseComplete))
	waitForAccumulated(t, h.clientBound, beEmpty(protocol.MsgParseComplete))

	// Bind against an UNKNOWN portal name collision path is not needed
	// here - instead verify the value is never echoed into any client-
	// bound synthetic frame by forcing an unrelated rejection (unknown
	// portal Execute) while a Bind carrying the marker was ALSO sent.
	params := []protocol.BindParam{{Value: []byte(secretValue)}}
	h.sendClient(feBindFrame("p1", "s1", nil, params, nil))
	h.sendBackend(beEmpty(protocol.MsgBindComplete))
	waitForAccumulated(t, h.clientBound, append(beEmpty(protocol.MsgParseComplete), beEmpty(protocol.MsgBindComplete)...))

	h.sendClient(feExecuteFrame("does-not-exist", 0))
	deadline := time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) <= len(beEmpty(protocol.MsgParseComplete))+len(beEmpty(protocol.MsgBindComplete)) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	got := h.clientBound.Snapshot()
	if bytes.Contains(got, []byte(secretValue)) {
		t.Fatalf("client-bound bytes leaked the Bind value marker: %x", got)
	}
}

// ==========================================================================
// Non-Go-error non-disclosure: strings package sanity import check
// ==========================================================================

func TestExtendedFrontend_NonDisclosure_GoErrorsNeverContainSQL(t *testing.T) {
	const secretSQL = "SECRET_GOERR_SQL_MARKER"
	h := newHarness(t, DenyKeywords("DROP TABLE"), nil)
	defer h.close()

	// A REAL wire-accurate Parse frame carrying the marker (bkz. gorev 7:
	// real raw-byte tests through Gate.RunExtended). This particular query
	// does not match the deny list, so it registers successfully; the
	// important assertion is that no internal error (there shouldn't be
	// one) ever echoes the marker. The backend ParseComplete is
	// acknowledged so the plan head clears - otherwise the LATER Bind
	// rejection's synthetic frame would remain correctly QUEUED behind
	// the still-pending Parse (bkz. existing queued-ordering semantics,
	// internal/gateway's TestExtendedRuntime_QueuedOrdering_*) and never
	// become client-visible within this test's bounded wait.
	parseFrame := feParseFrame("s1", secretSQL, nil)
	h.sendClient(parseFrame)
	waitForAccumulated(t, h.upstream, parseFrame)
	h.sendBackend(beEmpty(protocol.MsgParseComplete))
	waitForAccumulated(t, h.clientBound, beEmpty(protocol.MsgParseComplete))

	// Force a genuine error path too: an unknown-statement Bind using the
	// marker as the statement name.
	prefixLen := len(h.clientBound.Snapshot())
	h.sendClient(feBindFrame("p1", secretSQL, nil, nil, nil))
	deadline := time.Now().Add(2 * time.Second)
	for len(h.clientBound.Snapshot()) <= prefixLen && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	got := h.clientBound.Snapshot()
	if len(got) <= prefixLen {
		t.Fatal("expected a synthetic ErrorResponse for the unknown-statement Bind, got no new client-bound bytes")
	}
	if strings.Contains(string(got), secretSQL) {
		t.Fatalf("client-bound bytes leaked the SQL/name marker: %x", got)
	}
}

// ==========================================================================
// Bounded, deterministic stress/property test (bkz. gorev 19)
// ==========================================================================
//
// TestExtendedFrontend_Stress drives a short, bounded, seeded mix of
// frontend messages (valid/malformed Parse, Bind with text/binary/null
// parameters, Describe, Execute, Close, Flush, Sync, Terminate), policy
// allow/block, backend acknowledgements/errors and async backend messages
// against a real harness (bridge + ExtendedRuntime + net.Pipe). It is a
// short bounded property test in the same spirit as
// internal/gateway.TestExtendedRuntime_Stress and the protocol package's
// opReader-driven fuzz tests, adapted here to drive the frontend bridge's
// entry points instead. Uses deterministic seeds and bounded deadlines -
// no timing-only sleeps beyond short, bounded polling waits.
//
// Invariants checked:
//   - no panic (a panic anywhere would fail the test outright);
//   - no name/SQL/Bind-value marker ever appears in client-bound bytes
//     UNLESS it is legitimately relayed real backend content (bodyMarker,
//     via genuine backend frames) - nameMarker (used only in rejected
//     Parse/Bind/local-only paths) must NEVER appear;
//   - the harness always reaches a definitive stop (no hang) within the
//     bounded deadline;
//   - no goroutine deadlock across repeated fresh harnesses.
func TestExtendedFrontend_Stress(t *testing.T) {
	seeds := [][]byte{
		{0, 8, 1, 9, 2, 8, 3, 6, 7, 5, 4},
		{1, 1, 8, 9, 0, 8, 2, 2},
		{2, 2, 2, 9, 9, 0, 1, 6},
		{},
		{9, 9, 9, 9, 9, 9, 9, 9, 3, 4, 5},
		{7, 6, 5, 4, 3, 2, 1, 0, 8, 9},
	}

	const nameMarker = "SECRET_STRESS_NAME_MARKER"
	const bodyMarker = "SECRET_STRESS_BODY_MARKER"

	for si, seed := range seeds {
		seed := seed
		t.Run(fmt.Sprintf("seed-%d", si), func(t *testing.T) {
			h := newHarness(t, DenyKeywords("DROP TABLE"), nil)

			pos := 0
			next := func() (byte, bool) {
				if pos >= len(seed) {
					return 0, false
				}
				b := seed[pos]
				pos++
				return b, true
			}

			stopped := false
			checkStopped := func() bool {
				if stopped {
					return true
				}
				select {
				case err := <-h.runDone:
					h.runOnce.Do(func() { h.runResult = err })
					stopped = true
				default:
				}
				return stopped
			}

			for step := 0; step < 60 && !checkStopped(); step++ {
				b, ok := next()
				if !ok {
					break
				}
				switch int(b) % 11 {
				case 0:
					h.sendClient(feParseFrame("s1", "SELECT 1", nil))
				case 1:
					h.sendClient(feParseFrame(nameMarker, "DROP TABLE users;", nil)) // policy-blocked
				case 2:
					h.sendClient(feBindFrame("p1", "s1", nil, []protocol.BindParam{{Value: []byte(bodyMarker)}}, nil))
				case 3:
					h.sendClient(feBindFrame("p1", "does-not-exist", nil, []protocol.BindParam{{Null: true}}, nil))
				case 4:
					h.sendClient(feDescribeFrame(protocol.TargetPortal, "p1"))
				case 5:
					h.sendClient(feExecuteFrame("p1", 0))
				case 6:
					h.sendClient(feCloseFrame(protocol.TargetStatement, "s1"))
				case 7:
					h.sendClient(feFlushFrame())
				case 8:
					h.sendClient(feSyncFrame())
				case 9:
					h.sendBackend(beEmpty(protocol.MsgParseComplete))
				case 10:
					h.sendBackend(buildFrame(protocol.MsgNoticeResponse, []byte{'S', 'N', 0, 0}))
				}
				time.Sleep(200 * time.Microsecond) // bounded settling, not a correctness dependency
			}

			h.cancel()
			h.waitRuntimeDone()
			h.waitGateDone()

			clientBytes := h.clientBound.Snapshot()
			if bytes.Contains(clientBytes, []byte(nameMarker)) {
				t.Fatalf("client-bound bytes leaked the name marker: %x", clientBytes)
			}
			upstreamBytes := h.upstream.Snapshot()
			if bytes.Contains(upstreamBytes, []byte(nameMarker)) {
				// nameMarker is used ONLY for a policy-blocked Parse
				// statement name, which must never reach the backend.
				t.Fatalf("upstream bytes leaked the blocked name marker: %x", upstreamBytes)
			}
		})
	}
}

// ==========================================================================
// Framing-versus-parsing (sertlestirme incelemesi, gorev 1/2/7)
// ==========================================================================

// waitForSynthetic waits for exactly one ErrorResponse to appear
// client-bound and returns it.
func waitForSynthetic(t *testing.T, h *harness) []byte {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got := h.clientBound.Snapshot()
		if len(got) > 0 {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for a synthetic ErrorResponse")
	return nil
}

func TestExtendedFrontend_Framing_ValidParseParsedAndForwarded(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	frame := feParseFrame("s1", "SELECT 1", nil)
	h.sendClient(frame)
	waitForAccumulated(t, h.upstream, frame)
}

func TestExtendedFrontend_Framing_MalformedParseProducesOneSyntheticAndDiscard(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	h.sendClient(malformedParseFrame("s1"))
	got := waitForSynthetic(t, h)
	if protocol.MessageType(got[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected an ErrorResponse frame, got tag %q", got[0])
	}
	if !h.frontend.discarding() {
		t.Fatal("expected the bridge to enter discard-until-Sync")
	}
	if h.frontend.isTerminal() {
		t.Fatal("expected the decoder to NOT fail closed for a completely framed malformed body")
	}
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the malformed Parse never forwarded, got %x", h.upstream.Snapshot())
	}
}

func TestExtendedFrontend_Framing_MalformedBindProducesOneSyntheticAndDiscard(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	h.sendClient(malformedBindFrame("p1", "s1"))
	got := waitForSynthetic(t, h)
	if protocol.MessageType(got[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected an ErrorResponse frame, got tag %q", got[0])
	}
	if !h.frontend.discarding() {
		t.Fatal("expected the bridge to enter discard-until-Sync")
	}
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the malformed Bind never forwarded, got %x", h.upstream.Snapshot())
	}
}

func TestExtendedFrontend_Framing_MalformedDescribeProducesOneSyntheticAndDiscard(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	h.sendClient(malformedDescribeFrame("s1"))
	got := waitForSynthetic(t, h)
	if protocol.MessageType(got[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected an ErrorResponse frame, got tag %q", got[0])
	}
	if !h.frontend.discarding() {
		t.Fatal("expected the bridge to enter discard-until-Sync")
	}
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the malformed Describe never forwarded, got %x", h.upstream.Snapshot())
	}
}

func TestExtendedFrontend_Framing_MalformedExecuteProducesOneSyntheticAndDiscard(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	h.sendClient(malformedExecuteFrame("p1"))
	got := waitForSynthetic(t, h)
	if protocol.MessageType(got[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected an ErrorResponse frame, got tag %q", got[0])
	}
	if !h.frontend.discarding() {
		t.Fatal("expected the bridge to enter discard-until-Sync")
	}
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the malformed Execute never forwarded, got %x", h.upstream.Snapshot())
	}
}

func TestExtendedFrontend_Framing_MalformedCloseProducesOneSyntheticAndDiscard(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	h.sendClient(malformedCloseFrame("s1"))
	got := waitForSynthetic(t, h)
	if protocol.MessageType(got[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected an ErrorResponse frame, got tag %q", got[0])
	}
	if !h.frontend.discarding() {
		t.Fatal("expected the bridge to enter discard-until-Sync")
	}
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the malformed Close never forwarded, got %x", h.upstream.Snapshot())
	}
}

func TestExtendedFrontend_Framing_MalformedSyncFailsClosedNeverForwarded(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	h.sendClient(malformedSyncFrame())

	gateErr := h.waitGateDone()
	if !errors.Is(gateErr, ErrExtendedFrontendMalformedFrame) {
		t.Fatalf("expected ErrExtendedFrontendMalformedFrame, got %v", gateErr)
	}
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the malformed Sync never forwarded, got %x", h.upstream.Snapshot())
	}
}

func TestExtendedFrontend_Framing_MalformedTerminateFailsClosedNeverForwarded(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	h.sendClient(malformedTerminateFrame())

	gateErr := h.waitGateDone()
	if !errors.Is(gateErr, ErrExtendedFrontendMalformedFrame) {
		t.Fatalf("expected ErrExtendedFrontendMalformedFrame, got %v", gateErr)
	}
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the malformed Terminate never forwarded, got %x", h.upstream.Snapshot())
	}
}

// ==========================================================================
// Discard-before-parsing: the CORE regression scenario (gorev 3)
// ==========================================================================
//
// "A policy-blocked Parse followed by a deliberately malformed Bind and
// then a valid Sync must: (1) produce exactly one synthetic ErrorResponse;
// (2) discard the malformed Bind without decoder failure; (3) register and
// forward the valid Sync; (4) relay the real ReadyForQuery later; (5) keep
// the runtime usable for the next cycle."

func TestExtendedFrontend_DiscardBeforeParsing_BlockedParseThenMalformedBindThenSync(t *testing.T) {
	var policyCalls int32
	countingPolicy := PolicyFunc(func(m protocol.Message) (Verdict, string) {
		policyCalls++
		return DenyKeywords("DROP TABLE").Evaluate(m)
	})
	h := newHarness(t, countingPolicy, nil)
	defer h.close()

	// 1. Blocked Parse.
	h.sendClient(feParseFrame("s1", "DROP TABLE users;", nil))
	synthetic := waitForSynthetic(t, h)
	if protocol.MessageType(synthetic[0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected exactly one synthetic ErrorResponse, got %x", synthetic)
	}
	callsAfterBlock := policyCalls

	// 2. Malformed Bind while discarding - must be silently dropped
	// WITHOUT any decoder failure and WITHOUT invoking policy again.
	h.sendClient(malformedBindFrame("p1", "s1"))
	time.Sleep(20 * time.Millisecond) // bounded settling for the (absence of) processing
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the discarded malformed Bind never forwarded, got %x", h.upstream.Snapshot())
	}
	if !bytes.Equal(h.clientBound.Snapshot(), synthetic) {
		t.Fatalf("expected NO additional synthetic error for the discarded malformed Bind, got %x (was %x)", h.clientBound.Snapshot(), synthetic)
	}
	if policyCalls != callsAfterBlock {
		t.Fatalf("expected policy NOT invoked for the discarded malformed Bind, calls went from %d to %d", callsAfterBlock, policyCalls)
	}
	if h.frontend.isTerminal() {
		t.Fatal("expected the decoder to NOT fail closed for the discarded malformed Bind")
	}

	// 3. Valid Sync - must still be registered and forwarded.
	sync := feSyncFrame()
	h.sendClient(sync)
	waitForAccumulated(t, h.upstream, sync)

	deadline := time.Now().Add(2 * time.Second)
	for h.frontend.discarding() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.frontend.discarding() {
		t.Fatal("expected discard to clear after Sync was forwarded")
	}

	// 4. Real ReadyForQuery completes the cycle.
	rfq := beRFQ(protocol.TxStatusIdle)
	h.sendBackend(rfq)
	waitForAccumulated(t, h.clientBound, append(append([]byte{}, synthetic...), rfq...))

	// 5. Runtime remains usable for the next cycle.
	parse2 := feParseFrame("s2", "SELECT 2", nil)
	h.sendClient(parse2)
	waitForAccumulated(t, h.upstream, append(sync, parse2...))
}

func TestExtendedFrontend_DiscardBeforeParsing_BlockedParseThenMalformedParseThenSync(t *testing.T) {
	h := newHarness(t, DenyKeywords("DROP TABLE"), nil)
	defer h.close()

	h.sendClient(feParseFrame("s1", "DROP TABLE users;", nil))
	synthetic := waitForSynthetic(t, h)

	h.sendClient(malformedParseFrame("s2"))
	time.Sleep(20 * time.Millisecond)
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the discarded malformed Parse never forwarded, got %x", h.upstream.Snapshot())
	}
	if !bytes.Equal(h.clientBound.Snapshot(), synthetic) {
		t.Fatalf("expected NO additional synthetic error, got %x (was %x)", h.clientBound.Snapshot(), synthetic)
	}
	if h.frontend.isTerminal() {
		t.Fatal("expected the decoder to NOT fail closed for the discarded malformed Parse")
	}

	sync := feSyncFrame()
	h.sendClient(sync)
	waitForAccumulated(t, h.upstream, sync)

	deadline := time.Now().Add(2 * time.Second)
	for h.frontend.discarding() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.frontend.discarding() {
		t.Fatal("expected discard to clear after Sync was forwarded")
	}
}

func TestExtendedFrontend_DiscardBeforeParsing_BlockedParseThenMalformedFlushThenSync(t *testing.T) {
	h := newHarness(t, DenyKeywords("DROP TABLE"), nil)
	defer h.close()

	h.sendClient(feParseFrame("s1", "DROP TABLE users;", nil))
	synthetic := waitForSynthetic(t, h)

	h.sendClient(malformedFlushFrame())
	time.Sleep(20 * time.Millisecond)
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected the discarded malformed Flush never forwarded, got %x", h.upstream.Snapshot())
	}
	if !bytes.Equal(h.clientBound.Snapshot(), synthetic) {
		t.Fatalf("expected NO additional synthetic error, got %x (was %x)", h.clientBound.Snapshot(), synthetic)
	}
	if h.frontend.isTerminal() {
		t.Fatal("expected the decoder to NOT fail closed for the discarded malformed Flush")
	}

	sync := feSyncFrame()
	h.sendClient(sync)
	waitForAccumulated(t, h.upstream, sync)

	deadline := time.Now().Add(2 * time.Second)
	for h.frontend.discarding() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.frontend.discarding() {
		t.Fatal("expected discard to clear after Sync was forwarded")
	}
}

// ==========================================================================
// EOF finalization (gorev 4)
// ==========================================================================

func TestExtendedFrontend_EOF_EmptyBufferIsClean(t *testing.T) {
	h := newHarness(t, nil, nil)

	if err := h.clientTest.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gateErr := h.waitGateDone(); gateErr != nil {
		t.Fatalf("expected clean EOF (nil), got %v", gateErr)
	}
	runErr := h.waitRuntimeDone()
	if !errors.Is(runErr, gateway.ErrFrontendClosed) {
		t.Fatalf("expected ErrFrontendClosed, got %v", runErr)
	}
	h.cancel()
}

func TestExtendedFrontend_EOF_PartialHeaderFailsClosed(t *testing.T) {
	for n := 1; n <= 4; n++ {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			h := newHarness(t, nil, nil)
			defer h.close()

			full := feSyncFrame()
			h.sendClient(full[:n])
			if err := h.clientTest.Close(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			gateErr := h.waitGateDone()
			if !errors.Is(gateErr, ErrExtendedFrontendDecodeFailed) {
				t.Fatalf("expected ErrExtendedFrontendDecodeFailed, got %v", gateErr)
			}
			if len(h.upstream.Snapshot()) != 0 {
				t.Fatalf("expected no upstream bytes, got %x", h.upstream.Snapshot())
			}
		})
	}
}

func TestExtendedFrontend_EOF_TruncatedBodyFailsClosed(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	full := feParseFrame("s1", "SELECT 1", nil)
	h.sendClient(full[:len(full)-2]) // tag+length present, body cut short
	if err := h.clientTest.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gateErr := h.waitGateDone()
	if !errors.Is(gateErr, ErrExtendedFrontendDecodeFailed) {
		t.Fatalf("expected ErrExtendedFrontendDecodeFailed, got %v", gateErr)
	}
	if len(h.upstream.Snapshot()) != 0 {
		t.Fatalf("expected no upstream bytes, got %x", h.upstream.Snapshot())
	}
}

func TestExtendedFrontend_EOF_CompleteFramePlusPartialNext_ProcessesOnceThenFailsClosed(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	complete := feFlushFrame()
	partialNext := feSyncFrame()[:2]
	h.sendClient(append(append([]byte{}, complete...), partialNext...))
	waitForAccumulated(t, h.upstream, complete)

	if err := h.clientTest.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gateErr := h.waitGateDone()
	if !errors.Is(gateErr, ErrExtendedFrontendDecodeFailed) {
		t.Fatalf("expected ErrExtendedFrontendDecodeFailed, got %v", gateErr)
	}
	// The complete frame must have been forwarded EXACTLY once - no
	// partial trailing bytes ever reach the backend.
	if !bytes.Equal(h.upstream.Snapshot(), complete) {
		t.Fatalf("expected exactly the one complete frame forwarded, got %x", h.upstream.Snapshot())
	}
}

func TestExtendedFrontend_EOF_SeveralCompleteFramesRemainClean(t *testing.T) {
	h := newHarness(t, nil, nil)

	f1 := feFlushFrame()
	f2 := feSyncFrame()
	h.sendClient(append(append([]byte{}, f1...), f2...))
	waitForAccumulated(t, h.upstream, append(append([]byte{}, f1...), f2...))

	if err := h.clientTest.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gateErr := h.waitGateDone(); gateErr != nil {
		t.Fatalf("expected clean EOF (nil), got %v", gateErr)
	}
	h.cancel()
	h.waitRuntimeDone()
}

// ==========================================================================
// Non-disclosure for malformed bodies (gorev 6/17)
// ==========================================================================

func TestExtendedFrontend_NonDisclosure_MalformedBodyMarkersNeverInErrors(t *testing.T) {
	const secretMarker = "SECRET_MALFORMED_BODY_MARKER"
	h := newHarness(t, nil, nil)
	defer h.close()

	// Embed the marker in the (malformed) Bind's statement name field -
	// even though the body is malformed elsewhere (invalid format code),
	// the marker must never surface in any client-bound or Go error.
	body := append(cstr("p1"), cstr(secretMarker)...)
	body = append(body, int16b(1)...)
	body = append(body, int16b(7)...) // invalid format code
	body = append(body, int16b(0)...)
	body = append(body, int16b(0)...)
	h.sendClient(buildFrame(protocol.MsgBind, body))

	got := waitForSynthetic(t, h)
	if bytes.Contains(got, []byte(secretMarker)) {
		t.Fatalf("synthetic ErrorResponse leaked the malformed-body marker: %x", got)
	}
}

func TestExtendedFrontend_NonDisclosure_UnknownTagNeverInErrors(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	// An unrecognized frontend tag byte with a distinctive length so any
	// accidental leak of the numeric tag/length would be easy to spot -
	// but ErrExtendedFrontendUnsupportedMessage is a FIXED sentinel with
	// no dynamic content at all.
	h.sendClient(buildFrame(protocol.MessageType(0x7F), []byte{1, 2, 3, 4, 5}))

	gateErr := h.waitGateDone()
	if !errors.Is(gateErr, ErrExtendedFrontendUnsupportedMessage) {
		t.Fatalf("expected ErrExtendedFrontendUnsupportedMessage, got %v", gateErr)
	}
	if gateErr.Error() != ErrExtendedFrontendUnsupportedMessage.Error() {
		t.Fatalf("expected the EXACT fixed sentinel with no appended detail, got %q", gateErr.Error())
	}
}

func TestExtendedFrontend_NonDisclosure_DecodeErrorIsExactFixedSentinel(t *testing.T) {
	h := newHarness(t, nil, nil)
	defer h.close()

	bad := []byte{byte(protocol.MsgParse), 0, 0, 0, 1} // declared length < 4
	h.sendClient(bad)

	gateErr := h.waitGateDone()
	if !errors.Is(gateErr, ErrExtendedFrontendDecodeFailed) {
		t.Fatalf("expected ErrExtendedFrontendDecodeFailed, got %v", gateErr)
	}
	if gateErr.Error() != ErrExtendedFrontendDecodeFailed.Error() {
		t.Fatalf("expected the EXACT fixed sentinel (no declared-length/tag detail appended), got %q", gateErr.Error())
	}
}

// erroringReader is an io.Reader whose Read ALWAYS returns a fixed,
// marker-bearing, non-EOF error - used to prove RunExtended's returned
// error is the EXACT fixed ErrExtendedFrontendReadFailed sentinel, never
// the underlying error's own text (bkz. gorev 6).
type erroringReader struct{ err error }

func (r erroringReader) Read(p []byte) (int, error) { return 0, r.err }

func TestExtendedFrontend_NonDisclosure_ReadErrorIsExactFixedSentinel(t *testing.T) {
	backendRuntimeSide, backendPeer := net.Pipe()
	defer backendPeer.Close()
	clientRuntimeSide, clientPeer := net.Pipe()
	defer clientPeer.Close()

	s := protocol.NewState()
	limits := gateway.RuntimeLimits{FrontendEventBuffer: 8, BackendEventBuffer: 8, MaxFrontendFrameBytes: 64 * 1024}
	rt, err := gateway.NewExtendedRuntime(s, backendRuntimeSide, clientRuntimeSide, protocol.DefaultSequencerLimits(), limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frontend, err := NewExtendedFrontend(rt, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rtDone := make(chan error, 1)
	go func() { rtDone <- rt.Run(ctx) }()
	waitRuntimeStarted(t, rt)

	const secretDetail = "SECRET_READ_ERROR_DETAIL_MARKER"
	injected := errors.New(secretDetail)

	gate := &Gate{}
	gateErr := gate.RunExtended(ctx, erroringReader{err: injected}, frontend)
	if !errors.Is(gateErr, ErrExtendedFrontendReadFailed) {
		t.Fatalf("expected ErrExtendedFrontendReadFailed, got %v", gateErr)
	}
	if gateErr.Error() != ErrExtendedFrontendReadFailed.Error() {
		t.Fatalf("expected the EXACT fixed sentinel (no underlying detail appended), got %q", gateErr.Error())
	}
	if strings.Contains(gateErr.Error(), secretDetail) {
		t.Fatalf("RunExtended's error leaked the underlying read-error detail: %q", gateErr.Error())
	}

	cancel()
	<-rtDone
}

// ==========================================================================
// Repeated stress: critical discard/framing/shutdown behavior (gorev 7,9)
// ==========================================================================

func TestExtendedFrontend_DiscardBeforeParsing_Repeated(t *testing.T) {
	const iterations = 100
	for i := 0; i < iterations; i++ {
		func() {
			h := newHarness(t, DenyKeywords("DROP TABLE"), nil)
			defer h.close()

			h.sendClient(feParseFrame("s1", "DROP TABLE users;", nil))
			synthetic := waitForSynthetic(t, h)

			h.sendClient(malformedBindFrame("p1", "s1"))
			time.Sleep(2 * time.Millisecond)
			if len(h.upstream.Snapshot()) != 0 {
				t.Fatalf("iteration %d: expected no upstream bytes, got %x", i, h.upstream.Snapshot())
			}
			if !bytes.Equal(h.clientBound.Snapshot(), synthetic) {
				t.Fatalf("iteration %d: expected exactly one synthetic error, got %x", i, h.clientBound.Snapshot())
			}
			if h.frontend.isTerminal() {
				t.Fatalf("iteration %d: expected the decoder to NOT fail closed", i)
			}

			sync := feSyncFrame()
			h.sendClient(sync)
			waitForAccumulated(t, h.upstream, sync)
		}()
	}
}

func TestExtendedFrontend_EOF_TruncatedBody_Repeated(t *testing.T) {
	const iterations = 100
	for i := 0; i < iterations; i++ {
		func() {
			h := newHarness(t, nil, nil)
			defer h.close()

			full := feParseFrame("s1", "SELECT 1", nil)
			h.sendClient(full[:len(full)-2])
			if err := h.clientTest.Close(); err != nil {
				t.Fatalf("iteration %d: unexpected error: %v", i, err)
			}
			gateErr := h.waitGateDone()
			if !errors.Is(gateErr, ErrExtendedFrontendDecodeFailed) {
				t.Fatalf("iteration %d: expected ErrExtendedFrontendDecodeFailed, got %v", i, gateErr)
			}
			if len(h.upstream.Snapshot()) != 0 {
				t.Fatalf("iteration %d: expected no upstream bytes, got %x", i, h.upstream.Snapshot())
			}
		}()
	}
}

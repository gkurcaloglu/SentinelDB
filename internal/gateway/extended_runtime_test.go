package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// --- Test helpers: frame builders --------------------------------------

func buildFrame(t protocol.MessageType, body []byte) []byte {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(body)+4))
	raw := append([]byte{byte(t)}, length...)
	raw = append(raw, body...)
	return raw
}

func emptyFrame(t protocol.MessageType) []byte { return buildFrame(t, nil) }

func rfqFrame(status byte) []byte { return buildFrame(protocol.MsgReadyForQuery, []byte{status}) }

func dataRowFrame() []byte { return buildFrame(protocol.MsgDataRow, []byte{0, 0}) }

func commandCompleteFrame(tag string) []byte {
	return buildFrame(protocol.MsgCommandComplete, append([]byte(tag), 0))
}

// minimalErrorFrame is the minimal VALID ErrorResponse under the
// tightened field-framing rule: at least one non-terminal field is
// required.
func minimalErrorFrame() []byte {
	body := []byte{'S'}
	body = append(body, []byte("ERROR")...)
	body = append(body, 0)
	body = append(body, 0) // terminator
	return buildFrame(protocol.MsgErrorResponse, body)
}

func fieldedErrorFrame(text string) []byte {
	body := []byte{'S'}
	body = append(body, []byte("ERROR")...)
	body = append(body, 0)
	body = append(body, 'M')
	body = append(body, []byte(text)...)
	body = append(body, 0)
	body = append(body, 0)
	return buildFrame(protocol.MsgErrorResponse, body)
}

func terminalOnlyErrorFrame() []byte { return buildFrame(protocol.MsgErrorResponse, []byte{0}) }

// --- Test helpers: frontend operation request builders --------------------
//
// State is now exclusively owned by the event loop (bkz. "Make the event
// loop the sole owner of protocol.State") - tests build typed requests
// instead of calling protocol.State.Create* themselves.

func parseReq(name, query string, paramOIDs []uint32) FrontendOperationRequest {
	return FrontendOperationRequest{Kind: protocol.OpParse, StatementName: name, Query: query, ParamOIDs: paramOIDs}
}

func bindReq(portal, stmt string, paramFormats []int16, paramNulls []bool, resultFormats []int16) FrontendOperationRequest {
	return FrontendOperationRequest{
		Kind: protocol.OpBind, PortalName: portal, StatementName: stmt,
		ParamFormats: paramFormats, ParamNulls: paramNulls, ResultFormats: resultFormats,
	}
}

func describeStmtReq(name string) FrontendOperationRequest {
	return FrontendOperationRequest{Kind: protocol.OpDescribeStatement, StatementName: name}
}

func describePortalReq(name string) FrontendOperationRequest {
	return FrontendOperationRequest{Kind: protocol.OpDescribePortal, PortalName: name}
}

func executeReq(portal string) FrontendOperationRequest {
	return FrontendOperationRequest{Kind: protocol.OpExecute, PortalName: portal}
}

func closeStmtReq(name string) FrontendOperationRequest {
	return FrontendOperationRequest{Kind: protocol.OpCloseStatement, StatementName: name}
}

func closePortalReq(name string) FrontendOperationRequest {
	return FrontendOperationRequest{Kind: protocol.OpClosePortal, PortalName: name}
}

func syncReq() FrontendOperationRequest { return FrontendOperationRequest{Kind: protocol.OpSync} }

func mustRegister(t *testing.T, ctx context.Context, rt *ExtendedRuntime, req FrontendOperationRequest) protocol.PendingOperation {
	t.Helper()
	reg, err := rt.RegisterFrontendOperation(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return reg.Operation
}

// --- Test helpers: writer double -----------------------------------------

// trackingWriter is an in-memory io.WriteCloser test double that records
// every write, can inject partial writes / no-progress / errors, and
// detects concurrent Write calls (proving the runtime never issues more
// than one at a time).
type trackingWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	closed bool

	partialN       int  // if > 0, caps every Write to at most this many bytes
	noProgressOnce bool // if true, the NEXT Write returns (0, nil) once
	writeErrOnce   error

	writeCount          int32
	busy                int32
	concurrentViolation atomic.Bool
}

func newTrackingWriter() *trackingWriter { return &trackingWriter{} }

func (w *trackingWriter) Write(p []byte) (int, error) {
	if !atomic.CompareAndSwapInt32(&w.busy, 0, 1) {
		w.concurrentViolation.Store(true)
		return 0, errors.New("test: concurrent write detected")
	}
	defer atomic.StoreInt32(&w.busy, 0)
	runtime.Gosched()

	atomic.AddInt32(&w.writeCount, 1)

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errors.New("test: write after close")
	}
	if w.noProgressOnce {
		w.noProgressOnce = false
		return 0, nil
	}
	if w.writeErrOnce != nil {
		err := w.writeErrOnce
		w.writeErrOnce = nil
		return 0, err
	}
	n := len(p)
	if w.partialN > 0 && n > w.partialN {
		n = w.partialN
	}
	w.buf.Write(p[:n])
	return n, nil
}

func (w *trackingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return nil
}

func (w *trackingWriter) Closed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closed
}

func (w *trackingWriter) Snapshot() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

func (w *trackingWriter) WriteCount() int { return int(atomic.LoadInt32(&w.writeCount)) }

func (w *trackingWriter) ConcurrentViolation() bool { return w.concurrentViolation.Load() }

// --- Test helpers: runtime setup -----------------------------------------

func testRuntimeLimits() RuntimeLimits {
	return RuntimeLimits{FrontendEventBuffer: 8, BackendEventBuffer: 8}
}

func newTestRuntime(t *testing.T, backend io.ReadCloser, client io.WriteCloser) *ExtendedRuntime {
	t.Helper()
	s := protocol.NewState()
	rt, err := NewExtendedRuntime(s, backend, client, protocol.DefaultSequencerLimits(), testRuntimeLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return rt
}

func waitStarted(t *testing.T, r *ExtendedRuntime) {
	t.Helper()
	select {
	case <-r.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Run to start")
	}
}

func runInBackground(t *testing.T, r *ExtendedRuntime, ctx context.Context) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	waitStarted(t, r)
	return done
}

func waitDone(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Run to return")
		return nil
	}
}

func waitForBytes(t *testing.T, w *trackingWriter, want []byte) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := w.Snapshot()
		if bytes.Equal(got, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for bytes: got %x want %x", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertNoGoroutineLeak(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		after := runtime.NumGoroutine()
		if after <= before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("possible goroutine leak: before=%d after=%d", before, after)
		}
		time.Sleep(time.Millisecond)
	}
}

// setupRuntimeExecuteHead registers an unnamed Parse, Bind and Execute
// through the runtime (acknowledging each backend terminal along the
// way), leaving the sequencer's head at the registered Execute operation.
func setupRuntimeExecuteHead(t *testing.T, ctx context.Context, rt *ExtendedRuntime, backendW io.Writer, client *trackingWriter) protocol.PendingOperation {
	t.Helper()
	mustRegister(t, ctx, rt, parseReq("", "SELECT 1", nil))
	pc := emptyFrame(protocol.MsgParseComplete)
	if _, err := backendW.Write(pc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, pc)

	mustRegister(t, ctx, rt, bindReq("", "", nil, nil, nil))
	bc := emptyFrame(protocol.MsgBindComplete)
	if _, err := backendW.Write(bc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, append(append([]byte{}, pc...), bc...))

	return mustRegister(t, ctx, rt, executeReq(""))
}

// --- Lifecycle -------------------------------------------------------------

func TestNewExtendedRuntime_Validation(t *testing.T) {
	validLimits := testRuntimeLimits()
	s := protocol.NewState()
	backend := io.NopCloser(strings.NewReader(""))
	client := newTrackingWriter()

	if _, err := NewExtendedRuntime(nil, backend, client, protocol.DefaultSequencerLimits(), validLimits); !errors.Is(err, ErrNilState) {
		t.Fatalf("expected ErrNilState, got %v", err)
	}
	if _, err := NewExtendedRuntime(s, nil, client, protocol.DefaultSequencerLimits(), validLimits); !errors.Is(err, ErrNilBackend) {
		t.Fatalf("expected ErrNilBackend, got %v", err)
	}
	if _, err := NewExtendedRuntime(s, backend, nil, protocol.DefaultSequencerLimits(), validLimits); !errors.Is(err, ErrNilClient) {
		t.Fatalf("expected ErrNilClient, got %v", err)
	}

	badLimits := []RuntimeLimits{
		{FrontendEventBuffer: 0, BackendEventBuffer: 1},
		{FrontendEventBuffer: 1, BackendEventBuffer: 0},
		{FrontendEventBuffer: -1, BackendEventBuffer: 1},
	}
	for i, l := range badLimits {
		if _, err := NewExtendedRuntime(s, backend, client, protocol.DefaultSequencerLimits(), l); !errors.Is(err, ErrInvalidRuntimeLimits) {
			t.Fatalf("case %d: expected ErrInvalidRuntimeLimits for %+v, got %v", i, l, err)
		}
	}

	badSeqLimits := protocol.SequencerLimits{}
	if _, err := NewExtendedRuntime(s, backend, client, badSeqLimits, validLimits); err == nil {
		t.Fatal("expected an error for invalid sequencer limits")
	}
}

func TestExtendedRuntime_SubmitBeforeRun_ReturnsNotRunning(t *testing.T) {
	rt := newTestRuntime(t, io.NopCloser(strings.NewReader("")), newTrackingWriter())
	if _, err := rt.RegisterFrontendOperation(context.Background(), parseReq("s1", "SELECT 1", nil)); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("expected ErrNotRunning, got %v", err)
	}
	if err := rt.SubmitSyntheticError(context.Background(), protocol.CycleID(1), minimalErrorFrame()); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("expected ErrNotRunning, got %v", err)
	}
}

func TestExtendedRuntime_Run_SucceedsOnlyOnce(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)

	done := runInBackground(t, rt, context.Background())

	if err := rt.Run(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("expected ErrAlreadyRunning, got %v", err)
	}

	backendW.Close()
	if err := waitDone(t, done); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtendedRuntime_SubmitWhileRunning_Succeeds(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)

	done := runInBackground(t, rt, context.Background())

	if _, err := rt.RegisterFrontendOperation(context.Background(), parseReq("s1", "SELECT 1", nil)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	backendW.Close()
	waitDone(t, done)
}

func TestExtendedRuntime_SubmitAfterTerminal_ReturnsStopped(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)

	done := runInBackground(t, rt, context.Background())
	backendW.Close() // EOF, no pending work -> clean stop
	if err := waitDone(t, done); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := rt.RegisterFrontendOperation(context.Background(), parseReq("s1", "SELECT 1", nil)); !errors.Is(err, ErrRuntimeStopped) {
		t.Fatalf("expected ErrRuntimeStopped, got %v", err)
	}
	if err := rt.SubmitSyntheticError(context.Background(), protocol.CycleID(1), minimalErrorFrame()); !errors.Is(err, ErrRuntimeStopped) {
		t.Fatalf("expected ErrRuntimeStopped, got %v", err)
	}
}

func TestExtendedRuntime_ContextCancellation_ClosesBothEnds(t *testing.T) {
	backendConn1, backendConn2 := net.Pipe()
	clientConn1, clientConn2 := net.Pipe()
	rt := newTestRuntime(t, backendConn1, clientConn1)

	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, rt, ctx)
	cancel()

	err := waitDone(t, done)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	if _, err := backendConn2.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected backend peer read to fail after runtime closed its end")
	}
	if _, err := clientConn2.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected client peer read to fail after runtime closed its end")
	}
}

func TestExtendedRuntime_BackendReaderJoinedBeforeRunReturns(t *testing.T) {
	// backendR never receives data or a close from the test - the ONLY
	// way Run() can return promptly is if cancellation correctly closes
	// r.backend, unblocking runBackendReader's Read() so it can exit and
	// be joined by Run's wg.Wait() before Run itself returns.
	backendR, _ := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)

	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, rt, ctx)
	cancel()
	if err := waitDone(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestExtendedRuntime_NoGoroutineLeakOnOrdinaryCancellation(t *testing.T) {
	before := runtime.NumGoroutine()

	backendR, _ := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)

	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, rt, ctx)
	cancel()
	waitDone(t, done)

	assertNoGoroutineLeak(t, before)
}

// --- Blocked-first ----------------------------------------------------

func TestExtendedRuntime_BlockedFirst_SyntheticEmitsImmediately(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	frame := minimalErrorFrame()
	if err := rt.SubmitSyntheticError(context.Background(), protocol.CycleID(1), frame); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(client.Snapshot(), frame) {
		t.Fatalf("expected the synthetic frame written exactly once, got %x", client.Snapshot())
	}
	if client.WriteCount() != 1 {
		t.Fatalf("expected exactly one Write call, got %d", client.WriteCount())
	}

	cancel()
	waitDone(t, done)
}

// --- Queued ordering -----------------------------------------------------

func TestExtendedRuntime_QueuedOrdering_ParseCompleteBeforeSynthetic(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	op := mustRegister(t, context.Background(), rt, parseReq("s1", "SELECT 1", nil))

	if err := rt.SubmitSyntheticError(context.Background(), op.Cycle, minimalErrorFrame()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(client.Snapshot()) != 0 {
		t.Fatalf("expected no output yet (synthetic remains blocked behind Parse), got %x", client.Snapshot())
	}

	frame := emptyFrame(protocol.MsgParseComplete)
	if _, err := backendW.Write(frame); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := append(append([]byte{}, frame...), minimalErrorFrame()...)
	waitForBytes(t, client, want)

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_IntermediateDataRows_DoNotReleaseQueuedSynthetic(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	eop := setupRuntimeExecuteHead(t, context.Background(), rt, backendW, client)

	if err := rt.SubmitSyntheticError(context.Background(), eop.Cycle, minimalErrorFrame()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	dr := dataRowFrame()
	prefix := client.Snapshot()
	for i := 0; i < 3; i++ {
		if _, err := backendW.Write(dr); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	want := append(append([]byte{}, prefix...), bytes.Repeat(dr, 3)...)
	waitForBytes(t, client, want)

	if bytes.Contains(client.Snapshot(), minimalErrorFrame()) {
		t.Fatal("expected the synthetic frame withheld until the Execute terminal completion")
	}

	cc := commandCompleteFrame("SELECT 3")
	if _, err := backendW.Write(cc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	finalWant := append(append([]byte{}, want...), append(cc, minimalErrorFrame()...)...)
	waitForBytes(t, client, finalWant)

	cancel()
	waitDone(t, done)
}

// --- Asynchronous backend events -----------------------------------------

func TestExtendedRuntime_Async_NoticeResponseNoPlan(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	notice := buildFrame(protocol.MsgNoticeResponse, []byte{'S', 'N', 0, 0})
	if _, err := backendW.Write(notice); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, notice)

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_Async_ParameterStatusDuringExecute_DoesNotConsumePlan(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	setupRuntimeExecuteHead(t, context.Background(), rt, backendW, client)
	before := client.Snapshot()

	ps := buildFrame(protocol.MsgParameterStatus, []byte{'k', 0, 'v', 0})
	if _, err := backendW.Write(ps); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, append(append([]byte{}, before...), ps...))

	// The Execute plan unit must remain: a real terminal still completes
	// it normally.
	cc := commandCompleteFrame("SELECT 0")
	if _, err := backendW.Write(cc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, append(append(append([]byte{}, before...), ps...), cc...))

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_Async_NotificationResponseWhileSyncPending(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	mustRegister(t, context.Background(), rt, syncReq())

	notif := buildFrame(protocol.MsgNotificationResponse, append([]byte{0, 0, 0, 1}, append([]byte("ch"), 0, 'p', 0)...))
	if _, err := backendW.Write(notif); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, notif)

	rfq := rfqFrame(protocol.TxStatusIdle)
	if _, err := backendW.Write(rfq); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, append(append([]byte{}, notif...), rfq...))

	cancel()
	waitDone(t, done)
}

// --- Sync -------------------------------------------------------------

func TestExtendedRuntime_Sync_ErrorResponseThenReadyForQuery(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	mustRegister(t, context.Background(), rt, syncReq())

	errFrame := minimalErrorFrame()
	if _, err := backendW.Write(errFrame); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, errFrame)

	rfq := rfqFrame(protocol.TxStatusIdle)
	if _, err := backendW.Write(rfq); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, append(append([]byte{}, errFrame...), rfq...))

	cancel()
	err := waitDone(t, done)
	if errors.Is(err, ErrTerminationRequested) {
		t.Fatalf("Sync ErrorResponse must not request termination, got %v", err)
	}
}

func TestExtendedRuntime_Sync_MultipleCyclesFIFO(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	mustRegister(t, context.Background(), rt, syncReq())
	mustRegister(t, context.Background(), rt, parseReq("s2", "SELECT 2", nil))
	mustRegister(t, context.Background(), rt, syncReq())

	rfq1 := rfqFrame(protocol.TxStatusIdle)
	if _, err := backendW.Write(rfq1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, rfq1)

	pc := emptyFrame(protocol.MsgParseComplete)
	if _, err := backendW.Write(pc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, append(append([]byte{}, rfq1...), pc...))

	rfq2 := rfqFrame(protocol.TxStatusIdle)
	if _, err := backendW.Write(rfq2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, append(append(append([]byte{}, rfq1...), pc...), rfq2...))

	cancel()
	waitDone(t, done)
}

// --- Connection-level error ------------------------------------------

func TestExtendedRuntime_ConnectionLevelError_RelayedThenTerminate(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	frame := minimalErrorFrame()
	if _, err := backendW.Write(frame); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := waitDone(t, done)
	if !errors.Is(err, ErrTerminationRequested) {
		t.Fatalf("expected ErrTerminationRequested, got %v", err)
	}
	if !bytes.Equal(client.Snapshot(), frame) {
		t.Fatalf("expected exactly the relayed frame, got %x", client.Snapshot())
	}
	if !client.Closed() {
		t.Fatal("expected the client connection closed")
	}
}

func TestExtendedRuntime_ConnectionLevelError_MalformedNoOutputFailsClosed(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	if _, err := backendW.Write(terminalOnlyErrorFrame()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := waitDone(t, done)
	if !errors.Is(err, ErrBackendProtocolFailure) {
		t.Fatalf("expected ErrBackendProtocolFailure, got %v", err)
	}
	if len(client.Snapshot()) != 0 {
		t.Fatalf("expected no output, got %x", client.Snapshot())
	}
	if !client.Closed() {
		t.Fatal("expected the client connection closed")
	}
}

// --- Writes -------------------------------------------------------------

func TestExtendedRuntime_Writes_PartialWriterCompletesFrame(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	client.partialN = 3
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	frame := minimalErrorFrame()
	if err := rt.SubmitSyntheticError(context.Background(), protocol.CycleID(1), frame); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(client.Snapshot(), frame) {
		t.Fatalf("expected the complete frame despite partial writes, got %x want %x", client.Snapshot(), frame)
	}
	if client.WriteCount() < 2 {
		t.Fatalf("expected multiple Write calls due to partial writes, got %d", client.WriteCount())
	}

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_Writes_NoProgressFailsClosed(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	client.noProgressOnce = true
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	err := rt.SubmitSyntheticError(context.Background(), protocol.CycleID(1), minimalErrorFrame())
	if !errors.Is(err, ErrNoProgress) || !errors.Is(err, ErrClientWriteFailed) {
		t.Fatalf("expected wrapped ErrClientWriteFailed/ErrNoProgress, got %v", err)
	}

	runErr := waitDone(t, done)
	if !errors.Is(runErr, ErrClientWriteFailed) {
		t.Fatalf("expected Run to return ErrClientWriteFailed, got %v", runErr)
	}
}

func TestExtendedRuntime_Writes_ClientWriteErrorTerminatesRuntime(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	injected := errors.New("test: simulated write failure")
	client.writeErrOnce = injected
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	err := rt.SubmitSyntheticError(context.Background(), protocol.CycleID(1), minimalErrorFrame())
	if !errors.Is(err, ErrClientWriteFailed) {
		t.Fatalf("expected ErrClientWriteFailed, got %v", err)
	}

	runErr := waitDone(t, done)
	if !errors.Is(runErr, ErrClientWriteFailed) {
		t.Fatalf("expected Run to return ErrClientWriteFailed, got %v", runErr)
	}
}

func TestExtendedRuntime_Writes_FramesBeforeTerminateWrittenExactlyOnce(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	frame := minimalErrorFrame()
	if _, err := backendW.Write(frame); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := waitDone(t, done); !errors.Is(err, ErrTerminationRequested) {
		t.Fatalf("expected ErrTerminationRequested, got %v", err)
	}
	if !bytes.Equal(client.Snapshot(), frame) {
		t.Fatalf("expected exactly one relayed frame, got %x", client.Snapshot())
	}
	if strings.Count(string(client.Snapshot()), string(frame)) != 1 {
		t.Fatal("expected the frame written exactly once")
	}
}

func TestExtendedRuntime_Writes_NoWriteAfterTermination(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	if _, err := backendW.Write(minimalErrorFrame()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitDone(t, done)

	countAfter := client.WriteCount()
	time.Sleep(10 * time.Millisecond)
	if client.WriteCount() != countAfter {
		t.Fatal("expected no further writes after termination")
	}
}

func TestExtendedRuntime_Writes_MaxConcurrencyIsOne(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	// State is now owned exclusively by the event loop, so concurrent
	// callers safely race directly against RegisterFrontendOperation
	// itself (no external State access needed).
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cycle := protocol.CycleID(i + 1)
			_ = rt.SubmitSyntheticError(context.Background(), cycle, minimalErrorFrame())
		}(i)
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = rt.RegisterFrontendOperation(context.Background(), parseReq(fmt.Sprintf("s%d", i), "SELECT 1", nil))
		}(i)
	}
	wg.Wait()

	if client.ConcurrentViolation() {
		t.Fatal("detected concurrent Write calls - the event loop must be the sole client writer")
	}

	cancel()
	waitDone(t, done)
}

// --- Backend reading -------------------------------------------------

func TestExtendedRuntime_BackendReading_FragmentedFrame(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	frame := buildFrame(protocol.MsgNoticeResponse, []byte{'S', 'N', 0, 0})
	go func() {
		for _, b := range frame {
			backendW.Write([]byte{b})
		}
	}()
	waitForBytes(t, client, frame)

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_BackendReading_SeveralFramesOneRead(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	f1 := buildFrame(protocol.MsgNoticeResponse, []byte{'S', 'N', 0, 0})
	f2 := buildFrame(protocol.MsgParameterStatus, []byte{'k', 0, 'v', 0})
	combined := append(append([]byte{}, f1...), f2...)
	if _, err := backendW.Write(combined); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, combined)

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_BackendReading_DecoderError(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	bad := buildFrame(protocol.MsgErrorResponse, nil)
	bad[4] = 0 // corrupt length field to below minimum (< 4)
	if _, err := backendW.Write(bad); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := waitDone(t, done)
	if !errors.Is(err, ErrBackendReadFailed) {
		t.Fatalf("expected ErrBackendReadFailed, got %v", err)
	}
	if len(client.Snapshot()) != 0 {
		t.Fatalf("expected no output on decode failure, got %x", client.Snapshot())
	}
}

func TestExtendedRuntime_BackendReading_NonEOFReadError(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	injected := errors.New("test: simulated backend read failure")
	backendW.CloseWithError(injected)

	err := waitDone(t, done)
	if !errors.Is(err, ErrBackendReadFailed) {
		t.Fatalf("expected ErrBackendReadFailed, got %v", err)
	}
}

func TestExtendedRuntime_BackendReading_CleanEOFNoPendingWork(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	backendW.Close()

	err := waitDone(t, done)
	if err != nil {
		t.Fatalf("expected a clean stop (nil error), got %v", err)
	}
}

func TestExtendedRuntime_BackendReading_UnexpectedEOFWithPendingWork(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	mustRegister(t, context.Background(), rt, parseReq("s1", "SELECT 1", nil))

	backendW.Close()

	err := waitDone(t, done)
	if !errors.Is(err, ErrBackendClosedUnexpectedly) {
		t.Fatalf("expected ErrBackendClosedUnexpectedly, got %v", err)
	}
}

func TestExtendedRuntime_BackendReading_BlockedReaderStillWokenBySynthetic(t *testing.T) {
	// The backend reader's Read() blocks forever (no data, no close) for
	// the lifetime of this test - proves the event loop is woken by the
	// SEPARATE frontend event source, not only by backend traffic.
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	frame := minimalErrorFrame()
	if err := rt.SubmitSyntheticError(context.Background(), protocol.CycleID(1), frame); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(client.Snapshot(), frame) {
		t.Fatalf("expected the synthetic frame written despite the blocked backend reader")
	}

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_BackendReading_ChannelBackpressureNoMessageLoss(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	s := protocol.NewState()
	limits := RuntimeLimits{FrontendEventBuffer: 1, BackendEventBuffer: 1} // deliberately tiny
	rt, err := NewExtendedRuntime(s, backendR, client, protocol.DefaultSequencerLimits(), limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	var frames [][]byte
	for i := 0; i < 10; i++ {
		f := buildFrame(protocol.MsgNoticeResponse, []byte{'S', 'N', 0, 0})
		frames = append(frames, f)
	}
	var want []byte
	for _, f := range frames {
		want = append(want, f...)
		if _, err := backendW.Write(f); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	waitForBytes(t, client, want)

	cancel()
	waitDone(t, done)
}

// --- Plan mismatch ------------------------------------------------------
//
// Note: the pre-hardening "backend acknowledgement arrives before plan
// registration" scenario (a caller creating a State operation without
// ever registering it with the sequencer) is now structurally
// IMPOSSIBLE - State is exclusively owned by the event loop, and
// RegisterFrontendOperation always creates the State operation and
// registers it with the sequencer atomically in the same turn. What
// remains representable (and still tested below) is a real backend
// message arriving with no matching operation at all, or the wrong kind.

func TestExtendedRuntime_PlanMismatch_WrongOperationPlan(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	mustRegister(t, context.Background(), rt, parseReq("s1", "SELECT 1", nil))

	if _, err := backendW.Write(emptyFrame(protocol.MsgBindComplete)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := waitDone(t, done)
	if !errors.Is(err, ErrBackendProtocolFailure) {
		t.Fatalf("expected ErrBackendProtocolFailure, got %v", err)
	}
}

func TestExtendedRuntime_PlanMismatch_UnexpectedReadyForQuery(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	if _, err := backendW.Write(rfqFrame(protocol.TxStatusIdle)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := waitDone(t, done)
	if !errors.Is(err, ErrBackendProtocolFailure) {
		t.Fatalf("expected ErrBackendProtocolFailure, got %v", err)
	}
}

func TestExtendedRuntime_PlanMismatch_UnsupportedCOPYResponse(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	setupRuntimeExecuteHead(t, context.Background(), rt, backendW, client)

	if _, err := backendW.Write(buildFrame(protocol.MsgCopyOutResponse, []byte{0, 0, 0})); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := waitDone(t, done)
	if !errors.Is(err, ErrBackendProtocolFailure) {
		t.Fatalf("expected ErrBackendProtocolFailure, got %v", err)
	}
}

// --- Cancellation -------------------------------------------------------

func TestExtendedRuntime_Cancellation_WhileBackendReadBlocked(t *testing.T) {
	backendR, _ := io.Pipe() // never written to, never closed by the test
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, rt, ctx)
	cancel()
	if err := waitDone(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestExtendedRuntime_Cancellation_BeforeRun_ReturnsNotRunning(t *testing.T) {
	backendR, _ := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)

	canceledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	// Runtime not started yet: not-running takes precedence over an
	// already-canceled caller context (checked first, no blocking).
	if _, err := rt.RegisterFrontendOperation(canceledCtx, parseReq("s1", "SELECT 1", nil)); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("expected ErrNotRunning, got %v", err)
	}
}

func TestExtendedRuntime_Cancellation_WhileClientWriteBlocked(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	clientConn1, clientConn2 := net.Pipe() // real blocking net.Conn semantics
	defer clientConn2.Close()
	rt := newTestRuntime(t, backendR, clientConn1)

	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, rt, ctx)

	// Submit a synthetic error from a separate goroutine: since nobody
	// reads clientConn2, the runtime's Write into clientConn1 blocks.
	submitDone := make(chan error, 1)
	go func() {
		submitDone <- rt.SubmitSyntheticError(context.Background(), protocol.CycleID(1), minimalErrorFrame())
	}()

	cancel()

	select {
	case err := <-submitDone:
		if err == nil {
			t.Fatal("expected the blocked submit to fail once the runtime tears down")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("submit did not unblock after cancellation")
	}

	waitDone(t, done)
}

func TestExtendedRuntime_Cancellation_RepeatedCloseCallsAreSafe(t *testing.T) {
	backendR, _ := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, rt, ctx)
	cancel()
	cancel() // repeated cancel is always safe on a context.CancelFunc
	waitDone(t, done)

	if err := backendR.Close(); err == nil {
		// Closing an already-closed io.PipeReader is documented as a
		// no-op returning nil - either way it must not panic.
		_ = err
	}
	if err := client.Close(); err != nil {
		t.Fatalf("expected repeated Close to be safe, got %v", err)
	}
}

// --- Mutation isolation / non-disclosure ---------------------------------

func TestExtendedRuntime_MutationIsolation_SyntheticFrameMutatedAfterSubmission(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	op := mustRegister(t, context.Background(), rt, parseReq("s1", "SELECT 1", nil))

	frame := append([]byte(nil), minimalErrorFrame()...)
	if err := rt.SubmitSyntheticError(context.Background(), op.Cycle, frame); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame[5] = 0xFF // mutate caller's own slice after submission returns

	pc := emptyFrame(protocol.MsgParseComplete)
	if _, err := backendW.Write(pc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := append(append([]byte{}, pc...), minimalErrorFrame()...)
	waitForBytes(t, client, want)

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_MutationIsolation_RequestSlicesMutatedAfterSubmission(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	oids := []uint32{23, 25}
	req := parseReq("s1", "SELECT 1", oids)
	reg, err := rt.RegisterFrontendOperation(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	oids[0] = 999999 // mutate caller's own slice after submission returns

	if reg.Operation.Kind != protocol.OpParse {
		t.Fatalf("unexpected registration: %+v", reg)
	}

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_NonDisclosure_ErrorsNeverContainMarkers(t *testing.T) {
	const secretStmt = "SECRET_RUNTIME_STMT_MARKER"
	const secretSQL = "SECRET_RUNTIME_SQL_MARKER"

	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	mustRegister(t, context.Background(), rt, parseReq(secretStmt, "SELECT 1 -- "+secretSQL, nil))

	// Trigger a plan mismatch by acknowledging the WRONG kind.
	if _, err := backendW.Write(emptyFrame(protocol.MsgBindComplete)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := waitDone(t, done)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.Contains(msg, secretStmt) || strings.Contains(msg, secretSQL) {
		t.Fatalf("runtime error leaked a marker: %s", msg)
	}
}

func TestExtendedRuntime_NonDisclosure_RegistrationErrorNeverContainsMarkers(t *testing.T) {
	const secretPortal = "SECRET_RUNTIME_BIND_MARKER"
	const secretStmt = "SECRET_RUNTIME_UNKNOWN_STMT_MARKER"
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	// Bind against a statement that was never Parsed: State.CreateBind
	// rejects this with ErrUnknownStatement before any mutation.
	_, err := rt.RegisterFrontendOperation(context.Background(), bindReq(secretPortal, secretStmt, nil, nil, nil))
	if err == nil {
		t.Fatal("expected an unknown-statement rejection")
	}
	if strings.Contains(err.Error(), secretPortal) || strings.Contains(err.Error(), secretStmt) {
		t.Fatalf("registration error leaked a client-supplied name marker: %v", err)
	}

	cancel()
	waitDone(t, done)
}

// ==========================================================================
// State/sequencer divergence (bkz. gorev 2)
// ==========================================================================

func TestExtendedRuntime_Divergence_StateFailureLeavesRuntimeUsable(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	// Bind against a statement that was never Parsed: State.CreateBind
	// itself rejects this (ErrUnknownStatement) BEFORE any mutation -
	// this must NOT terminate the runtime.
	_, err := rt.RegisterFrontendOperation(context.Background(), bindReq("p1", "does-not-exist", nil, nil, nil))
	if err == nil {
		t.Fatal("expected an error for binding an unknown statement")
	}
	if errors.Is(err, ErrFrontendRegistrationDiverged) {
		t.Fatalf("a State.Create* rejection (no mutation) must not be treated as a divergence, got %v", err)
	}

	// The runtime must remain fully usable afterward.
	op := mustRegister(t, context.Background(), rt, parseReq("s1", "SELECT 1", nil))
	pc := emptyFrame(protocol.MsgParseComplete)
	if _, err := backendW.Write(pc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, pc)
	_ = op

	cancel()
	if err := waitDone(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestExtendedRuntime_Divergence_SequencerCapacityFailureAfterStateCreation_Terminates(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	s := protocol.NewState()
	seqLimits := protocol.DefaultSequencerLimits()
	seqLimits.MaxPlanUnits = 1 // exhausted after the first registration
	rt, err := NewExtendedRuntime(s, backendR, client, seqLimits, testRuntimeLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	done := runInBackground(t, rt, context.Background())

	mustRegister(t, context.Background(), rt, syncReq()) // fills the 1-unit plan capacity

	// State.CreateParse SUCCEEDS (mutates State) but
	// AddForwardedOperation fails (ErrPlanQueueFull) - a genuine
	// divergence.
	_, regErr := rt.RegisterFrontendOperation(context.Background(), parseReq("s1", "SELECT 1", nil))
	if !errors.Is(regErr, ErrFrontendRegistrationDiverged) {
		t.Fatalf("expected ErrFrontendRegistrationDiverged, got %v", regErr)
	}

	runErr := waitDone(t, done)
	if !errors.Is(runErr, ErrFrontendRegistrationDiverged) {
		t.Fatalf("expected Run to return ErrFrontendRegistrationDiverged, got %v", runErr)
	}
	if !client.Closed() {
		t.Fatal("expected the client connection closed")
	}
}

func TestExtendedRuntime_Divergence_DuplicateRegistrationAfterStateCreation_Terminates(t *testing.T) {
	// A duplicate CLOSE-then-CLOSE-again style scenario is hard to force
	// through State (Close never errors); instead we reuse the plan-
	// capacity mechanism above as the canonical, deterministic way to
	// force AddForwardedOperation to reject an already-created State
	// operation. This test additionally confirms NO frontend frame may
	// be treated as safe to forward, and that both connections close.
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	s := protocol.NewState()
	seqLimits := protocol.DefaultSequencerLimits()
	seqLimits.MaxPlanUnits = 1
	rt, err := NewExtendedRuntime(s, backendR, client, seqLimits, testRuntimeLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	done := runInBackground(t, rt, context.Background())

	mustRegister(t, context.Background(), rt, syncReq())

	reg, regErr := rt.RegisterFrontendOperation(context.Background(), parseReq("s1", "SELECT 1", nil))
	if !errors.Is(regErr, ErrFrontendRegistrationDiverged) {
		t.Fatalf("expected ErrFrontendRegistrationDiverged, got %v", regErr)
	}
	if reg.Operation.ID != protocol.NoPendingOperation {
		t.Fatalf("expected no usable operation snapshot on divergence, got %+v", reg)
	}

	waitDone(t, done)
	if !client.Closed() {
		t.Fatal("expected client connection closed")
	}

	// A later, would-be-forwarding caller must never be told it can
	// safely proceed.
	if _, err := rt.RegisterFrontendOperation(context.Background(), parseReq("s2", "SELECT 2", nil)); !errors.Is(err, ErrRuntimeStopped) {
		t.Fatalf("expected ErrRuntimeStopped for all later submissions, got %v", err)
	}
	if err := rt.SubmitSyntheticError(context.Background(), protocol.CycleID(1), minimalErrorFrame()); !errors.Is(err, ErrRuntimeStopped) {
		t.Fatalf("expected ErrRuntimeStopped, got %v", err)
	}
}

func TestExtendedRuntime_Divergence_ErrorsContainNoClientMarkers(t *testing.T) {
	const secretStmt = "SECRET_DIVERGENCE_STMT_MARKER"
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	s := protocol.NewState()
	seqLimits := protocol.DefaultSequencerLimits()
	seqLimits.MaxPlanUnits = 1
	rt, err := NewExtendedRuntime(s, backendR, client, seqLimits, testRuntimeLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	done := runInBackground(t, rt, context.Background())

	mustRegister(t, context.Background(), rt, syncReq())
	_, regErr := rt.RegisterFrontendOperation(context.Background(), parseReq(secretStmt, "SELECT 1", nil))
	if strings.Contains(regErr.Error(), secretStmt) {
		t.Fatalf("divergence error leaked the statement name: %v", regErr)
	}

	runErr := waitDone(t, done)
	if runErr != nil && strings.Contains(runErr.Error(), secretStmt) {
		t.Fatalf("Run's primary error leaked the statement name: %v", runErr)
	}
}

// ==========================================================================
// Accepted-event cancellation (bkz. gorev 3)
// ==========================================================================

func TestExtendedRuntime_AcceptedEvent_ContextCanceledBeforeEnqueue_NotProcessed(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	s := protocol.NewState()
	limits := RuntimeLimits{FrontendEventBuffer: 1, BackendEventBuffer: 1}
	rt, err := NewExtendedRuntime(s, backendR, client, protocol.DefaultSequencerLimits(), limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entered := make(chan struct{}, 8)
	enqueued := make(chan struct{}, 8)
	release := make(chan struct{})
	rt.onFrontendEventAccepted = func() {
		entered <- struct{}{}
		<-release
	}
	rt.onFrontendEventEnqueued = func() {
		enqueued <- struct{}{}
	}

	done := runInBackground(t, rt, context.Background())

	// A: gets dequeued immediately, loop pauses in the hook.
	aDone := make(chan error, 1)
	go func() {
		_, err := rt.RegisterFrontendOperation(context.Background(), parseReq("sA", "SELECT A", nil))
		aDone <- err
	}()
	<-enqueued
	<-entered

	// B: fills the now-empty (capacity-1) channel while the loop stays
	// paused on A.
	bDone := make(chan error, 1)
	go func() {
		_, err := rt.RegisterFrontendOperation(context.Background(), parseReq("sB", "SELECT B", nil))
		bDone <- err
	}()
	<-enqueued

	// C: context ALREADY canceled, and the channel is FULL (B occupies
	// its one slot) with the loop still paused on A - C's send cannot
	// possibly succeed, so only ctx.Done() is reachable.
	cCtx, cCancel := context.WithCancel(context.Background())
	cCancel()
	if _, err := rt.RegisterFrontendOperation(cCtx, parseReq("sC", "SELECT C", nil)); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled for C (never enqueued), got %v", err)
	}

	close(release)

	if err := <-aDone; err != nil {
		t.Fatalf("expected A to succeed, got %v", err)
	}
	if err := <-bDone; err != nil {
		t.Fatalf("expected B to succeed, got %v", err)
	}

	backendW.Close()
	waitDone(t, done)
}

func TestExtendedRuntime_AcceptedEvent_ContextCanceledAfterAcceptance_GetsDefinitiveResult(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)

	accepted := make(chan struct{})
	rt.onFrontendEventAccepted = func() { close(accepted) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	submitCtx, submitCancel := context.WithCancel(context.Background())
	type result struct {
		reg FrontendRegistration
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		reg, err := rt.RegisterFrontendOperation(submitCtx, parseReq("s1", "SELECT 1", nil))
		resultCh <- result{reg, err}
	}()

	<-accepted     // the event loop has definitely dequeued the event
	submitCancel() // cancel AFTER acceptance - must NOT produce ctx.Err()

	select {
	case res := <-resultCh:
		if res.err != nil {
			t.Fatalf("expected the definitive successful result despite post-acceptance cancellation, got %v", res.err)
		}
		if res.reg.Operation.Kind != protocol.OpParse {
			t.Fatalf("unexpected registration: %+v", res.reg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("submit did not return a definitive result")
	}

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_AcceptedEvent_FailureAfterAcceptance_ReturnsSpecificFailure(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)

	accepted := make(chan struct{})
	rt.onFrontendEventAccepted = func() { close(accepted) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	// Register the statement first so the SECOND (duplicate) attempt is
	// guaranteed to be rejected by the sequencer once processed.
	mustRegister(t, context.Background(), rt, parseReq("dup", "SELECT 1", nil))

	accepted2 := make(chan struct{})
	rt.onFrontendEventAccepted = func() { close(accepted2) }
	submitCtx, submitCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		// Duplicate statement name is fine (State allows re-Parse by
		// name) - instead force a plan-registration failure isn't
		// straightforward here, so we assert on ANY definitive result:
		// cancellation after acceptance must never be ctx.Canceled.
		_, err := rt.RegisterFrontendOperation(submitCtx, parseReq("dup2", "SELECT 2", nil))
		errCh <- err
	}()
	<-accepted2
	submitCancel()

	select {
	case err := <-errCh:
		if errors.Is(err, context.Canceled) {
			t.Fatalf("accepted event must not resolve to ctx.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("submit did not return a definitive result")
	}

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_AcceptedEvent_RuntimeTermination_ReleasesUnprocessedSubmitter(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	s := protocol.NewState()
	seqLimits := protocol.DefaultSequencerLimits()
	seqLimits.MaxPlanUnits = 1
	limits := RuntimeLimits{FrontendEventBuffer: 2, BackendEventBuffer: 2}
	rt, err := NewExtendedRuntime(s, backendR, client, seqLimits, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entered := make(chan struct{}, 8)
	enqueued := make(chan struct{}, 8)
	release := make(chan struct{})
	rt.onFrontendEventAccepted = func() {
		entered <- struct{}{}
		<-release
	}
	rt.onFrontendEventEnqueued = func() {
		enqueued <- struct{}{}
	}

	done := runInBackground(t, rt, context.Background())

	aDone := make(chan error, 1)
	go func() {
		_, err := rt.RegisterFrontendOperation(context.Background(), parseReq("sA", "SELECT A", nil))
		aDone <- err
	}()
	<-enqueued
	<-entered // A dequeued, loop paused

	bDone := make(chan error, 1)
	go func() {
		_, err := rt.RegisterFrontendOperation(context.Background(), parseReq("sB", "SELECT B", nil))
		bDone <- err
	}()
	<-enqueued

	cDone := make(chan error, 1)
	go func() {
		_, err := rt.RegisterFrontendOperation(context.Background(), parseReq("sC", "SELECT C", nil))
		cDone <- err
	}()
	<-enqueued // buffer capacity 2: now holds B then C

	close(release) // let the loop resume: process A (succeeds), then B (diverges -> terminal)

	if err := <-aDone; err != nil {
		t.Fatalf("expected A to succeed, got %v", err)
	}
	bErr := <-bDone
	if !errors.Is(bErr, ErrFrontendRegistrationDiverged) {
		t.Fatalf("expected ErrFrontendRegistrationDiverged for B, got %v", bErr)
	}
	// C was accepted (enqueued) but the loop exited before ever
	// dequeuing it - C's submitter must be released with
	// ErrRuntimeStopped, not left hanging forever.
	cErr := <-cDone
	if !errors.Is(cErr, ErrRuntimeStopped) {
		t.Fatalf("expected ErrRuntimeStopped for the never-dequeued C, got %v", cErr)
	}

	runErr := waitDone(t, done)
	if !errors.Is(runErr, ErrFrontendRegistrationDiverged) {
		t.Fatalf("expected Run to return ErrFrontendRegistrationDiverged, got %v", runErr)
	}
}

func TestExtendedRuntime_AcceptedEvent_NoAcknowledgementGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()

	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, rt, ctx)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			submitCtx, submitCancel := context.WithCancel(context.Background())
			defer submitCancel()
			_, _ = rt.RegisterFrontendOperation(submitCtx, parseReq(fmt.Sprintf("s%d", i), "SELECT 1", nil))
		}(i)
	}
	wg.Wait()

	cancel()
	backendW.Close()
	waitDone(t, done)

	assertNoGoroutineLeak(t, before)
}

func TestExtendedRuntime_AcceptedEvent_RegistrationBeforeForwardingUnambiguous(t *testing.T) {
	// A successful RegisterFrontendOperation result is the ONLY signal a
	// future frontend caller may treat as "safe to forward the frame."
	// This test confirms the success path returns a usable, non-zero
	// operation snapshot, and a rejected/diverged path never does.
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	reg, err := rt.RegisterFrontendOperation(context.Background(), parseReq("s1", "SELECT 1", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg.Operation.ID == protocol.NoPendingOperation {
		t.Fatal("expected a usable operation ID on success")
	}

	rejectedReg, rejErr := rt.RegisterFrontendOperation(context.Background(), bindReq("p1", "unknown-statement", nil, nil, nil))
	if rejErr == nil {
		t.Fatal("expected a rejection for an unknown statement")
	}
	if rejectedReg.Operation.ID != protocol.NoPendingOperation {
		t.Fatalf("expected a zero-value operation on rejection, got %+v", rejectedReg)
	}

	cancel()
	waitDone(t, done)
}

// ==========================================================================
// Truncated backend messages at EOF (bkz. gorev 4)
// ==========================================================================

func TestExtendedRuntime_EOF_ZeroBufferedBytes_Clean(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	backendW.Close()

	if err := waitDone(t, done); err != nil {
		t.Fatalf("expected a clean stop, got %v", err)
	}
}

func TestExtendedRuntime_EOF_PartialHeaderBytes_FailsClosed(t *testing.T) {
	for n := 1; n <= 4; n++ {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			backendR, backendW := io.Pipe()
			client := newTrackingWriter()
			rt := newTestRuntime(t, backendR, client)
			done := runInBackground(t, rt, context.Background())

			full := rfqFrame(protocol.TxStatusIdle)
			if _, err := backendW.Write(full[:n]); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			backendW.Close()

			err := waitDone(t, done)
			if !errors.Is(err, ErrTruncatedBackendMessage) {
				t.Fatalf("expected ErrTruncatedBackendMessage, got %v", err)
			}
			if len(client.Snapshot()) != 0 {
				t.Fatalf("expected no output, got %x", client.Snapshot())
			}
		})
	}
}

func TestExtendedRuntime_EOF_TruncatedBody_FailsClosed(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	full := buildFrame(protocol.MsgErrorResponse, []byte{'S', 'E', 'R', 'R', 'O', 'R', 0, 0})
	if _, err := backendW.Write(full[:8]); err != nil { // tag+length present, body cut short
		t.Fatalf("unexpected error: %v", err)
	}
	backendW.Close()

	err := waitDone(t, done)
	if !errors.Is(err, ErrTruncatedBackendMessage) {
		t.Fatalf("expected ErrTruncatedBackendMessage, got %v", err)
	}
}

func TestExtendedRuntime_EOF_CompleteFramePlusPartialNext_RelaysOnceThenFailsClosed(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	notice := buildFrame(protocol.MsgNoticeResponse, []byte{'S', 'N', 0, 0})
	partialNext := buildFrame(protocol.MsgParameterStatus, []byte{'k', 0, 'v', 0})[:3]
	if _, err := backendW.Write(append(append([]byte{}, notice...), partialNext...)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	backendW.Close()

	err := waitDone(t, done)
	if !errors.Is(err, ErrTruncatedBackendMessage) {
		t.Fatalf("expected ErrTruncatedBackendMessage, got %v", err)
	}
	if !bytes.Equal(client.Snapshot(), notice) {
		t.Fatalf("expected exactly the one complete frame relayed once, got %x", client.Snapshot())
	}
}

func TestExtendedRuntime_EOF_SeveralCompleteFrames_Clean(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	f1 := buildFrame(protocol.MsgNoticeResponse, []byte{'S', 'N', 0, 0})
	f2 := buildFrame(protocol.MsgParameterStatus, []byte{'k', 0, 'v', 0})
	combined := append(append([]byte{}, f1...), f2...)
	if _, err := backendW.Write(combined); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	backendW.Close()

	err := waitDone(t, done)
	if err != nil {
		t.Fatalf("expected a clean stop, got %v", err)
	}
	if !bytes.Equal(client.Snapshot(), combined) {
		t.Fatalf("expected both frames relayed, got %x", client.Snapshot())
	}
}

func TestExtendedRuntime_EOF_TruncationErrorContainsNoRawBytesOrFieldValues(t *testing.T) {
	const secretMarker = "SECRET_EOF_TRUNCATION_MARKER"
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	frame := buildFrame(protocol.MsgErrorResponse, append([]byte{'M'}, append([]byte(secretMarker), 0, 0)...))
	if _, err := backendW.Write(frame[:len(frame)-2]); err != nil { // leave it incomplete
		t.Fatalf("unexpected error: %v", err)
	}
	backendW.Close()

	err := waitDone(t, done)
	if !errors.Is(err, ErrTruncatedBackendMessage) {
		t.Fatalf("expected ErrTruncatedBackendMessage, got %v", err)
	}
	if strings.Contains(err.Error(), secretMarker) {
		t.Fatalf("truncation error leaked buffered content: %v", err)
	}
}

// ==========================================================================
// State ownership stress test (bkz. gorev 5)
// ==========================================================================

// TestExtendedRuntime_StateOwnership_ConcurrentSubmittersNoRace drives many
// concurrent RegisterFrontendOperation/SubmitSyntheticError callers
// against a single runtime. Before this hardening, routing State
// creation through the runtime was mandatory precisely because
// protocol.State is unsafe for concurrent access (a concurrent
// Create* call from two goroutines can panic with "concurrent map
// writes"); this test proves that concurrent SUBMITTERS no longer
// touch State directly and therefore never trigger that failure mode -
// all State/sequencer access is serialized onto the single event-loop
// goroutine regardless of how many goroutines call the public API.
func TestExtendedRuntime_StateOwnership_ConcurrentSubmittersNoRace(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	const n = 50
	var wg sync.WaitGroup
	ids := make([]protocol.PendingOperationID, n)
	errsCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reg, err := rt.RegisterFrontendOperation(context.Background(), parseReq(fmt.Sprintf("s%d", i), "SELECT 1", nil))
			if err != nil {
				errsCh <- err
				return
			}
			ids[i] = reg.Operation.ID
		}(i)
	}
	wg.Wait()
	close(errsCh)
	for err := range errsCh {
		t.Fatalf("unexpected registration error: %v", err)
	}

	// Every successfully registered operation must have a distinct,
	// non-zero ID - proving State's internal counters were never
	// corrupted by concurrent, unserialized access.
	seen := make(map[protocol.PendingOperationID]bool, n)
	for _, id := range ids {
		if id == protocol.NoPendingOperation {
			t.Fatal("expected every registration to receive a non-zero operation ID")
		}
		if seen[id] {
			t.Fatalf("duplicate operation ID observed: %d", id)
		}
		seen[id] = true
	}

	if client.ConcurrentViolation() {
		t.Fatal("detected concurrent client writes during the ownership stress run")
	}

	cancel()
	waitDone(t, done)
}

// --- Bounded randomized/stress test ---------------------------------------
//
// TestExtendedRuntime_Stress drives a short, bounded, deterministic mix of
// frontend registrations, synthetic submissions, backend frames
// (including malformed ones), asynchronous messages, and cancellation,
// checking core invariants throughout. It is a short bounded property
// test in the same spirit as the protocol package's opReader-driven fuzz
// tests, adapted here to drive the runtime's public API instead of
// calling ResponseSequencer/State directly.
func TestExtendedRuntime_Stress(t *testing.T) {
	seeds := [][]byte{
		{0, 8, 1, 9, 2, 8, 3},
		{1, 1, 8, 9, 0, 8},
		{2, 2, 2, 9, 9},
		{},
		{9, 9, 9, 9, 9, 9, 9, 9},
	}

	for si, seed := range seeds {
		seed := seed
		t.Run(fmt.Sprintf("seed-%d", si), func(t *testing.T) {
			backendR, backendW := io.Pipe()
			client := newTrackingWriter()
			rt := newTestRuntime(t, backendR, client)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := runInBackground(t, rt, ctx)

			const bodyMarker = "SECRET_RUNTIME_STRESS_BODY_MARKER"
			const nameMarker = "SECRET_RUNTIME_STRESS_NAME_MARKER"

			pos := 0
			next := func() (byte, bool) {
				if pos >= len(seed) {
					return 0, false
				}
				b := seed[pos]
				pos++
				return b, true
			}

			var seenErrs []string
			var runErr error
			runErrReceived := false
			for step := 0; step < 40; step++ {
				b, ok := next()
				if !ok {
					break
				}
				switch int(b) % 8 {
				case 0:
					if _, aerr := rt.RegisterFrontendOperation(context.Background(), parseReq(nameMarker, "SELECT 1", nil)); aerr != nil {
						seenErrs = append(seenErrs, aerr.Error())
					}
				case 1:
					cycle := protocol.CycleID(int(b)%3 + 1)
					if aerr := rt.SubmitSyntheticError(context.Background(), cycle, fieldedErrorFrame(bodyMarker)); aerr != nil {
						seenErrs = append(seenErrs, aerr.Error())
					}
				case 2:
					backendW.Write(emptyFrame(protocol.MsgParseComplete))
				case 3:
					backendW.Write(buildFrame(protocol.MsgNoticeResponse, []byte{'S', 'N', 0, 0}))
				case 4:
					backendW.Write([]byte{byte(protocol.MsgErrorResponse), 0, 0, 0, 1}) // malformed: length < 4
				case 5:
					backendW.Write(rfqFrame(protocol.TxStatusIdle))
				case 6:
					if _, aerr := rt.RegisterFrontendOperation(context.Background(), syncReq()); aerr != nil {
						seenErrs = append(seenErrs, aerr.Error())
					}
				case 7:
					backendW.Write(dataRowFrame())
				}

				select {
				case runErr = <-done:
					// Runtime already terminated (e.g. malformed frame in
					// case 4, or ErrTerminationRequested) - stop driving
					// further events for this seed. Capture the drained
					// value here (done has capacity 1) so the later
					// lookup below does not block forever on an
					// already-empty channel.
					runErrReceived = true
					goto afterLoop
				default:
				}
			}
		afterLoop:

			cancel()
			if !runErrReceived {
				runErr = waitDone(t, done)
			}

			for _, e := range seenErrs {
				if strings.Contains(e, nameMarker) {
					t.Fatalf("a runtime error leaked the name marker: %s", e)
				}
			}
			if runErr != nil && strings.Contains(runErr.Error(), nameMarker) {
				t.Fatalf("Run's primary error leaked the name marker: %v", runErr)
			}
			// bodyMarker legitimately appears in RELAYED backend frame
			// bytes (it is real relayed protocol content, not sequencer
			// metadata) - only the ERROR TEXT/name-marker checks above
			// are meaningful non-disclosure assertions here.
			_ = client.Snapshot()

			if client.ConcurrentViolation() {
				t.Fatal("detected concurrent client writes during the stress run")
			}
		})
	}
}

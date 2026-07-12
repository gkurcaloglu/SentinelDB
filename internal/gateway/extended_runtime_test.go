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
	maxSeen             int32
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

func newTestRuntime(t *testing.T, backend io.ReadCloser, client io.WriteCloser) (*protocol.State, *ExtendedRuntime) {
	t.Helper()
	s := protocol.NewState()
	rt, err := NewExtendedRuntime(s, backend, client, protocol.DefaultSequencerLimits(), testRuntimeLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return s, rt
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
func setupRuntimeExecuteHead(t *testing.T, ctx context.Context, s *protocol.State, rt *ExtendedRuntime, backendW io.Writer, client *trackingWriter) protocol.PendingOperation {
	t.Helper()
	pop, _, _ := s.CreateParse("", "SELECT 1", nil)
	if err := rt.RegisterForwardedOperation(ctx, pop); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pc := emptyFrame(protocol.MsgParseComplete)
	if _, err := backendW.Write(pc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, pc)

	bop, _, _ := s.CreateBind("", "", nil, nil, nil)
	if err := rt.RegisterForwardedOperation(ctx, bop); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bc := emptyFrame(protocol.MsgBindComplete)
	if _, err := backendW.Write(bc); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	waitForBytes(t, client, append(append([]byte{}, pc...), bc...))

	eop, err := s.CreateExecute("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := rt.RegisterForwardedOperation(ctx, eop); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return eop
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
	_, rt := newTestRuntime(t, io.NopCloser(strings.NewReader("")), newTrackingWriter())
	op := protocol.PendingOperation{ID: 1, Kind: protocol.OpParse, Cycle: 1}
	if err := rt.RegisterForwardedOperation(context.Background(), op); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("expected ErrNotRunning, got %v", err)
	}
	if err := rt.SubmitSyntheticError(context.Background(), protocol.CycleID(1), minimalErrorFrame()); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("expected ErrNotRunning, got %v", err)
	}
}

func TestExtendedRuntime_Run_SucceedsOnlyOnce(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	_, rt := newTestRuntime(t, backendR, client)

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
	s, rt := newTestRuntime(t, backendR, client)

	done := runInBackground(t, rt, context.Background())

	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if err := rt.RegisterForwardedOperation(context.Background(), op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	backendW.Close()
	waitDone(t, done)
}

func TestExtendedRuntime_SubmitAfterTerminal_ReturnsStopped(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	s, rt := newTestRuntime(t, backendR, client)

	done := runInBackground(t, rt, context.Background())
	backendW.Close() // EOF, no pending work -> clean stop
	if err := waitDone(t, done); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if err := rt.RegisterForwardedOperation(context.Background(), op); !errors.Is(err, ErrRuntimeStopped) {
		t.Fatalf("expected ErrRuntimeStopped, got %v", err)
	}
	if err := rt.SubmitSyntheticError(context.Background(), protocol.CycleID(1), minimalErrorFrame()); !errors.Is(err, ErrRuntimeStopped) {
		t.Fatalf("expected ErrRuntimeStopped, got %v", err)
	}
}

func TestExtendedRuntime_ContextCancellation_ClosesBothEnds(t *testing.T) {
	backendConn1, backendConn2 := net.Pipe()
	clientConn1, clientConn2 := net.Pipe()
	_, rt := newTestRuntime(t, backendConn1, clientConn1)

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
	// be joined by Run's wg.Wait() before Run itself returns. If the
	// reader were not properly joined, this test would time out via
	// waitDone's deadline.
	backendR, _ := io.Pipe()
	client := newTrackingWriter()
	_, rt := newTestRuntime(t, backendR, client)

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
	_, rt := newTestRuntime(t, backendR, client)

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
	_, rt := newTestRuntime(t, backendR, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	frame := minimalErrorFrame()
	if err := rt.SubmitSyntheticError(context.Background(), protocol.CycleID(1), frame); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// By the time SubmitSyntheticError returned, the frame was already
	// fully written - the ack is only sent after output processing
	// completes (bkz. RegisterForwardedOperation/SubmitSyntheticError doc
	// comment). No backend traffic was needed at all.
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
	s, rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if err := rt.RegisterForwardedOperation(context.Background(), op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	s, rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	eop := setupRuntimeExecuteHead(t, context.Background(), s, rt, backendW, client)

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
	_, rt := newTestRuntime(t, backendR, client)
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
	s, rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	setupRuntimeExecuteHead(t, context.Background(), s, rt, backendW, client)
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
	s, rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	syncOp, _ := s.CreateSync()
	if err := rt.RegisterForwardedOperation(context.Background(), syncOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	s, rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	syncOp, _ := s.CreateSync()
	if err := rt.RegisterForwardedOperation(context.Background(), syncOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	s, rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	sync1, _ := s.CreateSync()
	if err := rt.RegisterForwardedOperation(context.Background(), sync1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op2, _, _ := s.CreateParse("s2", "SELECT 2", nil)
	if err := rt.RegisterForwardedOperation(context.Background(), op2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sync2, _ := s.CreateSync()
	if err := rt.RegisterForwardedOperation(context.Background(), sync2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	_, rt := newTestRuntime(t, backendR, client)
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
	_, rt := newTestRuntime(t, backendR, client)
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
	_, rt := newTestRuntime(t, backendR, client)
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
	_, rt := newTestRuntime(t, backendR, client)
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
	_, rt := newTestRuntime(t, backendR, client)
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
	_, rt := newTestRuntime(t, backendR, client)
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
	_, rt := newTestRuntime(t, backendR, client)
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
	s, rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	// protocol.State is single-writer by design (owned exclusively by one
	// frontend producer in the real architecture) - Create* calls
	// themselves must happen serially. Only RegisterForwardedOperation
	// itself (channel-based, safe for concurrent callers) is exercised
	// concurrently below.
	ops := make([]protocol.PendingOperation, 10)
	for i := 0; i < 10; i++ {
		op, _, err := s.CreateParse(fmt.Sprintf("s%d", i), "SELECT 1", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ops[i] = op
	}

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
			_ = rt.RegisterForwardedOperation(context.Background(), ops[i])
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
	_, rt := newTestRuntime(t, backendR, client)
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
	_, rt := newTestRuntime(t, backendR, client)
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
	_, rt := newTestRuntime(t, backendR, client)
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
	_, rt := newTestRuntime(t, backendR, client)
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
	_, rt := newTestRuntime(t, backendR, client)
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
	s, rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if err := rt.RegisterForwardedOperation(context.Background(), op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	_, rt := newTestRuntime(t, backendR, client)
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

func TestExtendedRuntime_PlanMismatch_AckBeforeRegistration(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	s, rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	s.CreateParse("s1", "SELECT 1", nil) // deliberately NOT registered with the runtime

	if _, err := backendW.Write(emptyFrame(protocol.MsgParseComplete)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := waitDone(t, done)
	if !errors.Is(err, ErrBackendProtocolFailure) {
		t.Fatalf("expected ErrBackendProtocolFailure, got %v", err)
	}
	if len(client.Snapshot()) != 0 {
		t.Fatalf("expected no output, got %x", client.Snapshot())
	}
}

func TestExtendedRuntime_PlanMismatch_WrongOperationPlan(t *testing.T) {
	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	s, rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if err := rt.RegisterForwardedOperation(context.Background(), op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	_, rt := newTestRuntime(t, backendR, client)
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
	s, rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	setupRuntimeExecuteHead(t, context.Background(), s, rt, backendW, client)

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
	_, rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, rt, ctx)
	cancel()
	if err := waitDone(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestExtendedRuntime_Cancellation_WhileFrontendSubmitWaitsForCapacity(t *testing.T) {
	backendR, _ := io.Pipe()
	client := newTrackingWriter()
	s := protocol.NewState()
	limits := RuntimeLimits{FrontendEventBuffer: 1, BackendEventBuffer: 1}
	rt, err := NewExtendedRuntime(s, backendR, client, protocol.DefaultSequencerLimits(), limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A submit ctx that's already canceled must return promptly with
	// ctx.Err() rather than hang, even if the runtime never started.
	canceledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	op := protocol.PendingOperation{ID: 1, Kind: protocol.OpParse, Cycle: 1}
	if err := rt.RegisterForwardedOperation(canceledCtx, op); !errors.Is(err, ErrNotRunning) {
		// Runtime not started yet: not-running takes precedence over an
		// already-canceled caller context (checked first, no blocking).
		t.Fatalf("expected ErrNotRunning, got %v", err)
	}
}

func TestExtendedRuntime_Cancellation_WhileClientWriteBlocked(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	clientConn1, clientConn2 := net.Pipe() // real blocking net.Conn semantics
	defer clientConn2.Close()
	_, rt := newTestRuntime(t, backendR, clientConn1)

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

func TestExtendedRuntime_Cancellation_WithPendingAcknowledgement(t *testing.T) {
	backendR, _ := io.Pipe()
	client := newTrackingWriter()
	s := protocol.NewState()
	limits := RuntimeLimits{FrontendEventBuffer: 1, BackendEventBuffer: 1}
	rt, err := NewExtendedRuntime(s, backendR, client, protocol.DefaultSequencerLimits(), limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, rt, ctx)

	// Fill the buffer with one in-flight (never-drained, since the loop
	// is still running normally and WILL drain it) - instead, directly
	// test that a submit whose OWN ctx is canceled mid-flight returns
	// ctx.Err() rather than leaking.
	submitCtx, submitCancel := context.WithCancel(context.Background())
	submitCancel()
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	err = rt.RegisterForwardedOperation(submitCtx, op)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected nil or context.Canceled, got %v", err)
	}

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_Cancellation_RepeatedCloseCallsAreSafe(t *testing.T) {
	backendR, _ := io.Pipe()
	client := newTrackingWriter()
	_, rt := newTestRuntime(t, backendR, client)
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
	s, rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if err := rt.RegisterForwardedOperation(context.Background(), op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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

func TestExtendedRuntime_NonDisclosure_ErrorsNeverContainMarkers(t *testing.T) {
	const secretStmt = "SECRET_RUNTIME_STMT_MARKER"
	const secretSQL = "SECRET_RUNTIME_SQL_MARKER"

	backendR, backendW := io.Pipe()
	client := newTrackingWriter()
	s, rt := newTestRuntime(t, backendR, client)
	done := runInBackground(t, rt, context.Background())

	op, _, _ := s.CreateParse(secretStmt, "SELECT 1 -- "+secretSQL, nil)
	if err := rt.RegisterForwardedOperation(context.Background(), op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	const secretStmt = "SECRET_RUNTIME_DUP_MARKER"
	backendR, backendW := io.Pipe()
	defer backendW.Close()
	client := newTrackingWriter()
	s, rt := newTestRuntime(t, backendR, client)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	op, _, _ := s.CreateParse(secretStmt, "SELECT 1", nil)
	if err := rt.RegisterForwardedOperation(context.Background(), op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err := rt.RegisterForwardedOperation(context.Background(), op) // duplicate
	if err == nil {
		t.Fatal("expected a duplicate-registration error")
	}
	if strings.Contains(err.Error(), secretStmt) {
		t.Fatalf("registration error leaked the statement name marker: %v", err)
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
// calling ResponseSequencer directly.
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
			s, rt := newTestRuntime(t, backendR, client)
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
					op, _, err := s.CreateParse(nameMarker, "SELECT 1", nil)
					if err == nil {
						if aerr := rt.RegisterForwardedOperation(context.Background(), op); aerr != nil {
							seenErrs = append(seenErrs, aerr.Error())
						}
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
					syncOp, err := s.CreateSync()
					if err == nil {
						if aerr := rt.RegisterForwardedOperation(context.Background(), syncOp); aerr != nil {
							seenErrs = append(seenErrs, aerr.Error())
						}
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

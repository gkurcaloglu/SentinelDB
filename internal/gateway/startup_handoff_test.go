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
	"testing"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// --- Test helpers: startup-style (tag-less, length-prefixed) frame builders

func startupFrame(code uint32, body []byte) []byte {
	total := 4 + 4 + len(body)
	out := make([]byte, 4, total)
	binary.BigEndian.PutUint32(out[0:4], uint32(total))
	codeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(codeBuf, code)
	out = append(out, codeBuf...)
	out = append(out, body...)
	return out
}

func sslRequestFrame() []byte    { return startupFrame(sslRequestCode, nil) }
func gssEncRequestFrame() []byte { return startupFrame(gssEncRequestCode, nil) }

func cancelRequestFrame(pid, secret uint32) []byte {
	body := make([]byte, 8)
	binary.BigEndian.PutUint32(body[0:4], pid)
	binary.BigEndian.PutUint32(body[4:8], secret)
	return startupFrame(cancelRequestCode, body)
}

// cancelRequestFrameWithKey builds a CancelRequest carrying an arbitrary-
// length secret key (bkz. PostgreSQL protocol 3.2 / PostgreSQL 18+) -
// unlike cancelRequestFrame, which always builds the legacy 4-byte key
// shape.
func cancelRequestFrameWithKey(pid uint32, key []byte) []byte {
	body := make([]byte, 4+len(key))
	binary.BigEndian.PutUint32(body[0:4], pid)
	copy(body[4:], key)
	return startupFrame(cancelRequestCode, body)
}

func startupParamBody(pairs ...string) []byte {
	var body []byte
	for _, p := range pairs {
		body = append(body, []byte(p)...)
		body = append(body, 0)
	}
	body = append(body, 0)
	return body
}

func startupMessageFrame(major, minor int16, pairs ...string) []byte {
	version := uint32(uint16(major))<<16 | uint32(uint16(minor))
	return startupFrame(version, startupParamBody(pairs...))
}

// startupMessageFrameRaw builds a StartupMessage frame around a caller-
// supplied RAW parameter body - used to construct deliberately malformed
// parameter areas that startupParamBody's pairs-based API cannot express.
func startupMessageFrameRaw(major, minor int16, rawParamBody []byte) []byte {
	version := uint32(uint16(major))<<16 | uint32(uint16(minor))
	return startupFrame(version, rawParamBody)
}

// --- Test helpers: normal (tag+length) frame builders for auth/startup ----

func authFrame(code uint32, extra []byte) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, code)
	body = append(body, extra...)
	return buildFrame(protocol.MsgAuthentication, body)
}

func authOkFrame() []byte        { return authFrame(authOk, nil) }
func authCleartextFrame() []byte { return authFrame(authCleartextPassword, nil) }
func authMD5Frame(salt [4]byte) []byte {
	return authFrame(authMD5Password, salt[:])
}
func authSASLFrame(mechanisms ...string) []byte {
	var body []byte
	for _, m := range mechanisms {
		body = append(body, []byte(m)...)
		body = append(body, 0)
	}
	body = append(body, 0)
	return authFrame(authSASL, body)
}
func authSASLContinueFrame(data []byte) []byte { return authFrame(authSASLContinue, data) }
func authSASLFinalFrame(data []byte) []byte    { return authFrame(authSASLFinal, data) }
func authGSSFrame() []byte                     { return authFrame(7, nil) } // AuthenticationGSS - unsupported

func passwordMessageFrame(payload []byte) []byte {
	return buildFrame(protocol.MsgPasswordMessage, payload)
}

func paramStatusFrame(key, value string) []byte {
	body := append(cstr(key), cstr(value)...)
	return buildFrame(protocol.MsgParameterStatus, body)
}

func backendKeyDataFrame(pid, secret uint32) []byte {
	body := make([]byte, 8)
	binary.BigEndian.PutUint32(body[0:4], pid)
	binary.BigEndian.PutUint32(body[4:8], secret)
	return buildFrame(protocol.MsgBackendKeyData, body)
}

// backendKeyDataFrameWithKey builds a BackendKeyData carrying an arbitrary-
// length secret key (bkz. PostgreSQL protocol 3.2 / PostgreSQL 18+) -
// unlike backendKeyDataFrame, which always builds the legacy 4-byte key
// shape.
func backendKeyDataFrameWithKey(pid uint32, key []byte) []byte {
	body := make([]byte, 4+len(key))
	binary.BigEndian.PutUint32(body[0:4], pid)
	copy(body[4:], key)
	return buildFrame(protocol.MsgBackendKeyData, body)
}

// randomKeyBytes returns a deterministic, non-zero byte slice of length n -
// used as a stand-in secret key; the exact bytes are never inspected by
// production code, only forwarded/relayed.
func randomKeyBytes(n int) []byte {
	key := make([]byte, n)
	for i := range key {
		key[i] = byte(0x41 + (i % 26))
	}
	return key
}

func noticeResponseFrame(text string) []byte {
	body := []byte{'S'}
	body = append(body, []byte("NOTICE")...)
	body = append(body, 0)
	body = append(body, 'M')
	body = append(body, []byte(text)...)
	body = append(body, 0)
	body = append(body, 0)
	return buildFrame(protocol.MsgNoticeResponse, body)
}

func negotiateProtocolVersionFrame() []byte {
	return buildFrame(protocol.MessageType('v'), make([]byte, 8))
}

// --- Test harness -----------------------------------------------------

type handoffOutcome struct {
	result StartupResult
	err    error
}

type handoffHarness struct {
	t      *testing.T
	cancel context.CancelFunc

	clientTest  net.Conn // test double for the REAL client
	backendTest net.Conn // test double for the REAL backend

	done chan handoffOutcome
}

func newHandoffHarnessWithLimits(t *testing.T, limits StartupLimits) *handoffHarness {
	t.Helper()
	clientHandoffSide, clientTestSide := net.Pipe()
	backendHandoffSide, backendTestSide := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan handoffOutcome, 1)
	go func() {
		res, err := RunStartupHandoff(ctx, clientHandoffSide, backendHandoffSide, limits)
		done <- handoffOutcome{res, err}
	}()

	return &handoffHarness{
		t: t, cancel: cancel,
		clientTest: clientTestSide, backendTest: backendTestSide,
		done: done,
	}
}

func newHandoffHarness(t *testing.T) *handoffHarness {
	return newHandoffHarnessWithLimits(t, DefaultStartupLimits())
}

func (h *handoffHarness) waitOutcome() handoffOutcome {
	h.t.Helper()
	select {
	case o := <-h.done:
		return o
	case <-time.After(2 * time.Second):
		h.t.Fatal("timed out waiting for RunStartupHandoff to return")
		return handoffOutcome{}
	}
}

// readExactly reads exactly n bytes from conn within a bounded deadline,
// failing the test on timeout/short read - used by tests to assert relayed
// bytes without racing the handoff goroutine.
func readExactly(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("failed to read %d bytes: %v", n, err)
	}
	conn.SetReadDeadline(time.Time{})
	return buf
}

func writeFrame(t *testing.T, conn net.Conn, frame []byte) {
	t.Helper()
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
}

func assertNoClientBytes(t *testing.T, h *handoffHarness) {
	t.Helper()
	h.clientTest.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := h.clientTest.Read(buf); err == nil {
		t.Fatal("expected no bytes written to the client")
	}
}

func assertNoBackendBytes(t *testing.T, h *handoffHarness) {
	t.Helper()
	h.backendTest.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := h.backendTest.Read(buf); err == nil {
		t.Fatal("expected no bytes forwarded to the backend")
	}
}

func assertNoBytesForwarded(t *testing.T, h *handoffHarness) {
	t.Helper()
	assertNoBackendBytes(t, h)
	assertNoClientBytes(t, h)
}

// ==========================================================================
// Framing (bkz. gorev 20 "Framing")
// ==========================================================================

func TestStartupHandoff_ExactStartupMessageForwarding(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	sm := startupMessageFrame(3, 0, "user", "alice", "database", "postgres")
	writeFrame(t, h.clientTest, sm)

	got := readExactly(t, h.backendTest, len(sm))
	if !bytes.Equal(got, sm) {
		t.Fatalf("expected the exact StartupMessage forwarded, got %x want %x", got, sm)
	}

	writeFrame(t, h.backendTest, authOkFrame())
	if got := readExactly(t, h.clientTest, len(authOkFrame())); !bytes.Equal(got, authOkFrame()) {
		t.Fatalf("expected AuthenticationOk relayed, got %x", got)
	}
	writeFrame(t, h.backendTest, rfqFrame(protocol.TxStatusIdle))
	if got := readExactly(t, h.clientTest, len(rfqFrame(protocol.TxStatusIdle))); !bytes.Equal(got, rfqFrame(protocol.TxStatusIdle)) {
		t.Fatalf("expected ReadyForQuery relayed, got %x", got)
	}

	o := h.waitOutcome()
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
	if o.result.ReadyStatus != protocol.TxStatusIdle || o.result.CancelOnly {
		t.Fatalf("unexpected result: %+v", o.result)
	}
}

func TestStartupHandoff_FragmentedStartupMessage(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	sm := startupMessageFrame(3, 0, "user", "alice")
	go func() {
		for _, b := range sm {
			h.clientTest.Write([]byte{b})
		}
	}()

	got := readExactly(t, h.backendTest, len(sm))
	if !bytes.Equal(got, sm) {
		t.Fatalf("expected the exact fragmented StartupMessage forwarded, got %x want %x", got, sm)
	}

	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))
	writeFrame(t, h.backendTest, rfqFrame(protocol.TxStatusIdle))
	readExactly(t, h.clientTest, len(rfqFrame(protocol.TxStatusIdle)))

	if o := h.waitOutcome(); o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_SeveralFramesCoalescedInOneWrite(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	sm := startupMessageFrame(3, 0, "user", "alice")
	pw := passwordMessageFrame([]byte("irrelevant-secret-bytes"))
	go func() {
		// Both the StartupMessage AND the (later) PasswordMessage are
		// written in ONE underlying Write - proves no read-ahead is lost
		// across the startup/auth boundary within the handoff itself.
		h.clientTest.Write(append(append([]byte{}, sm...), pw...))
	}()

	got := readExactly(t, h.backendTest, len(sm))
	if !bytes.Equal(got, sm) {
		t.Fatalf("expected exact StartupMessage, got %x", got)
	}
	writeFrame(t, h.backendTest, authCleartextFrame())
	readExactly(t, h.clientTest, len(authCleartextFrame()))

	gotPw := readExactly(t, h.backendTest, len(pw))
	if !bytes.Equal(gotPw, pw) {
		t.Fatalf("expected exact coalesced PasswordMessage forwarded, got %x want %x", gotPw, pw)
	}

	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))
	writeFrame(t, h.backendTest, rfqFrame(protocol.TxStatusIdle))
	readExactly(t, h.clientTest, len(rfqFrame(protocol.TxStatusIdle)))

	if o := h.waitOutcome(); o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_PartialStartupLength_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	writeFrame(t, h.clientTest, []byte{0, 0}) // only 2 of 4 length bytes
	h.clientTest.Close()

	o := h.waitOutcome()
	if o.err == nil {
		t.Fatal("expected an error for a partial startup length")
	}
}

func TestStartupHandoff_InvalidStartupLength_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 3) // below minStartupFrameLen(8)
	writeFrame(t, h.clientTest, lenBuf)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure, got %v", o.err)
	}
}

func TestStartupHandoff_TruncatedStartupBody_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	sm := startupMessageFrame(3, 0, "user", "alice")
	writeFrame(t, h.clientTest, sm[:len(sm)-3])
	h.clientTest.Close()

	o := h.waitOutcome()
	if o.err == nil {
		t.Fatal("expected an error for a truncated startup body")
	}
}

func TestStartupHandoff_NoPartialForwarding_OnTruncatedFrame(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	sm := startupMessageFrame(3, 0, "user", "alice")
	writeFrame(t, h.clientTest, sm[:len(sm)-3])
	h.clientTest.Close()
	h.waitOutcome()

	// The backend must never have received ANY bytes for the truncated
	// frame.
	h.backendTest.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := h.backendTest.Read(buf); err == nil {
		t.Fatal("expected no bytes forwarded to the backend for a truncated frame")
	}
}

func TestStartupHandoff_NoReadAheadPastOneFrame(t *testing.T) {
	// Client sends the StartupMessage followed IMMEDIATELY by extra bytes
	// that must NOT be consumed as part of the startup frame.
	h := newHandoffHarness(t)
	defer h.cancel()

	sm := startupMessageFrame(3, 0, "user", "alice")
	marker := []byte("SECRET_NOT_PART_OF_STARTUP_FRAME")
	go func() { h.clientTest.Write(append(append([]byte{}, sm...), marker...)) }()

	got := readExactly(t, h.backendTest, len(sm))
	if !bytes.Equal(got, sm) {
		t.Fatalf("expected exactly the StartupMessage bytes, got %x", got)
	}
	if bytes.Contains(got, marker) {
		t.Fatal("expected the marker bytes NOT to be included in the forwarded startup frame")
	}

	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))
	writeFrame(t, h.backendTest, rfqFrame(protocol.TxStatusIdle))
	readExactly(t, h.clientTest, len(rfqFrame(protocol.TxStatusIdle)))
	h.waitOutcome()
}

// ==========================================================================
// SSL/GSS (bkz. gorev 20 "SSL/GSS")
// ==========================================================================

func TestStartupHandoff_SSLRequest_RepliesN_NeverReachesBackend(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	writeFrame(t, h.clientTest, sslRequestFrame())
	got := readExactly(t, h.clientTest, 1)
	if got[0] != 'N' {
		t.Fatalf("expected 'N', got %q", got)
	}

	sm := startupMessageFrame(3, 0, "user", "alice")
	writeFrame(t, h.clientTest, sm)
	gotBackend := readExactly(t, h.backendTest, len(sm))
	if !bytes.Equal(gotBackend, sm) {
		t.Fatalf("expected only the StartupMessage forwarded, got %x", gotBackend)
	}

	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))
	writeFrame(t, h.backendTest, rfqFrame(protocol.TxStatusIdle))
	readExactly(t, h.clientTest, len(rfqFrame(protocol.TxStatusIdle)))
	if o := h.waitOutcome(); o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_GSSENCRequest_RepliesN_NeverReachesBackend(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	writeFrame(t, h.clientTest, gssEncRequestFrame())
	got := readExactly(t, h.clientTest, 1)
	if got[0] != 'N' {
		t.Fatalf("expected 'N', got %q", got)
	}

	sm := startupMessageFrame(3, 0, "user", "alice")
	writeFrame(t, h.clientTest, sm)
	gotBackend := readExactly(t, h.backendTest, len(sm))
	if !bytes.Equal(gotBackend, sm) {
		t.Fatalf("expected only the StartupMessage forwarded, got %x", gotBackend)
	}
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))
	writeFrame(t, h.backendTest, rfqFrame(protocol.TxStatusIdle))
	readExactly(t, h.clientTest, len(rfqFrame(protocol.TxStatusIdle)))
	if o := h.waitOutcome(); o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_RepeatedSSLProbes_AllReceiveN(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	for i := 0; i < 3; i++ {
		writeFrame(t, h.clientTest, sslRequestFrame())
		got := readExactly(t, h.clientTest, 1)
		if got[0] != 'N' {
			t.Fatalf("probe %d: expected 'N', got %q", i, got)
		}
	}
	sm := startupMessageFrame(3, 0, "user", "alice")
	writeFrame(t, h.clientTest, sm)
	readExactly(t, h.backendTest, len(sm))
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))
	writeFrame(t, h.backendTest, rfqFrame(protocol.TxStatusIdle))
	readExactly(t, h.clientTest, len(rfqFrame(protocol.TxStatusIdle)))
	if o := h.waitOutcome(); o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

// ==========================================================================
// CancelRequest (bkz. gorev 20 "CancelRequest")
// ==========================================================================

func TestStartupHandoff_CancelRequest_ForwardedOnce_NoRuntimeConstructed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	const markerPID, markerSecret = 0xDEADBEEF, 0xCAFEBABE
	cr := cancelRequestFrame(markerPID, markerSecret)
	writeFrame(t, h.clientTest, cr)

	got := readExactly(t, h.backendTest, len(cr))
	if !bytes.Equal(got, cr) {
		t.Fatalf("expected the exact CancelRequest forwarded once, got %x want %x", got, cr)
	}

	o := h.waitOutcome()
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
	if !o.result.CancelOnly {
		t.Fatal("expected CancelOnly=true")
	}
	// No backend response is ever awaited/relayed for a CancelRequest -
	// nothing further should have been written to the client.
	h.clientTest.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := h.clientTest.Read(buf); err == nil {
		t.Fatal("expected no bytes written to the client after a CancelRequest")
	}
}

func TestStartupHandoff_CancelRequest_WrongLength_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	// Total frame length below minCancelRequestBytes (16) - too short to
	// even hold the minimum 4-byte legacy secret key.
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, 15)
	frame = append(frame, make([]byte, 11)...) // code(4)+pid(4)+3 key bytes = 11, total 15
	binary.BigEndian.PutUint32(frame[4:8], cancelRequestCode)
	writeFrame(t, h.clientTest, frame)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a too-short CancelRequest, got %v", o.err)
	}
}

func TestStartupHandoff_CancelRequest_MarkersAbsentFromError(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	const markerPID, markerSecret = 0x1337, 0x7331
	cr := cancelRequestFrame(markerPID, markerSecret)
	writeFrame(t, h.clientTest, cr)
	readExactly(t, h.backendTest, len(cr))

	o := h.waitOutcome()
	if o.err != nil {
		msg := o.err.Error()
		if bytes.Contains([]byte(msg), []byte{0x13, 0x37}) || bytes.Contains([]byte(msg), []byte{0x73, 0x31}) {
			t.Fatalf("expected no PID/secret bytes in error, got %v", o.err)
		}
	}
}

// ==========================================================================
// Authentication (bkz. gorev 20 "Authentication")
// ==========================================================================

// runToStartupMessage forwards a minimal StartupMessage and returns after
// the backend side has received it, leaving both sides positioned to drive
// the authentication phase.
func runToStartupMessage(t *testing.T, h *handoffHarness) {
	t.Helper()
	sm := startupMessageFrame(3, 0, "user", "alice")
	writeFrame(t, h.clientTest, sm)
	readExactly(t, h.backendTest, len(sm))
}

func finishWithReadyForQuery(t *testing.T, h *handoffHarness, status byte) handoffOutcome {
	t.Helper()
	writeFrame(t, h.backendTest, rfqFrame(status))
	readExactly(t, h.clientTest, len(rfqFrame(status)))
	return h.waitOutcome()
}

func TestStartupHandoff_AuthenticationOk_NoPasswordRequested(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
	if o.result.ReadyStatus != protocol.TxStatusIdle {
		t.Fatalf("unexpected ReadyStatus: %q", o.result.ReadyStatus)
	}
}

func TestStartupHandoff_CleartextPassword_RelayedOnce(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authCleartextFrame())
	readExactly(t, h.clientTest, len(authCleartextFrame()))

	pw := passwordMessageFrame([]byte("SECRET_CLEARTEXT_MARKER"))
	writeFrame(t, h.clientTest, pw)
	got := readExactly(t, h.backendTest, len(pw))
	if !bytes.Equal(got, pw) {
		t.Fatalf("expected the exact PasswordMessage forwarded once, got %x want %x", got, pw)
	}

	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))
	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_MD5Password_RelayedOnce(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	salt := [4]byte{0x01, 0x02, 0x03, 0x04}
	af := authMD5Frame(salt)
	writeFrame(t, h.backendTest, af)
	readExactly(t, h.clientTest, len(af))

	pw := passwordMessageFrame([]byte("md5SECRET_MD5_RESPONSE_MARKER"))
	writeFrame(t, h.clientTest, pw)
	got := readExactly(t, h.backendTest, len(pw))
	if !bytes.Equal(got, pw) {
		t.Fatalf("expected the exact MD5 PasswordMessage forwarded once, got %x want %x", got, pw)
	}

	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))
	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_CompleteSASLExchange(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	saslReq := authSASLFrame("SCRAM-SHA-256")
	writeFrame(t, h.backendTest, saslReq)
	readExactly(t, h.clientTest, len(saslReq))

	initial := passwordMessageFrame([]byte("SCRAM-SHA-256\x00SECRET_CLIENT_FIRST_MARKER"))
	writeFrame(t, h.clientTest, initial)
	got := readExactly(t, h.backendTest, len(initial))
	if !bytes.Equal(got, initial) {
		t.Fatalf("expected exact SASLInitialResponse forwarded, got %x", got)
	}

	cont := authSASLContinueFrame([]byte("SECRET_SERVER_FIRST_MARKER"))
	writeFrame(t, h.backendTest, cont)
	readExactly(t, h.clientTest, len(cont))

	resp := passwordMessageFrame([]byte("SECRET_CLIENT_FINAL_MARKER"))
	writeFrame(t, h.clientTest, resp)
	got = readExactly(t, h.backendTest, len(resp))
	if !bytes.Equal(got, resp) {
		t.Fatalf("expected exact SASLResponse forwarded, got %x", got)
	}

	final := authSASLFinalFrame([]byte("SECRET_SERVER_FINAL_MARKER"))
	writeFrame(t, h.backendTest, final)
	readExactly(t, h.clientTest, len(final))
	// AuthenticationSASLFinal does NOT request another PasswordMessage.

	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))
	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_MultipleSASLContinueRounds(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authSASLFrame("SCRAM-SHA-256"))
	readExactly(t, h.clientTest, len(authSASLFrame("SCRAM-SHA-256")))

	initial := passwordMessageFrame([]byte("SCRAM-SHA-256\x00round0"))
	writeFrame(t, h.clientTest, initial)
	readExactly(t, h.backendTest, len(initial))

	for i := 0; i < 3; i++ {
		cont := authSASLContinueFrame([]byte{byte(i)})
		writeFrame(t, h.backendTest, cont)
		readExactly(t, h.clientTest, len(cont))

		resp := passwordMessageFrame([]byte{byte(i), byte(i)})
		writeFrame(t, h.clientTest, resp)
		got := readExactly(t, h.backendTest, len(resp))
		if !bytes.Equal(got, resp) {
			t.Fatalf("round %d: expected exact response forwarded, got %x", i, got)
		}
	}

	final := authSASLFinalFrame([]byte("done"))
	writeFrame(t, h.backendTest, final)
	readExactly(t, h.clientTest, len(final))
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))
	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_MalformedPasswordMessage_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authCleartextFrame())
	readExactly(t, h.clientTest, len(authCleartextFrame()))

	// Declares a length far bigger than the max allowed frame - a
	// malformed/oversized frame, never partially forwarded.
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 0xFFFFFFF0)
	writeFrame(t, h.clientTest, append([]byte{'p'}, lenBuf...))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure, got %v", o.err)
	}
}

func TestStartupHandoff_WrongFrontendTagWhileAuthResponseExpected_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authCleartextFrame())
	readExactly(t, h.clientTest, len(authCleartextFrame()))

	// Client sends a Query ('Q') instead of the expected PasswordMessage.
	writeFrame(t, h.clientTest, buildFrame(protocol.MsgQuery, cstr("SELECT 1")))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a wrong frontend tag, got %v", o.err)
	}
}

func TestStartupHandoff_UnsupportedAuthenticationCode_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	gf := authGSSFrame()
	writeFrame(t, h.backendTest, gf)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupUnsupportedAuth) {
		t.Fatalf("expected ErrStartupUnsupportedAuth, got %v", o.err)
	}
	// Authentication frames are now validated BEFORE relay (bkz. gorev 3) -
	// an unsupported code must never reach the client at all.
	h.clientTest.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := h.clientTest.Read(buf); err == nil {
		t.Fatal("expected no bytes relayed to the client for an unsupported authentication code")
	}
}

func TestStartupHandoff_AuthenticationErrorResponse_RelayedOnce(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	ef := fieldedErrorFrame("SECRET_AUTH_FAILURE_MARKER")
	writeFrame(t, h.backendTest, ef)
	got := readExactly(t, h.clientTest, len(ef))
	if !bytes.Equal(got, ef) {
		t.Fatalf("expected the ErrorResponse relayed exactly once, got %x want %x", got, ef)
	}

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupBackendErrorResponse) {
		t.Fatalf("expected ErrStartupBackendErrorResponse, got %v", o.err)
	}
}

func TestStartupHandoff_BackendEOFDuringAuthentication(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	h.backendTest.Close()

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupBackendEOF) {
		t.Fatalf("expected ErrStartupBackendEOF, got %v", o.err)
	}
}

func TestStartupHandoff_ClientEOFWhilePasswordExpected(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authCleartextFrame())
	readExactly(t, h.clientTest, len(authCleartextFrame()))

	h.clientTest.Close()

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupClientEOF) {
		t.Fatalf("expected ErrStartupClientEOF, got %v", o.err)
	}
}

// ==========================================================================
// Startup backend messages (bkz. gorev 20 "Startup backend messages")
// ==========================================================================

func TestStartupHandoff_ParameterStatusRelay(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	ps := paramStatusFrame("server_version", "16.0")
	writeFrame(t, h.backendTest, ps)
	got := readExactly(t, h.clientTest, len(ps))
	if !bytes.Equal(got, ps) {
		t.Fatalf("expected ParameterStatus relayed unchanged, got %x want %x", got, ps)
	}

	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_BackendKeyDataRelay(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	bkd := backendKeyDataFrame(4242, 0x1234)
	writeFrame(t, h.backendTest, bkd)
	got := readExactly(t, h.clientTest, len(bkd))
	if !bytes.Equal(got, bkd) {
		t.Fatalf("expected BackendKeyData relayed unchanged, got %x want %x", got, bkd)
	}

	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_NoticeResponseRelay(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	nr := noticeResponseFrame("SECRET_NOTICE_MARKER")
	writeFrame(t, h.backendTest, nr)
	got := readExactly(t, h.clientTest, len(nr))
	if !bytes.Equal(got, nr) {
		t.Fatalf("expected NoticeResponse relayed unchanged, got %x want %x", got, nr)
	}

	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_NegotiateProtocolVersionRelay(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	npv := negotiateProtocolVersionFrame()
	writeFrame(t, h.backendTest, npv)
	got := readExactly(t, h.clientTest, len(npv))
	if !bytes.Equal(got, npv) {
		t.Fatalf("expected NegotiateProtocolVersion relayed unchanged, got %x want %x", got, npv)
	}
	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

// TestStartupHandoff_FirstReadyForQuery_OnlyIdleSucceeds replaces the
// former "all three statuses are accepted" test (bkz. gorev 5): a freshly
// constructed protocol.State/ExtendedRuntime always starts idle, so the
// FIRST ReadyForQuery that completes a handoff can only ever legitimately
// report 'I' - 'T'/'E' are impossible for a truly initial ReadyForQuery and
// must fail closed, never be relayed to the client.
func TestStartupHandoff_FirstReadyForQuery_OnlyIdleSucceeds(t *testing.T) {
	t.Run("idle_succeeds", func(t *testing.T) {
		h := newHandoffHarness(t)
		defer h.cancel()
		runToStartupMessage(t, h)
		writeFrame(t, h.backendTest, authOkFrame())
		readExactly(t, h.clientTest, len(authOkFrame()))

		o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
		if o.err != nil {
			t.Fatalf("unexpected error: %v", o.err)
		}
		if o.result.ReadyStatus != protocol.TxStatusIdle {
			t.Fatalf("expected ReadyStatus=%q, got %q", protocol.TxStatusIdle, o.result.ReadyStatus)
		}
	})

	for _, status := range []byte{protocol.TxStatusInTransaction, protocol.TxStatusFailedTransaction} {
		status := status
		t.Run(string(status), func(t *testing.T) {
			h := newHandoffHarness(t)
			defer h.cancel()
			runToStartupMessage(t, h)
			writeFrame(t, h.backendTest, authOkFrame())
			readExactly(t, h.clientTest, len(authOkFrame()))

			writeFrame(t, h.backendTest, rfqFrame(status))
			o := h.waitOutcome()
			if !errors.Is(o.err, ErrStartupProtocolFailure) {
				t.Fatalf("expected ErrStartupProtocolFailure for a non-idle initial ReadyForQuery (status %q), got %v", status, o.err)
			}
			// Must never have been relayed to the client.
			h.clientTest.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			buf := make([]byte, 1)
			if _, err := h.clientTest.Read(buf); err == nil {
				t.Fatalf("expected no bytes relayed to the client for a non-idle initial ReadyForQuery (status %q)", status)
			}
		})
	}
}

func TestStartupHandoff_InvalidReadyForQueryBody_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	writeFrame(t, h.backendTest, buildFrame(protocol.MsgReadyForQuery, []byte{'X'})) // invalid status byte

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure, got %v", o.err)
	}
}

func TestStartupHandoff_UnexpectedBackendTypeBeforeReadyForQuery_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	// RowDescription ('T') is not a valid pre-ReadyForQuery startup
	// message.
	writeFrame(t, h.backendTest, buildFrame(protocol.MsgRowDescription, []byte{0, 0}))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure, got %v", o.err)
	}
}

func TestStartupHandoff_FirstReadyForQuery_NoFakeSyncOrExtraRFQ(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	rfq := rfqFrame(protocol.TxStatusIdle)
	writeFrame(t, h.backendTest, rfq)
	got := readExactly(t, h.clientTest, len(rfq))
	if !bytes.Equal(got, rfq) {
		t.Fatalf("expected exactly one ReadyForQuery relayed, got %x", got)
	}
	h.waitOutcome()

	// No further bytes must have been written to the client (no
	// fabricated second ReadyForQuery, no synthetic Sync-driven output).
	h.clientTest.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := h.clientTest.Read(buf); err == nil {
		t.Fatal("expected no additional bytes written to the client after the first ReadyForQuery")
	}
}

// ==========================================================================
// Cancellation (bkz. gorev 20 "Cancellation")
// ==========================================================================

func TestStartupHandoff_ContextCancellation_BlockedClientRead(t *testing.T) {
	h := newHandoffHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	_ = ctx
	_ = cancel
	// Nothing written by the client - handoff is blocked in its very
	// first client read.
	time.Sleep(20 * time.Millisecond)
	h.cancel()

	o := h.waitOutcome()
	if !errors.Is(o.err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", o.err)
	}
}

func TestStartupHandoff_ContextCancellation_BlockedBackendRead(t *testing.T) {
	h := newHandoffHarness(t)
	runToStartupMessage(t, h)
	// Backend never responds - handoff is blocked reading the first
	// Authentication frame.
	time.Sleep(20 * time.Millisecond)
	h.cancel()

	o := h.waitOutcome()
	if !errors.Is(o.err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", o.err)
	}
}

func TestStartupHandoff_ContextCancellation_BlockedClientWrite(t *testing.T) {
	// SSLRequest write-back to the client blocks because nothing ever
	// reads it (net.Pipe is synchronous) - proves a blocked WRITE also
	// unblocks on cancellation.
	h := newHandoffHarness(t)
	writeFrame(t, h.clientTest, sslRequestFrame())
	time.Sleep(20 * time.Millisecond)
	h.cancel()

	o := h.waitOutcome()
	if !errors.Is(o.err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", o.err)
	}
}

func TestStartupHandoff_ContextCancellation_BlockedBackendWrite(t *testing.T) {
	// The StartupMessage write to the backend blocks because nothing ever
	// reads it.
	h := newHandoffHarness(t)
	writeFrame(t, h.clientTest, startupMessageFrame(3, 0, "user", "alice"))
	time.Sleep(20 * time.Millisecond)
	h.cancel()

	o := h.waitOutcome()
	if !errors.Is(o.err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", o.err)
	}
}

func TestStartupHandoff_ContextCancellation_ClosesBothSides(t *testing.T) {
	h := newHandoffHarness(t)
	h.cancel()
	h.waitOutcome()

	if _, err := h.clientTest.Write([]byte{0}); err == nil {
		t.Fatal("expected the client-side handoff connection to be closed")
	}
	if _, err := h.backendTest.Write([]byte{0}); err == nil {
		t.Fatal("expected the backend-side handoff connection to be closed")
	}
}

func TestStartupHandoff_NoWatcherGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		h := newHandoffHarness(t)
		runToStartupMessage(t, h)
		writeFrame(t, h.backendTest, authOkFrame())
		readExactly(t, h.clientTest, len(authOkFrame()))
		o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
		if o.err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, o.err)
		}
		h.clientTest.Close()
		h.backendTest.Close()
	}
	assertNoGoroutineLeak(t, before)
}

func TestStartupHandoff_DeterministicPrimaryCause_InternalBeforeParent(t *testing.T) {
	h := newHandoffHarnessWithLimits(t, DefaultStartupLimits())
	// Malformed frame - a genuine internal failure, no cancellation
	// involved at all.
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 3)
	writeFrame(t, h.clientTest, lenBuf)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected the genuine protocol failure to remain primary, got %v", o.err)
	}
	h.cancel()
}

// ==========================================================================
// Section 1: startup-style request validation (bkz. gorev 1) - arbitrary
// unrecognized codes/malformed SSLRequest/GSSENCRequest/StartupMessage
// frames must never be forwarded upstream.
// ==========================================================================

func TestStartupHandoff_UnsupportedMajorVersion_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	sm := startupMessageFrame(2, 0, "user", "alice") // major version 2 - not major==3
	writeFrame(t, h.clientTest, sm)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for an unsupported major version, got %v", o.err)
	}
	assertNoBytesForwarded(t, h)
}

func TestStartupHandoff_MalformedParameterPair_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	raw := []byte("user\x00alice") // value string never terminated
	writeFrame(t, h.clientTest, startupMessageFrameRaw(3, 0, raw))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a malformed parameter pair, got %v", o.err)
	}
	assertNoBytesForwarded(t, h)
}

func TestStartupHandoff_MissingFinalTerminator_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	raw := []byte("user\x00alice\x00") // valid pair, but no final terminating NUL
	writeFrame(t, h.clientTest, startupMessageFrameRaw(3, 0, raw))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a missing final terminator, got %v", o.err)
	}
	assertNoBytesForwarded(t, h)
}

func TestStartupHandoff_NameWithoutValue_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	raw := []byte("user\x00") // name terminated, but the body ends right there
	writeFrame(t, h.clientTest, startupMessageFrameRaw(3, 0, raw))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a name without a value, got %v", o.err)
	}
	assertNoBytesForwarded(t, h)
}

func TestStartupHandoff_TrailingBytesAfterTerminator_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	raw := append(startupParamBody("user", "alice"), []byte("EXTRA")...)
	writeFrame(t, h.clientTest, startupMessageFrameRaw(3, 0, raw))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for trailing bytes after the terminator, got %v", o.err)
	}
	assertNoBytesForwarded(t, h)
}

func TestStartupHandoff_MissingUserParameter_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	sm := startupMessageFrame(3, 0, "database", "postgres")
	writeFrame(t, h.clientTest, sm)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a missing user parameter, got %v", o.err)
	}
	assertNoBytesForwarded(t, h)
}

func TestStartupHandoff_EmptyUserValue_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	// "user" is structurally present but its value is empty - must not
	// satisfy the "non-empty" requirement.
	sm := startupMessageFrame(3, 0, "user", "")
	writeFrame(t, h.clientTest, sm)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for an empty user value, got %v", o.err)
	}
	assertNoBytesForwarded(t, h)
}

func TestStartupHandoff_SSLRequest_WrongLength_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	frame := startupFrame(sslRequestCode, []byte{0, 0, 0, 0}) // 4 extra trailing bytes
	writeFrame(t, h.clientTest, frame)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a wrong-length SSLRequest, got %v", o.err)
	}
	assertNoClientBytes(t, h) // no 'N' reply for a malformed probe
	assertNoBackendBytes(t, h)
}

func TestStartupHandoff_GSSENCRequest_WrongLength_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	frame := startupFrame(gssEncRequestCode, []byte{0, 0, 0, 0})
	writeFrame(t, h.clientTest, frame)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a wrong-length GSSENCRequest, got %v", o.err)
	}
	assertNoClientBytes(t, h)
	assertNoBackendBytes(t, h)
}

func TestStartupHandoff_ArbitraryUnknownStartupCode_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	// Neither SSL/GSS/Cancel, nor major==3.
	frame := startupFrame(0x12345678, []byte("whatever"))
	writeFrame(t, h.clientTest, frame)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for an arbitrary unknown startup code, got %v", o.err)
	}
	assertNoBytesForwarded(t, h)
}

// ==========================================================================
// Section 2: NegotiateProtocolVersion in both valid phases (bkz. gorev 2)
// ==========================================================================

func TestStartupHandoff_NegotiateProtocolVersion_FullSASLSequence(t *testing.T) {
	// The mandatory sequence: StartupMessage -> NegotiateProtocolVersion ->
	// AuthenticationSASL -> AuthenticationSASLContinue ->
	// AuthenticationSASLFinal -> AuthenticationOk ->
	// ParameterStatus/BackendKeyData -> ReadyForQuery.
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	npv := negotiateProtocolVersionFrame()
	writeFrame(t, h.backendTest, npv)
	got := readExactly(t, h.clientTest, len(npv))
	if !bytes.Equal(got, npv) {
		t.Fatalf("expected NegotiateProtocolVersion relayed before any Authentication message, got %x", got)
	}

	saslReq := authSASLFrame("SCRAM-SHA-256")
	writeFrame(t, h.backendTest, saslReq)
	readExactly(t, h.clientTest, len(saslReq))

	initial := passwordMessageFrame([]byte("SCRAM-SHA-256\x00client-first"))
	writeFrame(t, h.clientTest, initial)
	readExactly(t, h.backendTest, len(initial))

	cont := authSASLContinueFrame([]byte("server-first"))
	writeFrame(t, h.backendTest, cont)
	readExactly(t, h.clientTest, len(cont))

	resp := passwordMessageFrame([]byte("client-final"))
	writeFrame(t, h.clientTest, resp)
	readExactly(t, h.backendTest, len(resp))

	final := authSASLFinalFrame([]byte("server-final"))
	writeFrame(t, h.backendTest, final)
	readExactly(t, h.clientTest, len(final))

	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	ps := paramStatusFrame("server_version", "16.0")
	writeFrame(t, h.backendTest, ps)
	readExactly(t, h.clientTest, len(ps))

	bkd := backendKeyDataFrame(1234, 5678)
	writeFrame(t, h.backendTest, bkd)
	readExactly(t, h.clientTest, len(bkd))

	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_MalformedNegotiateProtocolVersion_FailsClosed_BeforeAuth(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	// Declares 5 unsupported options but supplies none.
	body := make([]byte, 8)
	binary.BigEndian.PutUint32(body[4:8], 5)
	npv := buildFrame(protocol.MessageType('v'), body)
	writeFrame(t, h.backendTest, npv)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a malformed NegotiateProtocolVersion, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_MalformedNegotiateProtocolVersion_FailsClosed_AfterAuth(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	body := []byte{0, 0, 0, 0} // too short - missing the option-count field
	npv := buildFrame(protocol.MessageType('v'), body)
	writeFrame(t, h.backendTest, npv)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a malformed NegotiateProtocolVersion, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

// ==========================================================================
// Section 3: authentication state machine (bkz. gorev 3) - impossible
// sequences and malformed bodies must never be relayed.
// ==========================================================================

func TestStartupHandoff_SASLContinueBeforeSASL_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authSASLContinueFrame([]byte("x")))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for SASLContinue before SASL, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_SASLFinalBeforeSASL_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authSASLFinalFrame([]byte("x")))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for SASLFinal before SASL, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_SecondInitialMethod_AfterCleartext_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authCleartextFrame())
	readExactly(t, h.clientTest, len(authCleartextFrame()))
	pw := passwordMessageFrame([]byte("secret"))
	writeFrame(t, h.clientTest, pw)
	readExactly(t, h.backendTest, len(pw))

	// A second "initial method" frame after one has already begun.
	writeFrame(t, h.backendTest, authMD5Frame([4]byte{1, 2, 3, 4}))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a second initial method, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_CleartextAfterSASLExchange_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	saslReq := authSASLFrame("SCRAM-SHA-256")
	writeFrame(t, h.backendTest, saslReq)
	readExactly(t, h.clientTest, len(saslReq))
	initial := passwordMessageFrame([]byte("SCRAM-SHA-256\x00x"))
	writeFrame(t, h.clientTest, initial)
	readExactly(t, h.backendTest, len(initial))

	writeFrame(t, h.backendTest, authCleartextFrame())

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for Cleartext after a SASL exchange started, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_SASLAfterMD5Response_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	af := authMD5Frame([4]byte{9, 9, 9, 9})
	writeFrame(t, h.backendTest, af)
	readExactly(t, h.clientTest, len(af))
	pw := passwordMessageFrame([]byte("md5response"))
	writeFrame(t, h.clientTest, pw)
	readExactly(t, h.backendTest, len(pw))

	writeFrame(t, h.backendTest, authSASLFrame("SCRAM-SHA-256"))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for SASL after an MD5 response, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_RepeatedAuthenticationOk_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	// A second Authentication frame during the post-auth phase - never a
	// valid message type there.
	writeFrame(t, h.backendTest, authOkFrame())

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a repeated AuthenticationOk, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_AuthenticationOk_TrailingData_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authFrame(authOk, []byte{0xFF}))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for AuthenticationOk with trailing data, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_AuthenticationCleartext_TrailingData_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authFrame(authCleartextPassword, []byte{0xFF}))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for AuthenticationCleartextPassword with trailing data, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_AuthenticationMD5_WrongSaltLength_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authFrame(authMD5Password, []byte{1, 2, 3})) // only 3 salt bytes

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for AuthenticationMD5Password with a wrong-length salt, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_AuthenticationSASL_EmptyMechanismList_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authFrame(authSASL, nil)) // no mechanisms, no terminator at all

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for an empty SASL mechanism list, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_AuthenticationSASL_TrailingBytesAfterTerminator_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	body := append([]byte("SCRAM-SHA-256\x00\x00"), []byte("EXTRA")...)
	writeFrame(t, h.backendTest, authFrame(authSASL, body))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for trailing bytes after a SASL mechanism list terminator, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_UnsupportedAuth_DoesNotReadPasswordMessage(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	writeFrame(t, h.backendTest, authGSSFrame())

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupUnsupportedAuth) {
		t.Fatalf("expected ErrStartupUnsupportedAuth, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

// ==========================================================================
// Section 4: backend startup message validation (bkz. gorev 4)
// ==========================================================================

func TestStartupHandoff_MalformedParameterStatus_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	// Only one NUL-terminated string instead of the required two.
	body := append(cstr("server_version"), []byte("16.0")...) // second string never terminated
	writeFrame(t, h.backendTest, buildFrame(protocol.MsgParameterStatus, body))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a malformed ParameterStatus, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_MalformedBackendKeyData_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	writeFrame(t, h.backendTest, buildFrame(protocol.MsgBackendKeyData, []byte{1, 2, 3})) // wrong length

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a malformed BackendKeyData, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_MalformedNoticeResponse_FailsClosed(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	writeFrame(t, h.backendTest, buildFrame(protocol.MsgNoticeResponse, []byte{0})) // zero fields

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a malformed NoticeResponse (zero fields), got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_MalformedErrorResponse_FailsClosed_DuringAuth(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)

	// No field-code/terminator structure at all - just raw ASCII bytes.
	writeFrame(t, h.backendTest, buildFrame(protocol.MsgErrorResponse, []byte("no terminator or field code")))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a malformed ErrorResponse, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

// ==========================================================================
// Section 6: shutdown-causality linearization (bkz. gorev 6) - deterministic,
// hook/barrier-based races, never sleep-based.
// ==========================================================================

func TestStartupHandoff_Causality_ProtocolFailureBeforeParentCancellation(t *testing.T) {
	clientHandoffSide, clientTestSide := net.Pipe()
	backendHandoffSide, backendTestSide := net.Pipe()
	defer clientTestSide.Close()
	defer backendTestSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hooks := &causeHooks{onClaimed: func(v int32) {
		if v == causeInternal {
			cancel()
		}
	}}
	done := make(chan handoffOutcome, 1)
	go func() {
		res, err := runStartupHandoffInternal(ctx, clientHandoffSide, backendHandoffSide, DefaultStartupLimits(), hooks)
		done <- handoffOutcome{res, err}
	}()

	// Malformed startup length - a genuine internal protocol failure, with
	// cancellation triggered ONLY once the internal cause has already won
	// the race (from inside the hook, synchronously on the work goroutine).
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 3) // below minStartupFrameLen(8)
	writeFrame(t, clientTestSide, lenBuf)

	select {
	case o := <-done:
		if !errors.Is(o.err, ErrStartupProtocolFailure) {
			t.Fatalf("expected the protocol failure to remain primary despite a racing cancellation, got %v", o.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

func TestStartupHandoff_Causality_ClientWriteFailureBeforeParentCancellation(t *testing.T) {
	clientHandoffSide, clientTestSide := net.Pipe()
	backendHandoffSide, backendTestSide := net.Pipe()
	defer backendTestSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hooks := &causeHooks{onClaimed: func(v int32) {
		if v == causeInternal {
			cancel()
		}
	}}
	done := make(chan handoffOutcome, 1)
	go func() {
		res, err := runStartupHandoffInternal(ctx, clientHandoffSide, backendHandoffSide, DefaultStartupLimits(), hooks)
		done <- handoffOutcome{res, err}
	}()

	// This call returns only once the handoff has fully read the
	// SSLRequest - then we close the client test side so the handoff's
	// reply write ('N') deterministically fails.
	writeFrame(t, clientTestSide, sslRequestFrame())
	clientTestSide.Close()

	select {
	case o := <-done:
		if !errors.Is(o.err, ErrStartupClientWriteFailed) {
			t.Fatalf("expected the client write failure to remain primary despite a racing cancellation, got %v", o.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

func TestStartupHandoff_Causality_BackendWriteFailureBeforeParentCancellation(t *testing.T) {
	clientHandoffSide, clientTestSide := net.Pipe()
	backendHandoffSide, backendTestSide := net.Pipe()
	defer clientTestSide.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hooks := &causeHooks{onClaimed: func(v int32) {
		if v == causeInternal {
			cancel()
		}
	}}
	done := make(chan handoffOutcome, 1)
	go func() {
		res, err := runStartupHandoffInternal(ctx, clientHandoffSide, backendHandoffSide, DefaultStartupLimits(), hooks)
		done <- handoffOutcome{res, err}
	}()

	// Close the backend side FIRST, so the handoff's forward-to-backend
	// write of the StartupMessage deterministically fails.
	backendTestSide.Close()
	writeFrame(t, clientTestSide, startupMessageFrame(3, 0, "user", "alice"))

	select {
	case o := <-done:
		if !errors.Is(o.err, ErrStartupBackendWriteFailed) {
			t.Fatalf("expected the backend write failure to remain primary despite a racing cancellation, got %v", o.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
}

func TestStartupHandoff_Causality_ParentCancellationBeforeCloseInducedError(t *testing.T) {
	// The watcher claims causeParent (and only THEN closes both
	// transports) BEFORE any close-induced read/write error can occur in
	// the blocked work goroutine - this ordering is already deterministic
	// by construction (claim, then close), no hook needed.
	h := newHandoffHarness(t)
	// Nothing written by the client - handoff is blocked in its very
	// first client read.
	h.cancel()

	o := h.waitOutcome()
	if !errors.Is(o.err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", o.err)
	}
}

func TestStartupHandoff_Causality_SuccessBeforeParentCancellation(t *testing.T) {
	clientHandoffSide, clientTestSide := net.Pipe()
	backendHandoffSide, backendTestSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hooks := &causeHooks{onClaimed: func(v int32) {
		if v == causeSuccess {
			cancel()
		}
	}}
	done := make(chan handoffOutcome, 1)
	go func() {
		res, err := runStartupHandoffInternal(ctx, clientHandoffSide, backendHandoffSide, DefaultStartupLimits(), hooks)
		done <- handoffOutcome{res, err}
	}()

	sm := startupMessageFrame(3, 0, "user", "alice")
	writeFrame(t, clientTestSide, sm)
	readExactly(t, backendTestSide, len(sm))
	writeFrame(t, backendTestSide, authOkFrame())
	readExactly(t, clientTestSide, len(authOkFrame()))
	rfq := rfqFrame(protocol.TxStatusIdle)
	writeFrame(t, backendTestSide, rfq)
	readExactly(t, clientTestSide, len(rfq))
	// The instant the handoff finishes writing the RFQ above, it calls
	// cause.succeed() -> the hook fires -> cancel() runs SYNCHRONOUSLY, on
	// the handoff's own goroutine, racing its still-in-flight return path.

	var o handoffOutcome
	select {
	case o = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
	if o.err != nil {
		t.Fatalf("expected success to be preserved despite a racing cancellation, got %v", o.err)
	}
	if o.result.ReadyStatus != protocol.TxStatusIdle {
		t.Fatalf("unexpected result: %+v", o.result)
	}
	// Transports must remain open - the watcher's own causeParent claim
	// must have LOST the race, so it must never have closed anything.
	assertPipeStillOpen(t, clientTestSide)
	assertPipeStillOpen(t, backendTestSide)
	clientTestSide.Close()
	backendTestSide.Close()
}

// assertPipeStillOpen proves conn has NOT been closed by its peer, without
// assuming anyone is actively reading it (bkz. gorev 6 - a net.Pipe write
// blocks forever waiting for a reader regardless of open/closed state, so a
// plain Write cannot distinguish "open but unread" from "closed"; a closed
// pipe fails IMMEDIATELY with io.ErrClosedPipe, while an open-but-unread
// pipe blocks until the deadline and fails with a timeout error instead).
func assertPipeStillOpen(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	_, err := conn.Write([]byte{0})
	conn.SetWriteDeadline(time.Time{})
	if err == nil {
		return
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return
	}
	t.Fatalf("expected the transport to remain open, got %v", err)
}

func TestStartupHandoff_Causality_ParentCancellationJustBeforeSuccess(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	// Write the final ReadyForQuery from the backend side, but do NOT read
	// it from the client side - net.Pipe's Write blocks until fully
	// drained by the peer, so this call returns only once the HANDOFF has
	// consumed it (io.ReadFull) - a channel-based signal, not a sleep. The
	// handoff is then immediately about to (or already does) block trying
	// to write the RFQ to the client, which nothing ever reads; cancel()
	// races in against that pending write.
	rfq := rfqFrame(protocol.TxStatusIdle)
	writeDone := make(chan struct{})
	go func() {
		h.backendTest.Write(rfq)
		close(writeDone)
	}()
	<-writeDone
	h.cancel()

	o := h.waitOutcome()
	if !errors.Is(o.err, context.Canceled) {
		t.Fatalf("expected context.Canceled (cancellation linearized before the pending write could succeed), got %v", o.err)
	}
	// The watcher's claim won this race, so it must have closed both
	// transports.
	if _, err := h.clientTest.Write([]byte{0}); err == nil {
		t.Fatal("expected the client-side handoff connection to be closed")
	}
	if _, err := h.backendTest.Write([]byte{0}); err == nil {
		t.Fatal("expected the backend-side handoff connection to be closed")
	}
}

// ==========================================================================
// Section 7: fixed, safe startup errors/logs (bkz. gorev 7) - Transport is
// an interface; an injected/test implementation must never be able to leak
// arbitrary error text into RunStartupHandoff's returned error.
// ==========================================================================

type errorInjectingTransport struct {
	net.Conn
	failRead  error
	failWrite error
}

func (t *errorInjectingTransport) Read(p []byte) (int, error) {
	if t.failRead != nil {
		return 0, t.failRead
	}
	return t.Conn.Read(p)
}

func (t *errorInjectingTransport) Write(p []byte) (int, error) {
	if t.failWrite != nil {
		return 0, t.failWrite
	}
	return t.Conn.Write(p)
}

func assertMarkerAbsent(t *testing.T, err error, marker string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a non-nil error")
	}
	for _, formatted := range []string{
		fmt.Sprintf("%v", err),
		fmt.Sprintf("%+v", err),
		fmt.Sprintf("%#v", err),
	} {
		if strings.Contains(formatted, marker) {
			t.Fatalf("marker leaked into formatted error: %s", formatted)
		}
	}
}

func TestStartupHandoff_TransportErrorMarker_ClientReadFailure_NeverLeaks(t *testing.T) {
	marker := "MARKER_CLIENT_READ_9f3a"
	clientHandoffSide, _ := net.Pipe()
	backendHandoffSide, backendTestSide := net.Pipe()
	defer backendTestSide.Close()
	injectedClient := &errorInjectingTransport{Conn: clientHandoffSide, failRead: errors.New("boom: " + marker)}

	_, err := RunStartupHandoff(context.Background(), injectedClient, backendHandoffSide, DefaultStartupLimits())
	assertMarkerAbsent(t, err, marker)
	if !errors.Is(err, ErrStartupClientReadFailed) {
		t.Fatalf("expected ErrStartupClientReadFailed, got %v", err)
	}
}

func TestStartupHandoff_TransportErrorMarker_ClientWriteFailure_NeverLeaks(t *testing.T) {
	marker := "MARKER_CLIENT_WRITE_7c21"
	clientHandoffSide, clientTestSide := net.Pipe()
	backendHandoffSide, backendTestSide := net.Pipe()
	defer clientTestSide.Close()
	defer backendTestSide.Close()
	injectedClient := &errorInjectingTransport{Conn: clientHandoffSide, failWrite: errors.New("boom: " + marker)}

	done := make(chan error, 1)
	go func() {
		_, err := RunStartupHandoff(context.Background(), injectedClient, backendHandoffSide, DefaultStartupLimits())
		done <- err
	}()

	writeFrame(t, clientTestSide, sslRequestFrame())

	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
	assertMarkerAbsent(t, err, marker)
	if !errors.Is(err, ErrStartupClientWriteFailed) {
		t.Fatalf("expected ErrStartupClientWriteFailed, got %v", err)
	}
}

func TestStartupHandoff_TransportErrorMarker_BackendReadFailure_NeverLeaks(t *testing.T) {
	marker := "MARKER_BACKEND_READ_b810"
	clientHandoffSide, clientTestSide := net.Pipe()
	backendHandoffSide, backendTestSide := net.Pipe()
	defer clientTestSide.Close()
	defer backendTestSide.Close()
	injectedBackend := &errorInjectingTransport{Conn: backendHandoffSide, failRead: errors.New("boom: " + marker)}

	done := make(chan error, 1)
	go func() {
		_, err := RunStartupHandoff(context.Background(), clientHandoffSide, injectedBackend, DefaultStartupLimits())
		done <- err
	}()

	sm := startupMessageFrame(3, 0, "user", "alice")
	// The forward-to-backend write (failWrite is nil here, so it passes
	// through to the real pipe) must be drained, or it blocks forever with
	// no reader - only the SUBSEQUENT backend Read is instrumented to fail.
	// Uses io.ReadFull directly (not the t.Fatal-calling readExactly
	// helper, which must never run on a non-test goroutine).
	go func() { io.ReadFull(backendTestSide, make([]byte, len(sm))) }()
	writeFrame(t, clientTestSide, sm)

	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
	assertMarkerAbsent(t, err, marker)
	if !errors.Is(err, ErrStartupBackendReadFailed) {
		t.Fatalf("expected ErrStartupBackendReadFailed, got %v", err)
	}
}

func TestStartupHandoff_TransportErrorMarker_BackendWriteFailure_NeverLeaks(t *testing.T) {
	marker := "MARKER_BACKEND_WRITE_44de"
	clientHandoffSide, clientTestSide := net.Pipe()
	backendHandoffSide, _ := net.Pipe()
	defer clientTestSide.Close()
	injectedBackend := &errorInjectingTransport{Conn: backendHandoffSide, failWrite: errors.New("boom: " + marker)}

	done := make(chan error, 1)
	go func() {
		_, err := RunStartupHandoff(context.Background(), clientHandoffSide, injectedBackend, DefaultStartupLimits())
		done <- err
	}()

	sm := startupMessageFrame(3, 0, "user", "alice")
	writeFrame(t, clientTestSide, sm)

	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
	assertMarkerAbsent(t, err, marker)
	if !errors.Is(err, ErrStartupBackendWriteFailed) {
		t.Fatalf("expected ErrStartupBackendWriteFailed, got %v", err)
	}
}

// ==========================================================================
// Protocol 3.2 (PostgreSQL 18+) variable-length cancellation keys - bkz.
// PostgreSQL protocol documentation: BackendKeyData's and CancelRequest's
// secret key is no longer always 4 bytes; it now extends to the end of the
// message, 4 through 256 bytes inclusive. Protocol 3.0's legacy 4-byte key
// remains supported as the minimum-length case; the gateway does not branch
// on the StartupMessage's negotiated minor version - it accepts any key
// length in the documented range regardless.
// ==========================================================================

func TestStartupHandoff_BackendKeyData_4ByteKey_Accepted(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	bkd := backendKeyDataFrameWithKey(4242, randomKeyBytes(4))
	writeFrame(t, h.backendTest, bkd)
	got := readExactly(t, h.clientTest, len(bkd))
	if !bytes.Equal(got, bkd) {
		t.Fatalf("expected the legacy 4-byte-key BackendKeyData relayed unchanged, got %x want %x", got, bkd)
	}
	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_BackendKeyData_32ByteKey_Accepted(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	// PostgreSQL 18 currently sends 32-byte secret keys.
	bkd := backendKeyDataFrameWithKey(4242, randomKeyBytes(32))
	writeFrame(t, h.backendTest, bkd)
	got := readExactly(t, h.clientTest, len(bkd))
	if !bytes.Equal(got, bkd) {
		t.Fatalf("expected the 32-byte-key BackendKeyData relayed unchanged, got %x want %x", got, bkd)
	}
	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_BackendKeyData_256ByteKey_Accepted(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	// The documented upper bound.
	bkd := backendKeyDataFrameWithKey(4242, randomKeyBytes(256))
	writeFrame(t, h.backendTest, bkd)
	got := readExactly(t, h.clientTest, len(bkd))
	if !bytes.Equal(got, bkd) {
		t.Fatalf("expected the 256-byte-key BackendKeyData relayed unchanged, got %x want %x", got, bkd)
	}
	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
}

func TestStartupHandoff_BackendKeyData_3ByteKey_Rejected(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	writeFrame(t, h.backendTest, backendKeyDataFrameWithKey(4242, randomKeyBytes(3)))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a 3-byte BackendKeyData key, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_BackendKeyData_257ByteKey_Rejected(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	writeFrame(t, h.backendTest, backendKeyDataFrameWithKey(4242, randomKeyBytes(257)))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a 257-byte BackendKeyData key, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_BackendKeyData_TruncatedPID_Rejected(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	// Only 2 bytes total - cannot even hold a complete 4-byte PID.
	writeFrame(t, h.backendTest, buildFrame(protocol.MsgBackendKeyData, []byte{1, 2}))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a truncated BackendKeyData PID, got %v", o.err)
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_BackendKeyData_MarkersAbsentFromError(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()
	runToStartupMessage(t, h)
	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	const markerPID = 0xC0FFEE
	markerKey := []byte("SECRET_BACKEND_KEY_DATA_MARKER_9f3a")
	writeFrame(t, h.backendTest, backendKeyDataFrameWithKey(markerPID, append(markerKey, randomKeyBytes(300)...))) // oversized -> rejected

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure, got %v", o.err)
	}
	for _, formatted := range []string{fmt.Sprintf("%v", o.err), fmt.Sprintf("%+v", o.err), fmt.Sprintf("%#v", o.err)} {
		if strings.Contains(formatted, string(markerKey)) || strings.Contains(formatted, "C0FFEE") {
			t.Fatalf("PID/secret key leaked into formatted error: %s", formatted)
		}
	}
}

func TestStartupHandoff_CancelRequest_LegacyFourByteKey(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	cr := cancelRequestFrameWithKey(4242, randomKeyBytes(4))
	writeFrame(t, h.clientTest, cr)
	got := readExactly(t, h.backendTest, len(cr))
	if !bytes.Equal(got, cr) {
		t.Fatalf("expected the legacy 4-byte-key CancelRequest forwarded unchanged, got %x want %x", got, cr)
	}
	o := h.waitOutcome()
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
	if !o.result.CancelOnly {
		t.Fatal("expected CancelOnly=true")
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_CancelRequest_32ByteKey_Accepted(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	// PostgreSQL 18-style key length.
	cr := cancelRequestFrameWithKey(4242, randomKeyBytes(32))
	writeFrame(t, h.clientTest, cr)
	got := readExactly(t, h.backendTest, len(cr))
	if !bytes.Equal(got, cr) {
		t.Fatalf("expected the 32-byte-key CancelRequest forwarded unchanged, got %x want %x", got, cr)
	}
	o := h.waitOutcome()
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
	if !o.result.CancelOnly {
		t.Fatal("expected CancelOnly=true")
	}
	// No backend response is ever awaited/relayed, and no runtime is
	// constructed - nothing further should have been written to the
	// client.
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_CancelRequest_256ByteKey_Accepted(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	// The documented upper bound.
	cr := cancelRequestFrameWithKey(4242, randomKeyBytes(256))
	writeFrame(t, h.clientTest, cr)
	got := readExactly(t, h.backendTest, len(cr))
	if !bytes.Equal(got, cr) {
		t.Fatalf("expected the 256-byte-key CancelRequest forwarded unchanged, got %x want %x", got, cr)
	}
	o := h.waitOutcome()
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
	if !o.result.CancelOnly {
		t.Fatal("expected CancelOnly=true")
	}
	assertNoClientBytes(t, h)
}

func TestStartupHandoff_CancelRequest_3ByteKey_Rejected(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	writeFrame(t, h.clientTest, cancelRequestFrameWithKey(4242, randomKeyBytes(3)))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a 3-byte CancelRequest key, got %v", o.err)
	}
	assertNoBytesForwarded(t, h)
}

func TestStartupHandoff_CancelRequest_257ByteKey_Rejected(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	writeFrame(t, h.clientTest, cancelRequestFrameWithKey(4242, randomKeyBytes(257)))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a 257-byte CancelRequest key, got %v", o.err)
	}
	assertNoBytesForwarded(t, h)
}

func TestStartupHandoff_CancelRequest_MissingPIDAndKey_Rejected(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	// A CancelRequest-coded frame with NO PID/key material at all (total
	// frame is just length+code, 8 bytes - well below the 16-byte
	// minimum).
	frame := startupFrame(cancelRequestCode, nil)
	writeFrame(t, h.clientTest, frame)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a CancelRequest missing PID/key material, got %v", o.err)
	}
	assertNoBytesForwarded(t, h)
}

func TestStartupHandoff_CancelRequest_MarkersAbsentFromError_VariableKey(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	const markerPID = 0xDEADBEEF
	markerKey := []byte("SECRET_CANCEL_KEY_MARKER_7c21")
	// 257 bytes -> rejected, forcing an error path that must not leak the
	// PID/key.
	writeFrame(t, h.clientTest, cancelRequestFrameWithKey(markerPID, append(markerKey, randomKeyBytes(230)...)))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure, got %v", o.err)
	}
	for _, formatted := range []string{fmt.Sprintf("%v", o.err), fmt.Sprintf("%+v", o.err), fmt.Sprintf("%#v", o.err)} {
		if strings.Contains(formatted, string(markerKey)) || strings.Contains(formatted, "DEADBEEF") {
			t.Fatalf("PID/secret key leaked into formatted error: %s", formatted)
		}
	}
}

func TestStartupHandoff_Protocol32_FullStartupRegression(t *testing.T) {
	// StartupMessage version 3.2 -> supported authentication ->
	// AuthenticationOk -> BackendKeyData with a 32-byte key ->
	// ReadyForQuery('I') -> successful handoff.
	h := newHandoffHarness(t)
	defer h.cancel()

	sm := startupMessageFrame(3, 2, "user", "alice", "database", "postgres")
	writeFrame(t, h.clientTest, sm)
	got := readExactly(t, h.backendTest, len(sm))
	if !bytes.Equal(got, sm) {
		t.Fatalf("expected the protocol 3.2 StartupMessage forwarded unchanged, got %x want %x", got, sm)
	}

	writeFrame(t, h.backendTest, authOkFrame())
	readExactly(t, h.clientTest, len(authOkFrame()))

	bkd := backendKeyDataFrameWithKey(9001, randomKeyBytes(32))
	writeFrame(t, h.backendTest, bkd)
	gotBkd := readExactly(t, h.clientTest, len(bkd))
	if !bytes.Equal(gotBkd, bkd) {
		t.Fatalf("expected the protocol 3.2 BackendKeyData relayed unchanged, got %x want %x", gotBkd, bkd)
	}

	o := finishWithReadyForQuery(t, h, protocol.TxStatusIdle)
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
	if o.result.ReadyStatus != protocol.TxStatusIdle || o.result.CancelOnly {
		t.Fatalf("unexpected result: %+v", o.result)
	}
}

func TestStartupHandoff_Protocol32_CancelRequestRegression(t *testing.T) {
	// A CancelRequest using the protocol 3.2 variable-length key shape,
	// independent of any StartupMessage - CancelRequest carries no
	// protocol version of its own.
	h := newHandoffHarness(t)
	defer h.cancel()

	cr := cancelRequestFrameWithKey(9001, randomKeyBytes(32))
	writeFrame(t, h.clientTest, cr)
	got := readExactly(t, h.backendTest, len(cr))
	if !bytes.Equal(got, cr) {
		t.Fatalf("expected the protocol 3.2 CancelRequest forwarded unchanged, got %x want %x", got, cr)
	}

	o := h.waitOutcome()
	if o.err != nil {
		t.Fatalf("unexpected error: %v", o.err)
	}
	if !o.result.CancelOnly {
		t.Fatal("expected CancelOnly=true")
	}
	assertNoClientBytes(t, h)
}

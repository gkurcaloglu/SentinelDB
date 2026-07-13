package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
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

	sm := startupMessageFrame(3, 0)
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

	sm := startupMessageFrame(3, 0)
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
	sm := startupMessageFrame(3, 0)
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

	// Manually build an oversized "CancelRequest"-coded frame (extra
	// trailing bytes) - must be rejected, not silently absorbed.
	body := make([]byte, 12) // code(4) + pid(4) + secret(4) + 4 extra bytes below via length field
	binary.BigEndian.PutUint32(body[0:4], cancelRequestCode)
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, uint32(4+len(body)+4))
	frame = append(frame, body...)
	frame = append(frame, 0, 0, 0, 0) // 4 extra trailing bytes within the declared length
	writeFrame(t, h.clientTest, frame)

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupProtocolFailure) {
		t.Fatalf("expected ErrStartupProtocolFailure for a wrong-length CancelRequest, got %v", o.err)
	}
}

func TestStartupHandoff_CancelRequest_MarkersAbsentFromError(t *testing.T) {
	h := newHandoffHarness(t)
	defer h.cancel()

	const markerPID, markerSecret = 0x1337, 0x7331
	writeFrame(t, h.clientTest, cancelRequestFrame(markerPID, markerSecret))
	readExactly(t, h.backendTest, cancelRequestBytes)

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
	// The frame is relayed (like every other Authentication* frame) BEFORE
	// its code is validated - drain it so the handoff's writeAll doesn't
	// block forever on this synchronous pipe.
	readExactly(t, h.clientTest, len(gf))

	o := h.waitOutcome()
	if !errors.Is(o.err, ErrStartupUnsupportedAuth) {
		t.Fatalf("expected ErrStartupUnsupportedAuth, got %v", o.err)
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

func TestStartupHandoff_FirstReadyForQueryRelay_AllStatuses(t *testing.T) {
	for _, status := range []byte{protocol.TxStatusIdle, protocol.TxStatusInTransaction, protocol.TxStatusFailedTransaction} {
		status := status
		t.Run(string(status), func(t *testing.T) {
			h := newHandoffHarness(t)
			defer h.cancel()
			runToStartupMessage(t, h)
			writeFrame(t, h.backendTest, authOkFrame())
			readExactly(t, h.clientTest, len(authOkFrame()))

			o := finishWithReadyForQuery(t, h, status)
			if o.err != nil {
				t.Fatalf("unexpected error: %v", o.err)
			}
			if o.result.ReadyStatus != status {
				t.Fatalf("expected ReadyStatus=%q, got %q", status, o.result.ReadyStatus)
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
	writeFrame(t, h.clientTest, startupMessageFrame(3, 0))
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

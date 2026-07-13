package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/masking"
	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// --- Test helpers: backend RowDescription/ParameterDescription frames -----

type maskTestField struct {
	name       string
	formatCode int16
}

func beRowDescriptionFrame(fields []maskTestField) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, uint16(len(fields)))
	for _, f := range fields {
		body = append(body, []byte(f.name)...)
		body = append(body, 0)
		body = append(body, 0, 0, 0, 0)  // TableOID
		body = append(body, 0, 0)        // Attribute
		body = append(body, 0, 0, 0, 25) // DataTypeOID (text-ish)
		body = append(body, 0xFF, 0xFF)  // DataTypeSize -1
		body = append(body, 0, 0, 0, 0)  // TypeModifier
		fc := make([]byte, 2)
		binary.BigEndian.PutUint16(fc, uint16(f.formatCode))
		body = append(body, fc...)
	}
	return buildFrame(protocol.MsgRowDescription, body)
}

func beNoDataFrame() []byte { return emptyFrame(protocol.MsgNoData) }

func beParameterDescriptionFrame(oids []uint32) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, uint16(len(oids)))
	for _, o := range oids {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, o)
		body = append(body, b...)
	}
	return buildFrame(protocol.MsgParameterDescription, body)
}

func beDataRowFrame(cells []protocol.DataCell) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, uint16(len(cells)))
	for _, c := range cells {
		if c.Null {
			body = append(body, 0xFF, 0xFF, 0xFF, 0xFF)
			continue
		}
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(c.Value)))
		body = append(body, lenBuf...)
		body = append(body, c.Value...)
	}
	return buildFrame(protocol.MsgDataRow, body)
}

// --- Test helpers: fake Masker ---------------------------------------------

type maskCall struct{ column, value string }

type fakeMasker struct {
	mu       sync.Mutex
	maskFunc func(column, value string) (string, bool, error)
	calls    []maskCall
	lastCtx  context.Context

	// concurrency proof: tracks the maximum number of simultaneously
	// in-flight Mask calls observed.
	inFlight    int32
	maxInFlight int32

	// block, if non-nil, is closed by the FIRST Mask call the moment it
	// begins (via entered), then Mask blocks on ctx.Done() (context-aware
	// blocking, per "Document that Masker implementations are expected to
	// honor context cancellation").
	entered chan struct{}
	block   bool
	// waitBeforeReturn, if non-nil, is waited on AFTER ctx.Done() fires
	// but BEFORE Mask actually returns ctx.Err() - used to deterministically
	// prove "cause X linearized BEFORE the Masker returned" without a
	// sleep: a test closes waitBeforeReturn only after observing (via
	// ExtendedRuntime.onWatcherShutdownBegun) that the OTHER cause has
	// already won the shutdown-cause race.
	waitBeforeReturn chan struct{}
}

func (f *fakeMasker) Mask(ctx context.Context, column, kind, value string) (string, bool, string, error) {
	f.mu.Lock()
	f.inFlight++
	if f.inFlight > f.maxInFlight {
		f.maxInFlight = f.inFlight
	}
	f.lastCtx = ctx
	f.calls = append(f.calls, maskCall{column, value})
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()

	if f.block {
		if f.entered != nil {
			close(f.entered)
		}
		<-ctx.Done()
		if f.waitBeforeReturn != nil {
			<-f.waitBeforeReturn
		}
		return "", false, "", ctx.Err()
	}

	if f.maskFunc == nil {
		return value, false, "", nil
	}
	masked, changed, err := f.maskFunc(column, value)
	return masked, changed, "", err
}

func (f *fakeMasker) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func emailLikeFakeMasker() *fakeMasker {
	return &fakeMasker{
		maskFunc: func(column, value string) (string, bool, error) {
			if !strings.Contains(value, "@") {
				return value, false, nil
			}
			return "MASKED", true, nil
		},
	}
}

// --- Test helpers: masking-enabled runtime setup ---------------------------

func newMaskingTestRuntime(t *testing.T, backend BackendTransport, client io.WriteCloser, cfg masking.Config, masker masking.Masker) *ExtendedRuntime {
	t.Helper()
	s := protocol.NewState()
	rt, err := NewExtendedRuntimeWithMasking(s, backend, client, protocol.DefaultSequencerLimits(), testRuntimeLimits(),
		cfg, masker, masking.DefaultExtendedLimits(), masking.Hooks{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return rt
}

// ==========================================================================
// Constructor
// ==========================================================================

func TestNewExtendedRuntimeWithMasking_EnabledRequiresNonNilMasker(t *testing.T) {
	backendR, _ := io.Pipe()
	defer backendR.Close()
	_, err := NewExtendedRuntimeWithMasking(protocol.NewState(), newDuplexBackend(backendR), newTrackingWriter(),
		protocol.DefaultSequencerLimits(), testRuntimeLimits(), masking.NewConfig(true, []string{"email"}), nil,
		masking.DefaultExtendedLimits(), masking.Hooks{})
	if !errors.Is(err, ErrNilMasker) {
		t.Fatalf("expected ErrNilMasker, got %v", err)
	}
}

func TestNewExtendedRuntimeWithMasking_DisabledAllowsNilMasker(t *testing.T) {
	backendR, _ := io.Pipe()
	defer backendR.Close()
	rt, err := NewExtendedRuntimeWithMasking(protocol.NewState(), newDuplexBackend(backendR), newTrackingWriter(),
		protocol.DefaultSequencerLimits(), testRuntimeLimits(), masking.NewConfig(false, nil), nil,
		masking.DefaultExtendedLimits(), masking.Hooks{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rt.maskTracker != nil {
		t.Fatal("expected no masking tracker when masking is disabled")
	}
}

func TestNewExtendedRuntimeWithMasking_Enabled_CreatesTracker(t *testing.T) {
	backendR, _ := io.Pipe()
	defer backendR.Close()
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), newTrackingWriter(), masking.NewConfig(true, []string{"email"}), emailLikeFakeMasker())
	if rt.maskTracker == nil {
		t.Fatal("expected a masking tracker when masking is enabled")
	}
}

// ==========================================================================
// Shape observation + Execute preflight + DataRow masking (integration)
// ==========================================================================

// runMaskingFullCycle drives Parse -> ParseComplete -> Describe(statement)
// -> ParameterDescription -> RowDescription -> Bind -> BindComplete ->
// Execute -> DataRow -> CommandComplete -> Sync -> ReadyForQuery through a
// masking-enabled runtime and returns the final client-visible bytes.
func TestExtendedRuntime_Masking_StatementShape_MasksDataRow(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	mustRegisterForward(t, ctx, rt, parseReq("s1", "SELECT id, email FROM users", nil), feParseFrame("s1", "SELECT id, email FROM users", nil))
	pc := emptyFrame(protocol.MsgParseComplete)
	backendW.Write(pc)
	waitForBytes(t, client, pc)

	mustRegisterForward(t, ctx, rt, describeStmtReq("s1"), feDescribeFrame(protocol.TargetStatement, "s1"))
	pd := beParameterDescriptionFrame(nil)
	backendW.Write(pd)
	waitForBytes(t, client, append(append([]byte{}, pc...), pd...))

	rd := beRowDescriptionFrame([]maskTestField{{"id", 0}, {"email", 0}})
	backendW.Write(rd)
	afterRD := append(append([]byte{}, pc...), append(pd, rd...)...)
	waitForBytes(t, client, afterRD)

	mustRegisterForward(t, ctx, rt, bindReq("p1", "s1", nil, nil, nil), feBindFrame("p1", "s1", nil, nil, nil))
	bc := emptyFrame(protocol.MsgBindComplete)
	backendW.Write(bc)
	afterBC := append(append([]byte{}, afterRD...), bc...)
	waitForBytes(t, client, afterBC)

	mustRegisterForward(t, ctx, rt, executeReq("p1"), feExecuteFrame("p1", 0))
	dr := beDataRowFrame([]protocol.DataCell{{Value: []byte("1")}, {Value: []byte("john@example.com")}})
	backendW.Write(dr)

	wantMaskedRow, err := protocol.ParseDataRow(dr[5:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantMaskedRow, err = wantMaskedRow.WithCell(1, protocol.DataCell{Value: []byte("MASKED")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantMaskedBytes := wantMaskedRow.Build()

	waitForBytes(t, client, append(append([]byte{}, afterBC...), wantMaskedBytes...))
	if masker.callCount() != 1 {
		t.Fatalf("expected exactly 1 Mask call, got %d", masker.callCount())
	}

	cc := commandCompleteFrame("SELECT 1")
	backendW.Write(cc)
	afterCC := append(append([]byte{}, afterBC...), append(wantMaskedBytes, cc...)...)
	waitForBytes(t, client, afterCC)

	mustRegisterForward(t, ctx, rt, syncReq(), feSyncFrame())
	rfq := rfqFrame(protocol.TxStatusIdle)
	backendW.Write(rfq)
	waitForBytes(t, client, append(append([]byte{}, afterCC...), rfq...))

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_Masking_StatementDescribeNoData_AllowsExecute(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	mustRegisterForward(t, ctx, rt, parseReq("s1", "UPDATE users SET x=1", nil), feParseFrame("s1", "UPDATE users SET x=1", nil))
	backendW.Write(emptyFrame(protocol.MsgParseComplete))
	waitForBytes(t, client, emptyFrame(protocol.MsgParseComplete))

	mustRegisterForward(t, ctx, rt, describeStmtReq("s1"), feDescribeFrame(protocol.TargetStatement, "s1"))
	backendW.Write(beParameterDescriptionFrame(nil))
	backendW.Write(beNoDataFrame())
	want := append(append([]byte{}, emptyFrame(protocol.MsgParseComplete)...), append(beParameterDescriptionFrame(nil), beNoDataFrame()...)...)
	waitForBytes(t, client, want)

	mustRegisterForward(t, ctx, rt, bindReq("p1", "s1", nil, nil, nil), feBindFrame("p1", "s1", nil, nil, nil))
	backendW.Write(emptyFrame(protocol.MsgBindComplete))
	want = append(want, emptyFrame(protocol.MsgBindComplete)...)
	waitForBytes(t, client, want)

	if _, err := mustRegisterForwardErr(rt, ctx, executeReq("p1"), feExecuteFrame("p1", 0)); err != nil {
		t.Fatalf("expected known-NoData to allow Execute, got %v", err)
	}

	cancel()
	waitDone(t, done)
}

func mustRegisterForwardErr(rt *ExtendedRuntime, ctx context.Context, req FrontendOperationRequest, frame []byte) (FrontendRegistration, error) {
	return rt.RegisterAndForwardFrontendOperation(ctx, req, frame)
}

// TestExtendedRuntime_Masking_StatementNoData_UnexpectedDataRow_FailsTerminal
// proves the defense-in-depth guarantee from gorev 3: even though the
// correlator/sequencer layer alone cannot rule out a (protocol-impossible,
// e.g. hostile-backend) DataRow arriving for a portal whose underlying
// statement was Described as NoData, the masking layer's committed
// KnownNoData plan rejects it fail-closed rather than silently relaying it
// as an ordinary unmasked row.
func TestExtendedRuntime_Masking_StatementNoData_UnexpectedDataRow_FailsTerminal(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	mustRegisterForward(t, ctx, rt, parseReq("s1", "UPDATE users SET x=1", nil), feParseFrame("s1", "UPDATE users SET x=1", nil))
	backendW.Write(emptyFrame(protocol.MsgParseComplete))
	waitForBytes(t, client, emptyFrame(protocol.MsgParseComplete))

	mustRegisterForward(t, ctx, rt, describeStmtReq("s1"), feDescribeFrame(protocol.TargetStatement, "s1"))
	backendW.Write(beParameterDescriptionFrame(nil))
	backendW.Write(beNoDataFrame())
	want := append(append([]byte{}, emptyFrame(protocol.MsgParseComplete)...), append(beParameterDescriptionFrame(nil), beNoDataFrame()...)...)
	waitForBytes(t, client, want)

	mustRegisterForward(t, ctx, rt, bindReq("p1", "s1", nil, nil, nil), feBindFrame("p1", "s1", nil, nil, nil))
	backendW.Write(emptyFrame(protocol.MsgBindComplete))
	want = append(want, emptyFrame(protocol.MsgBindComplete)...)
	waitForBytes(t, client, want)

	if _, err := mustRegisterForwardErr(rt, ctx, executeReq("p1"), feExecuteFrame("p1", 0)); err != nil {
		t.Fatalf("expected known-NoData to allow Execute, got %v", err)
	}

	prefix := client.Snapshot()
	dr := beDataRowFrame([]protocol.DataCell{{Value: []byte("SECRET_IMPOSSIBLE_ROW_MARKER")}})
	backendW.Write(dr)

	runErr := waitDone(t, done)
	if !errors.Is(runErr, ErrExtendedMaskingFailed) {
		t.Fatalf("expected ErrExtendedMaskingFailed, got %v", runErr)
	}
	got := client.Snapshot()
	if bytes.Contains(got, dr) {
		t.Fatal("expected the unexpected DataRow never written to the client")
	}
	if !bytes.HasPrefix(got, prefix) || len(got) <= len(prefix) || protocol.MessageType(got[len(prefix)]) != protocol.MsgErrorResponse {
		t.Fatalf("expected exactly one FATAL ErrorResponse appended after the earlier valid frames, got %x", got[len(prefix):])
	}
}

// TestExtendedRuntime_Masking_PortalNoData_UnexpectedDataRow_FailsTerminal
// is the portal-level equivalent (portal Describe itself reports NoData,
// not merely the underlying statement).
func TestExtendedRuntime_Masking_PortalNoData_UnexpectedDataRow_FailsTerminal(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	mustRegisterForward(t, ctx, rt, parseReq("s1", "SELECT 1", nil), feParseFrame("s1", "SELECT 1", nil))
	backendW.Write(emptyFrame(protocol.MsgParseComplete))
	waitForBytes(t, client, emptyFrame(protocol.MsgParseComplete))

	mustRegisterForward(t, ctx, rt, bindReq("p1", "s1", nil, nil, nil), feBindFrame("p1", "s1", nil, nil, nil))
	backendW.Write(emptyFrame(protocol.MsgBindComplete))
	want := append(append([]byte{}, emptyFrame(protocol.MsgParseComplete)...), emptyFrame(protocol.MsgBindComplete)...)
	waitForBytes(t, client, want)

	mustRegisterForward(t, ctx, rt, describePortalReq("p1"), feDescribeFrame(protocol.TargetPortal, "p1"))
	backendW.Write(beNoDataFrame())
	want = append(want, beNoDataFrame()...)
	waitForBytes(t, client, want)

	if _, err := mustRegisterForwardErr(rt, ctx, executeReq("p1"), feExecuteFrame("p1", 0)); err != nil {
		t.Fatalf("expected known-NoData to allow Execute, got %v", err)
	}

	prefix := client.Snapshot()
	dr := beDataRowFrame([]protocol.DataCell{{Value: []byte("SECRET_IMPOSSIBLE_ROW_MARKER")}})
	backendW.Write(dr)

	runErr := waitDone(t, done)
	if !errors.Is(runErr, ErrExtendedMaskingFailed) {
		t.Fatalf("expected ErrExtendedMaskingFailed, got %v", runErr)
	}
	got := client.Snapshot()
	if bytes.Contains(got, dr) {
		t.Fatal("expected the unexpected DataRow never written to the client")
	}
	if !bytes.HasPrefix(got, prefix) || len(got) <= len(prefix) || protocol.MessageType(got[len(prefix)]) != protocol.MsgErrorResponse {
		t.Fatalf("expected exactly one FATAL ErrorResponse appended after the earlier valid frames, got %x", got[len(prefix):])
	}
}

func TestExtendedRuntime_Masking_PortalDescribeTakesPrecedenceOverStatement(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	mustRegisterForward(t, ctx, rt, parseReq("s1", "SELECT note", nil), feParseFrame("s1", "SELECT note", nil))
	backendW.Write(emptyFrame(protocol.MsgParseComplete))
	waitForBytes(t, client, emptyFrame(protocol.MsgParseComplete))

	// Statement shape has NO email column.
	mustRegisterForward(t, ctx, rt, describeStmtReq("s1"), feDescribeFrame(protocol.TargetStatement, "s1"))
	backendW.Write(beParameterDescriptionFrame(nil))
	backendW.Write(beRowDescriptionFrame([]maskTestField{{"note", 0}}))
	afterStmtDesc := append(append([]byte{}, emptyFrame(protocol.MsgParseComplete)...),
		append(beParameterDescriptionFrame(nil), beRowDescriptionFrame([]maskTestField{{"note", 0}})...)...)
	waitForBytes(t, client, afterStmtDesc)

	mustRegisterForward(t, ctx, rt, bindReq("p1", "s1", nil, nil, nil), feBindFrame("p1", "s1", nil, nil, nil))
	backendW.Write(emptyFrame(protocol.MsgBindComplete))
	afterBind := append(append([]byte{}, afterStmtDesc...), emptyFrame(protocol.MsgBindComplete)...)
	waitForBytes(t, client, afterBind)

	// Portal shape DOES have email - must take precedence.
	mustRegisterForward(t, ctx, rt, describePortalReq("p1"), feDescribeFrame(protocol.TargetPortal, "p1"))
	portalRD := beRowDescriptionFrame([]maskTestField{{"id", 0}, {"email", 0}})
	backendW.Write(portalRD)
	afterPortalDesc := append(append([]byte{}, afterBind...), portalRD...)
	waitForBytes(t, client, afterPortalDesc)

	mustRegisterForward(t, ctx, rt, executeReq("p1"), feExecuteFrame("p1", 0))
	dr := beDataRowFrame([]protocol.DataCell{{Value: []byte("1")}, {Value: []byte("a@example.com")}})
	backendW.Write(dr)

	row, _ := protocol.ParseDataRow(dr[5:])
	row, _ = row.WithCell(1, protocol.DataCell{Value: []byte("MASKED")})
	wantMasked := row.Build()
	waitForBytes(t, client, append(append([]byte{}, afterPortalDesc...), wantMasked...))

	cancel()
	waitDone(t, done)
}

// ==========================================================================
// Bind result-format expansion + preflight rejections
// ==========================================================================

func TestExtendedRuntime_Masking_UnknownShape_LocallyRejected_NoBackendWrite(t *testing.T) {
	backendR, _ := io.Pipe()
	defer backendR.Close()
	backend := newDuplexBackend(backendR)
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, backend, client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	// Parse + Bind, but NO Describe at all - shape is unknown.
	mustRegisterForward(t, ctx, rt, parseReq("s1", "SELECT 1", nil), feParseFrame("s1", "SELECT 1", nil))
	mustRegisterForward(t, ctx, rt, bindReq("p1", "s1", nil, nil, nil), feBindFrame("p1", "s1", nil, nil, nil))
	before := backend.Snapshot()

	_, err := rt.RegisterAndForwardFrontendOperation(ctx, executeReq("p1"), feExecuteFrame("p1", 0))
	if !errors.Is(err, ErrExtendedMaskingPreflightRejected) {
		t.Fatalf("expected ErrExtendedMaskingPreflightRejected, got %v", err)
	}
	if !bytes.Equal(backend.Snapshot(), before) {
		t.Fatalf("expected NO Execute bytes forwarded upstream, backend grew from %x to %x", before, backend.Snapshot())
	}

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_Masking_UnknownShape_MaskingDisabled_Allowed(t *testing.T) {
	backendR, _ := io.Pipe()
	defer backendR.Close()
	backend := newDuplexBackend(backendR)
	client := newTrackingWriter()
	rt := newMaskingTestRuntime(t, backend, client, masking.NewConfig(false, []string{"email"}), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	mustRegisterForward(t, ctx, rt, parseReq("s1", "SELECT 1", nil), feParseFrame("s1", "SELECT 1", nil))
	mustRegisterForward(t, ctx, rt, bindReq("p1", "s1", nil, nil, nil), feBindFrame("p1", "s1", nil, nil, nil))
	if _, err := rt.RegisterAndForwardFrontendOperation(ctx, executeReq("p1"), feExecuteFrame("p1", 0)); err != nil {
		t.Fatalf("expected Execute to be allowed when masking is disabled, got %v", err)
	}

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_Masking_BinaryTarget_LocallyRejected_BeforeStateMutation(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	backend := newDuplexBackend(backendR)
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, backend, client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	mustRegisterForward(t, ctx, rt, parseReq("s1", "SELECT id, email", nil), feParseFrame("s1", "SELECT id, email", nil))
	backendW.Write(emptyFrame(protocol.MsgParseComplete))
	waitForBytes(t, client, emptyFrame(protocol.MsgParseComplete))

	mustRegisterForward(t, ctx, rt, describeStmtReq("s1"), feDescribeFrame(protocol.TargetStatement, "s1"))
	backendW.Write(beParameterDescriptionFrame(nil))
	backendW.Write(beRowDescriptionFrame([]maskTestField{{"id", 0}, {"email", 0}}))
	want := append(append([]byte{}, emptyFrame(protocol.MsgParseComplete)...),
		append(beParameterDescriptionFrame(nil), beRowDescriptionFrame([]maskTestField{{"id", 0}, {"email", 0}})...)...)
	waitForBytes(t, client, want)

	// Bind requests BINARY format for the email (target) column.
	mustRegisterForward(t, ctx, rt, bindReq("p1", "s1", nil, nil, []int16{0, 1}), feBindFrame("p1", "s1", nil, nil, []int16{0, 1}))
	backendW.Write(emptyFrame(protocol.MsgBindComplete))
	want = append(want, emptyFrame(protocol.MsgBindComplete)...)
	waitForBytes(t, client, want)

	before := backend.Snapshot()
	_, err := rt.RegisterAndForwardFrontendOperation(ctx, executeReq("p1"), feExecuteFrame("p1", 0))
	if !errors.Is(err, ErrExtendedMaskingPreflightRejected) {
		t.Fatalf("expected ErrExtendedMaskingPreflightRejected for a binary masking target, got %v", err)
	}
	if !bytes.Equal(backend.Snapshot(), before) {
		t.Fatal("expected no Execute bytes forwarded upstream for a rejected binary target")
	}
	if masker.callCount() != 0 {
		t.Fatal("expected the masker never invoked for a rejected binary target")
	}

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_Masking_BinaryNonTarget_Allowed(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	mustRegisterForward(t, ctx, rt, parseReq("s1", "SELECT id, email", nil), feParseFrame("s1", "SELECT id, email", nil))
	backendW.Write(emptyFrame(protocol.MsgParseComplete))
	waitForBytes(t, client, emptyFrame(protocol.MsgParseComplete))

	mustRegisterForward(t, ctx, rt, describeStmtReq("s1"), feDescribeFrame(protocol.TargetStatement, "s1"))
	backendW.Write(beParameterDescriptionFrame(nil))
	backendW.Write(beRowDescriptionFrame([]maskTestField{{"id", 0}, {"email", 0}}))
	want := append(append([]byte{}, emptyFrame(protocol.MsgParseComplete)...),
		append(beParameterDescriptionFrame(nil), beRowDescriptionFrame([]maskTestField{{"id", 0}, {"email", 0}})...)...)
	waitForBytes(t, client, want)

	// id (non-target) is binary(1); email (target) stays text(0).
	mustRegisterForward(t, ctx, rt, bindReq("p1", "s1", nil, nil, []int16{1, 0}), feBindFrame("p1", "s1", nil, nil, []int16{1, 0}))
	backendW.Write(emptyFrame(protocol.MsgBindComplete))
	want = append(want, emptyFrame(protocol.MsgBindComplete)...)
	waitForBytes(t, client, want)

	if _, err := rt.RegisterAndForwardFrontendOperation(ctx, executeReq("p1"), feExecuteFrame("p1", 0)); err != nil {
		t.Fatalf("expected a binary non-target column to be allowed, got %v", err)
	}

	cancel()
	waitDone(t, done)
}

// ==========================================================================
// DataRow masking failure / FATAL behavior
// ==========================================================================

func TestExtendedRuntime_Masking_MissingPlanAtDataRow_FailsTerminal(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	// Use plain RegisterFrontendOperation (bypasses the masking preflight
	// entirely, unlike RegisterAndForwardFrontendOperation) to deliberately
	// create an Execute with NO committed plan - proving the DataRow-time
	// defense (transformDataRowAction) ALSO fails closed, independent of
	// the preflight.
	mustRegister(t, ctx, rt, parseReq("", "SELECT 1", nil))
	backendW.Write(emptyFrame(protocol.MsgParseComplete))
	waitForBytes(t, client, emptyFrame(protocol.MsgParseComplete))
	mustRegister(t, ctx, rt, bindReq("", "", nil, nil, nil))
	backendW.Write(emptyFrame(protocol.MsgBindComplete))
	want := append(append([]byte{}, emptyFrame(protocol.MsgParseComplete)...), emptyFrame(protocol.MsgBindComplete)...)
	waitForBytes(t, client, want)
	mustRegister(t, ctx, rt, executeReq(""))

	dr := beDataRowFrame([]protocol.DataCell{{Value: []byte("john@example.com")}})
	backendW.Write(dr)

	runErr := waitDone(t, done)
	if !errors.Is(runErr, ErrExtendedMaskingFailed) {
		t.Fatalf("expected ErrExtendedMaskingFailed, got %v", runErr)
	}
	if bytes.Contains(client.Snapshot(), dr) {
		t.Fatal("expected the unmasked DataRow never written to the client")
	}
	if !bytes.HasSuffix(client.Snapshot(), []byte{}) {
		// sanity: at minimum the earlier valid frames plus a FATAL must
		// have been written.
	}
	got := client.Snapshot()
	if len(got) <= len(want) {
		t.Fatalf("expected a FATAL ErrorResponse appended after the earlier valid frames, got %x", got)
	}
	if protocol.MessageType(got[len(want)]) != protocol.MsgErrorResponse {
		t.Fatalf("expected the appended frame to be an ErrorResponse, got tag %q", got[len(want)])
	}
	_ = cancel
}

func TestExtendedRuntime_Masking_MaskerError_FatalThenCloses(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := &fakeMasker{maskFunc: func(column, value string) (string, bool, error) {
		return "", false, errors.New("plugin crashed")
	}}
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	eop := setupMaskingExecuteHead(t, ctx, rt, backendW, client, "s1", "p1", []maskTestField{{"email", 0}})
	_ = eop

	dr := beDataRowFrame([]protocol.DataCell{{Value: []byte("john@example.com")}})
	prefix := client.Snapshot()
	backendW.Write(dr)

	runErr := waitDone(t, done)
	if !errors.Is(runErr, ErrExtendedMaskingFailed) {
		t.Fatalf("expected ErrExtendedMaskingFailed, got %v", runErr)
	}
	got := client.Snapshot()
	if !bytes.HasPrefix(got, prefix) {
		t.Fatalf("expected earlier valid frames preserved, got %x want prefix %x", got, prefix)
	}
	if bytes.Contains(got[len(prefix):], dr) {
		t.Fatal("expected the unmasked DataRow never written")
	}
	if len(got) <= len(prefix) || protocol.MessageType(got[len(prefix)]) != protocol.MsgErrorResponse {
		t.Fatalf("expected exactly one FATAL ErrorResponse appended, got %x", got[len(prefix):])
	}
	if bytes.Contains(got[len(prefix):], []byte{byte(protocol.MsgReadyForQuery)}) {
		// weak byte check refined by structural scan below
	}
	for off := len(prefix); off < len(got); {
		if off+5 > len(got) {
			break
		}
		length := binary.BigEndian.Uint32(got[off+1 : off+5])
		total := 1 + int(length)
		if protocol.MessageType(got[off]) == protocol.MsgReadyForQuery {
			t.Fatal("expected no ReadyForQuery to be fabricated after a masking failure")
		}
		off += total
	}
}

// setupMaskingExecuteHead drives Parse -> ParseComplete -> Describe(stmt)
// -> ParamDesc -> RowDescription(fields) -> Bind -> BindComplete -> Execute
// through a masking-enabled runtime, leaving the sequencer head at Execute
// and returning that operation.
func setupMaskingExecuteHead(t *testing.T, ctx context.Context, rt *ExtendedRuntime, backendW io.Writer, client *trackingWriter, stmtName, portalName string, fields []maskTestField) protocol.CorrelatedOperation {
	t.Helper()
	mustRegisterForward(t, ctx, rt, parseReq(stmtName, "SELECT 1", nil), feParseFrame(stmtName, "SELECT 1", nil))
	backendW.Write(emptyFrame(protocol.MsgParseComplete))
	waitForBytes(t, client, emptyFrame(protocol.MsgParseComplete))

	mustRegisterForward(t, ctx, rt, describeStmtReq(stmtName), feDescribeFrame(protocol.TargetStatement, stmtName))
	backendW.Write(beParameterDescriptionFrame(nil))
	backendW.Write(beRowDescriptionFrame(fields))
	want := append(append([]byte{}, emptyFrame(protocol.MsgParseComplete)...),
		append(beParameterDescriptionFrame(nil), beRowDescriptionFrame(fields)...)...)
	waitForBytes(t, client, want)

	mustRegisterForward(t, ctx, rt, bindReq(portalName, stmtName, nil, nil, nil), feBindFrame(portalName, stmtName, nil, nil, nil))
	backendW.Write(emptyFrame(protocol.MsgBindComplete))
	want = append(want, emptyFrame(protocol.MsgBindComplete)...)
	waitForBytes(t, client, want)

	return mustRegisterForward(t, ctx, rt, executeReq(portalName), feExecuteFrame(portalName, 0))
}

// ==========================================================================
// Multi-portal isolation / PortalSuspended-resume
// ==========================================================================

func TestExtendedRuntime_Masking_TwoPortals_DifferentShapes_NoCrossContamination(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	mustRegisterForward(t, ctx, rt, parseReq("s1", "SELECT email", nil), feParseFrame("s1", "SELECT email", nil))
	backendW.Write(emptyFrame(protocol.MsgParseComplete))
	waitForBytes(t, client, emptyFrame(protocol.MsgParseComplete))

	// Portal A: has an email column via its OWN portal Describe.
	mustRegisterForward(t, ctx, rt, bindReq("pa", "s1", nil, nil, nil), feBindFrame("pa", "s1", nil, nil, nil))
	backendW.Write(emptyFrame(protocol.MsgBindComplete))
	afterBindA := append(append([]byte{}, emptyFrame(protocol.MsgParseComplete)...), emptyFrame(protocol.MsgBindComplete)...)
	waitForBytes(t, client, afterBindA)
	mustRegisterForward(t, ctx, rt, describePortalReq("pa"), feDescribeFrame(protocol.TargetPortal, "pa"))
	rdA := beRowDescriptionFrame([]maskTestField{{"email", 0}})
	backendW.Write(rdA)
	afterDescA := append(append([]byte{}, afterBindA...), rdA...)
	waitForBytes(t, client, afterDescA)

	// Portal B: NO email column.
	mustRegisterForward(t, ctx, rt, bindReq("pb", "s1", nil, nil, nil), feBindFrame("pb", "s1", nil, nil, nil))
	backendW.Write(emptyFrame(protocol.MsgBindComplete))
	afterBindB := append(append([]byte{}, afterDescA...), emptyFrame(protocol.MsgBindComplete)...)
	waitForBytes(t, client, afterBindB)
	mustRegisterForward(t, ctx, rt, describePortalReq("pb"), feDescribeFrame(protocol.TargetPortal, "pb"))
	rdB := beRowDescriptionFrame([]maskTestField{{"note", 0}})
	backendW.Write(rdB)
	afterDescB := append(append([]byte{}, afterBindB...), rdB...)
	waitForBytes(t, client, afterDescB)

	// Execute A: email masked.
	mustRegisterForward(t, ctx, rt, executeReq("pa"), feExecuteFrame("pa", 0))
	drA := beDataRowFrame([]protocol.DataCell{{Value: []byte("a@example.com")}})
	backendW.Write(drA)
	rowA, _ := protocol.ParseDataRow(drA[5:])
	rowA, _ = rowA.WithCell(0, protocol.DataCell{Value: []byte("MASKED")})
	afterA := append(append([]byte{}, afterDescB...), rowA.Build()...)
	waitForBytes(t, client, afterA)
	backendW.Write(commandCompleteFrame("SELECT 1"))
	afterCCA := append(append([]byte{}, afterA...), commandCompleteFrame("SELECT 1")...)
	waitForBytes(t, client, afterCCA)

	// Execute B: note column, NOT an email target - unchanged, no Mask call.
	beforeB := masker.callCount()
	mustRegisterForward(t, ctx, rt, executeReq("pb"), feExecuteFrame("pb", 0))
	drB := beDataRowFrame([]protocol.DataCell{{Value: []byte("plain text with @ in it")}})
	backendW.Write(drB)
	afterB := append(append([]byte{}, afterCCA...), drB...)
	waitForBytes(t, client, afterB)
	if masker.callCount() != beforeB {
		t.Fatalf("expected no additional Mask call for portal B (no target columns), got %d new calls", masker.callCount()-beforeB)
	}

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_Masking_PortalSuspended_PreservesPlan_ResumedExecuteMasks(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	eop := setupMaskingExecuteHead(t, ctx, rt, backendW, client, "s1", "p1", []maskTestField{{"email", 0}})
	_ = eop

	dr1 := beDataRowFrame([]protocol.DataCell{{Value: []byte("a@example.com")}})
	row1, _ := protocol.ParseDataRow(dr1[5:])
	row1, _ = row1.WithCell(0, protocol.DataCell{Value: []byte("MASKED")})
	prefix := client.Snapshot()
	backendW.Write(dr1)
	waitForBytes(t, client, append(append([]byte{}, prefix...), row1.Build()...))
	afterDR1 := client.Snapshot()

	backendW.Write(emptyFrame(protocol.MsgPortalSuspended))
	waitForBytes(t, client, append(append([]byte{}, afterDR1...), emptyFrame(protocol.MsgPortalSuspended)...))
	afterSuspend := client.Snapshot()

	// Resume: a fresh Execute of the SAME portal must still mask.
	mustRegisterForward(t, ctx, rt, executeReq("p1"), feExecuteFrame("p1", 0))
	dr2 := beDataRowFrame([]protocol.DataCell{{Value: []byte("b@example.com")}})
	backendW.Write(dr2)
	row2, _ := protocol.ParseDataRow(dr2[5:])
	row2, _ = row2.WithCell(0, protocol.DataCell{Value: []byte("MASKED")})
	waitForBytes(t, client, append(append([]byte{}, afterSuspend...), row2.Build()...))

	cancel()
	waitDone(t, done)
}

// ==========================================================================
// Lifecycle: unnamed portal replacement does not inherit old plan
// ==========================================================================

func TestExtendedRuntime_Masking_UnnamedPortalReplacement_DoesNotInheritOldPlan(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	// First unnamed statement+portal: has an email column, gets Executed
	// and masked.
	mustRegisterForward(t, ctx, rt, parseReq("", "SELECT email", nil), feParseFrame("", "SELECT email", nil))
	backendW.Write(emptyFrame(protocol.MsgParseComplete))
	waitForBytes(t, client, emptyFrame(protocol.MsgParseComplete))

	mustRegisterForward(t, ctx, rt, describeStmtReq(""), feDescribeFrame(protocol.TargetStatement, ""))
	backendW.Write(beParameterDescriptionFrame(nil))
	backendW.Write(beRowDescriptionFrame([]maskTestField{{"email", 0}}))
	afterDesc1 := append(append([]byte{}, emptyFrame(protocol.MsgParseComplete)...),
		append(beParameterDescriptionFrame(nil), beRowDescriptionFrame([]maskTestField{{"email", 0}})...)...)
	waitForBytes(t, client, afterDesc1)

	mustRegisterForward(t, ctx, rt, bindReq("", "", nil, nil, nil), feBindFrame("", "", nil, nil, nil))
	backendW.Write(emptyFrame(protocol.MsgBindComplete))
	afterBind1 := append(append([]byte{}, afterDesc1...), emptyFrame(protocol.MsgBindComplete)...)
	waitForBytes(t, client, afterBind1)

	// REPLACE the unnamed statement+portal with a fresh one that has NO
	// Describe at all - a completely different shape (unknown).
	mustRegisterForward(t, ctx, rt, parseReq("", "SELECT plain_col", nil), feParseFrame("", "SELECT plain_col", nil))
	backendW.Write(emptyFrame(protocol.MsgParseComplete))
	afterParse2 := append(append([]byte{}, afterBind1...), emptyFrame(protocol.MsgParseComplete)...)
	waitForBytes(t, client, afterParse2)

	mustRegisterForward(t, ctx, rt, bindReq("", "", nil, nil, nil), feBindFrame("", "", nil, nil, nil))
	backendW.Write(emptyFrame(protocol.MsgBindComplete))
	afterBind2 := append(append([]byte{}, afterParse2...), emptyFrame(protocol.MsgBindComplete)...)
	waitForBytes(t, client, afterBind2)

	// Executing the NEW unnamed portal (unknown shape) must be locally
	// rejected - NOT silently inherit the old portal's "email" plan.
	_, err := rt.RegisterAndForwardFrontendOperation(ctx, executeReq(""), feExecuteFrame("", 0))
	if !errors.Is(err, ErrExtendedMaskingPreflightRejected) {
		t.Fatalf("expected the replacement unnamed portal to have an unknown (not inherited) shape, got %v", err)
	}

	cancel()
	waitDone(t, done)
}

// ==========================================================================
// Concurrency / cancellation
// ==========================================================================

func TestExtendedRuntime_Masking_OnlyOneMaskCallAtATime(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := emailLikeFakeMasker()
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	setupMaskingExecuteHead(t, ctx, rt, backendW, client, "s1", "p1", []maskTestField{{"email", 0}})

	prefix := client.Snapshot()
	for i := 0; i < 5; i++ {
		backendW.Write(beDataRowFrame([]protocol.DataCell{{Value: []byte("x@example.com")}}))
	}
	deadline := time.Now().Add(2 * time.Second)
	for masker.callCount() < 5 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if masker.callCount() != 5 {
		t.Fatalf("expected 5 Mask calls, got %d", masker.callCount())
	}
	masker.mu.Lock()
	maxInFlight := masker.maxInFlight
	masker.mu.Unlock()
	if maxInFlight != 1 {
		t.Fatalf("expected at most 1 concurrent Mask call, observed max %d", maxInFlight)
	}
	_ = prefix

	cancel()
	waitDone(t, done)
}

func TestExtendedRuntime_Masking_ParentCancellation_InterruptsBlockedMasker(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := &fakeMasker{block: true, entered: make(chan struct{})}
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, rt, ctx)

	setupMaskingExecuteHead(t, ctx, rt, backendW, client, "s1", "p1", []maskTestField{{"email", 0}})
	backendW.Write(beDataRowFrame([]protocol.DataCell{{Value: []byte("x@example.com")}}))

	select {
	case <-masker.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the Masker to be invoked")
	}

	cancel()

	runErr := waitDone(t, done)
	if runErr == nil {
		t.Fatal("expected Run to return an error after parent cancellation interrupted a blocked Masker call")
	}
	if masker.lastCtx == nil || masker.lastCtx.Err() == nil {
		t.Fatal("expected the context passed to Masker to be canceled")
	}
}

// ==========================================================================
// Masking-failure causality linearization (bkz. gorev 5)
// ==========================================================================

// armableBlockingWriter wraps a *trackingWriter: while unarmed it behaves
// identically (writes captured normally); once Arm() is called, the NEXT
// Write blocks until Close() is invoked (simulating a real connection being
// torn down by the runtime's shutdown watcher unblocking a stalled Write) -
// used to deterministically catch the event loop genuinely blocked inside
// a FATAL write.
type armableBlockingWriter struct {
	*trackingWriter
	armed        atomic.Bool
	enteredWrite chan struct{}
	unblock      chan struct{}
	unblockOnce  sync.Once
}

func newArmableBlockingWriter() *armableBlockingWriter {
	return &armableBlockingWriter{
		trackingWriter: newTrackingWriter(),
		enteredWrite:   make(chan struct{}, 1),
		unblock:        make(chan struct{}),
	}
}

func (w *armableBlockingWriter) Arm() { w.armed.Store(true) }

func (w *armableBlockingWriter) Write(p []byte) (int, error) {
	if w.armed.Load() {
		select {
		case w.enteredWrite <- struct{}{}:
		default:
		}
		<-w.unblock
		return 0, errors.New("test: write interrupted by connection close")
	}
	return w.trackingWriter.Write(p)
}

func (w *armableBlockingWriter) Close() error {
	w.unblockOnce.Do(func() { close(w.unblock) })
	return w.trackingWriter.Close()
}

// TestExtendedRuntime_Masking_Causality_MaskingFailureFirst_LaterParentCancelDoesNotReplaceIt
// covers: genuine masking failure first, FATAL Write blocks, parent
// cancellation later unblocks it - masking failure remains primary.
func TestExtendedRuntime_Masking_Causality_MaskingFailureFirst_LaterParentCancelDoesNotReplaceIt(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newArmableBlockingWriter()
	masker := &fakeMasker{maskFunc: func(column, value string) (string, bool, error) {
		return "", false, errors.New("plugin crashed")
	}}
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	setupMaskingExecuteHead(t, ctx, rt, backendW, client.trackingWriter, "s1", "p1", []maskTestField{{"email", 0}})

	client.Arm() // the NEXT write (the FATAL) will block until Close()
	backendW.Write(beDataRowFrame([]protocol.DataCell{{Value: []byte("x@example.com")}}))

	select {
	case <-client.enteredWrite:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the FATAL write to begin")
	}

	// Parent cancellation races in WHILE the FATAL write is genuinely
	// blocked - it must NOT win shutdown-cause linearization: the masking
	// failure already claimed it before attempting the write.
	cancel()

	runErr := waitDone(t, done)
	if !errors.Is(runErr, ErrExtendedMaskingFailed) {
		t.Fatalf("expected the masking failure to remain the primary cause, got %v", runErr)
	}
	if errors.Is(runErr, context.Canceled) {
		t.Fatal("expected context.Canceled NOT to have replaced the masking failure as primary")
	}
}

// TestExtendedRuntime_Masking_Causality_ParentCancelFirst_ContextCauseRemainsPrimary
// covers: parent cancellation first, context-aware Masker returns because
// of cancellation - context cause remains primary, and the masking FATAL
// write is never even attempted. The Masker's return is deterministically
// gated on onWatcherShutdownBegun (fired at the END of the watcher's
// shutdown-cause claim) so the watcher's CAS is GUARANTEED to have already
// won before the event loop ever reaches emitMaskingFailureFatal.
func TestExtendedRuntime_Masking_Causality_ParentCancelFirst_ContextCauseRemainsPrimary(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	watcherClaimed := make(chan struct{})
	masker := &fakeMasker{block: true, entered: make(chan struct{}), waitBeforeReturn: watcherClaimed}
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	rt.onWatcherShutdownBegun = func() { close(watcherClaimed) }

	ctx, cancel := context.WithCancel(context.Background())
	done := runInBackground(t, rt, ctx)

	setupMaskingExecuteHead(t, ctx, rt, backendW, client, "s1", "p1", []maskTestField{{"email", 0}})
	backendW.Write(beDataRowFrame([]protocol.DataCell{{Value: []byte("x@example.com")}}))

	select {
	case <-masker.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the Masker to be invoked")
	}

	prefix := client.Snapshot()
	cancel() // parent cancellation FIRST - the watcher claims shutdownCause
	// BEFORE the (gated) Masker call is allowed to actually return.

	runErr := waitDone(t, done)
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("expected context.Canceled to remain primary, got %v", runErr)
	}
	if errors.Is(runErr, ErrExtendedMaskingFailed) {
		t.Fatal("expected the masking failure NOT to have become primary")
	}
	// No FATAL ErrorResponse must have been attempted at all.
	got := client.Snapshot()
	for off := len(prefix); off+5 <= len(got); {
		if protocol.MessageType(got[off]) == protocol.MsgErrorResponse {
			t.Fatalf("expected no FATAL ErrorResponse to be attempted, got %x", got[len(prefix):])
		}
		length := binary.BigEndian.Uint32(got[off+1 : off+5])
		off += 1 + int(length)
	}
}

// TestExtendedRuntime_Masking_Causality_FrontendCloseFirst_FrontendCauseRemainsPrimary
// covers: frontend closure first, context-aware Masker exits - frontend-
// close cause remains primary. Uses the SAME onWatcherShutdownBegun gate
// (fired at the end of beginFrontendShutdown too).
func TestExtendedRuntime_Masking_Causality_FrontendCloseFirst_FrontendCauseRemainsPrimary(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	watcherClaimed := make(chan struct{})
	masker := &fakeMasker{block: true, entered: make(chan struct{}), waitBeforeReturn: watcherClaimed}
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	rt.onWatcherShutdownBegun = func() { close(watcherClaimed) }

	ctx := context.Background()
	done := runInBackground(t, rt, ctx)

	setupMaskingExecuteHead(t, ctx, rt, backendW, client, "s1", "p1", []maskTestField{{"email", 0}})
	backendW.Write(beDataRowFrame([]protocol.DataCell{{Value: []byte("x@example.com")}}))

	select {
	case <-masker.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the Masker to be invoked")
	}

	go func() { _ = rt.NotifyFrontendClosed(context.Background(), FrontendClosedEOF, nil) }()

	runErr := waitDone(t, done)
	if !errors.Is(runErr, ErrFrontendClosed) {
		t.Fatalf("expected ErrFrontendClosed to remain primary, got %v", runErr)
	}
	if errors.Is(runErr, ErrExtendedMaskingFailed) {
		t.Fatal("expected the masking failure NOT to have become primary")
	}
}

// TestExtendedRuntime_Masking_Causality_FatalWriteFailureDoesNotReplaceMaskingCause
// covers: FATAL write failure (an immediate error, not a block) must not
// replace the masking failure as the primary cause.
func TestExtendedRuntime_Masking_Causality_FatalWriteFailureDoesNotReplaceMaskingCause(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := &fakeMasker{maskFunc: func(column, value string) (string, bool, error) {
		return "", false, errors.New("plugin crashed")
	}}
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	setupMaskingExecuteHead(t, ctx, rt, backendW, client, "s1", "p1", []maskTestField{{"email", 0}})

	client.writeErrOnce = errors.New("test: simulated FATAL write failure")
	backendW.Write(beDataRowFrame([]protocol.DataCell{{Value: []byte("x@example.com")}}))

	runErr := waitDone(t, done)
	if !errors.Is(runErr, ErrExtendedMaskingFailed) {
		t.Fatalf("expected the masking failure to remain primary even though its own FATAL write failed, got %v", runErr)
	}
}

// TestExtendedRuntime_Masking_Causality_FatalOutputAttemptedAtMostOnce proves
// exactly one write attempt is made for the FATAL frame - processActions
// stops at the first masking failure, so no later action (and no repeated
// FATAL attempt) can ever be processed.
func TestExtendedRuntime_Masking_Causality_FatalOutputAttemptedAtMostOnce(t *testing.T) {
	backendR, backendW := io.Pipe()
	defer backendR.Close()
	client := newTrackingWriter()
	masker := &fakeMasker{maskFunc: func(column, value string) (string, bool, error) {
		return "", false, errors.New("plugin crashed")
	}}
	rt := newMaskingTestRuntime(t, newDuplexBackend(backendR), client, masking.NewConfig(true, []string{"email"}), masker)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runInBackground(t, rt, ctx)

	setupMaskingExecuteHead(t, ctx, rt, backendW, client, "s1", "p1", []maskTestField{{"email", 0}})

	writesBefore := client.WriteCount()
	backendW.Write(beDataRowFrame([]protocol.DataCell{{Value: []byte("x@example.com")}}))

	runErr := waitDone(t, done)
	if !errors.Is(runErr, ErrExtendedMaskingFailed) {
		t.Fatalf("expected ErrExtendedMaskingFailed, got %v", runErr)
	}
	if got := client.WriteCount() - writesBefore; got != 1 {
		t.Fatalf("expected exactly 1 additional write (the FATAL frame), got %d", got)
	}
}

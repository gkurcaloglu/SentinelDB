package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/gateway"
	"github.com/gkurcaloglu/sentineldb/internal/masking"
	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// --- Integration-style tests: ExtendedFrontend + masking-enabled ---------
// ExtendedRuntime, connected over net.Pipe (bkz. gorev 22). The opt-in path
// is invoked directly here - there is NO cmd/gateway call site.

// maskingFakeMasker is a minimal masking.Masker test double: masks any
// value containing "@" to a fixed marker.
type maskingFakeMasker struct {
	block   bool
	entered chan struct{}
}

func (m *maskingFakeMasker) Mask(ctx context.Context, column, kind, value string) (string, bool, string, error) {
	if m.block {
		if m.entered != nil {
			close(m.entered)
		}
		<-ctx.Done()
		return "", false, "", ctx.Err()
	}
	if !strings.Contains(value, "@") {
		return value, false, "", nil
	}
	return "MASKED", true, "", nil
}

// waitForSyntheticAfter is waitForSynthetic (bkz. extended_frontend_test.go)
// adapted for a harness that ALREADY has prior client-bound bytes
// (clientBefore) before the expected synthetic ErrorResponse - it waits
// until clientBound grows STRICTLY PAST clientBefore, not merely until it
// is non-empty (which would return immediately/too early given the prior
// traffic already present).
func waitForSyntheticAfter(t *testing.T, h *harness, clientBefore []byte) []byte {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := h.clientBound.Snapshot()
		if len(got) > len(clientBefore) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for a synthetic ErrorResponse")
		}
		time.Sleep(time.Millisecond)
	}
}

func newMaskingHarness(t *testing.T, cfg masking.Config, masker masking.Masker) *harness {
	t.Helper()
	clientRuntimeSide, clientTestSide := net.Pipe()
	backendRuntimeSide, backendTestSide := net.Pipe()

	s := protocol.NewState()
	limits := gateway.RuntimeLimits{FrontendEventBuffer: 8, BackendEventBuffer: 8, MaxFrontendFrameBytes: 64 * 1024}
	rt, err := gateway.NewExtendedRuntimeWithMasking(s, backendRuntimeSide, clientRuntimeSide, protocol.DefaultSequencerLimits(), limits,
		cfg, masker, masking.DefaultExtendedLimits(), masking.Hooks{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frontend, err := NewExtendedFrontend(rt, nil, nil)
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

	return &harness{
		t: t, rt: rt, frontend: frontend,
		clientTest: clientTestSide, backendTest: backendTestSide,
		clientBound: newConnAccumulator(clientTestSide),
		upstream:    newConnAccumulator(backendTestSide),
		cancel:      cancel, rtDone: rtDone, runDone: runDone,
	}
}

func maskingBeRowDescription(fields []struct {
	name string
	fc   int16
}) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, uint16(len(fields)))
	for _, f := range fields {
		body = append(body, []byte(f.name)...)
		body = append(body, 0)
		body = append(body, 0, 0, 0, 0)
		body = append(body, 0, 0)
		body = append(body, 0, 0, 0, 25)
		body = append(body, 0xFF, 0xFF)
		body = append(body, 0, 0, 0, 0)
		fc := make([]byte, 2)
		binary.BigEndian.PutUint16(fc, uint16(f.fc))
		body = append(body, fc...)
	}
	return buildFrame(protocol.MsgRowDescription, body)
}

func maskingBeParamDesc() []byte { return buildFrame(protocol.MsgParameterDescription, []byte{0, 0}) }

func maskingBeDataRow(cells []protocol.DataCell) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, uint16(len(cells)))
	for _, c := range cells {
		if c.Null {
			body = append(body, 0xFF, 0xFF, 0xFF, 0xFF)
			continue
		}
		lb := make([]byte, 4)
		binary.BigEndian.PutUint32(lb, uint32(len(c.Value)))
		body = append(body, lb...)
		body = append(body, c.Value...)
	}
	return buildFrame(protocol.MsgDataRow, body)
}

func TestExtendedFrontendMasking_FullRoundTrip_StatementShape_MasksDataRow(t *testing.T) {
	h := newMaskingHarness(t, masking.NewConfig(true, []string{"email"}), &maskingFakeMasker{})
	defer h.close()

	// 1. Parse -> ParseComplete
	h.sendClient(feParseFrame("s1", "SELECT id, email FROM users", nil))
	waitForAccumulated(t, h.upstream, feParseFrame("s1", "SELECT id, email FROM users", nil))
	h.sendBackend(beEmpty(protocol.MsgParseComplete))
	waitForAccumulated(t, h.clientBound, beEmpty(protocol.MsgParseComplete))

	// 2. Describe statement -> ParameterDescription -> RowDescription
	h.sendClient(feDescribeFrame(protocol.TargetStatement, "s1"))
	wantUp := append(feParseFrame("s1", "SELECT id, email FROM users", nil), feDescribeFrame(protocol.TargetStatement, "s1")...)
	waitForAccumulated(t, h.upstream, wantUp)
	h.sendBackend(maskingBeParamDesc())
	h.sendBackend(maskingBeRowDescription([]struct {
		name string
		fc   int16
	}{{"id", 0}, {"email", 0}}))
	wantClient := append(append([]byte{}, beEmpty(protocol.MsgParseComplete)...), append(maskingBeParamDesc(), maskingBeRowDescription([]struct {
		name string
		fc   int16
	}{{"id", 0}, {"email", 0}})...)...)
	waitForAccumulated(t, h.clientBound, wantClient)

	// 3. Bind -> BindComplete
	h.sendClient(feBindFrame("p1", "s1", nil, nil, nil))
	wantUp = append(wantUp, feBindFrame("p1", "s1", nil, nil, nil)...)
	waitForAccumulated(t, h.upstream, wantUp)
	h.sendBackend(beEmpty(protocol.MsgBindComplete))
	wantClient = append(wantClient, beEmpty(protocol.MsgBindComplete)...)
	waitForAccumulated(t, h.clientBound, wantClient)

	// 4. Execute -> DataRow (masked) -> CommandComplete
	h.sendClient(feExecuteFrame("p1", 0))
	wantUp = append(wantUp, feExecuteFrame("p1", 0)...)
	waitForAccumulated(t, h.upstream, wantUp)

	dr := maskingBeDataRow([]protocol.DataCell{{Value: []byte("1")}, {Value: []byte("john@example.com")}})
	h.sendBackend(dr)
	row, err := protocol.ParseDataRow(dr[5:])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	row, err = row.WithCell(1, protocol.DataCell{Value: []byte("MASKED")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantClient = append(wantClient, row.Build()...)
	waitForAccumulated(t, h.clientBound, wantClient)

	h.sendBackend(beCommandComplete("SELECT 1"))
	wantClient = append(wantClient, beCommandComplete("SELECT 1")...)
	waitForAccumulated(t, h.clientBound, wantClient)

	// 5. Sync -> ReadyForQuery
	h.sendClient(feSyncFrame())
	wantUp = append(wantUp, feSyncFrame()...)
	waitForAccumulated(t, h.upstream, wantUp)
	h.sendBackend(beRFQ('I'))
	wantClient = append(wantClient, beRFQ('I')...)
	waitForAccumulated(t, h.clientBound, wantClient)
}

func TestExtendedFrontendMasking_PortalDescribePath(t *testing.T) {
	h := newMaskingHarness(t, masking.NewConfig(true, []string{"email"}), &maskingFakeMasker{})
	defer h.close()

	h.sendClient(feParseFrame("s1", "SELECT email", nil))
	waitForAccumulated(t, h.upstream, feParseFrame("s1", "SELECT email", nil))
	h.sendBackend(beEmpty(protocol.MsgParseComplete))
	waitForAccumulated(t, h.clientBound, beEmpty(protocol.MsgParseComplete))

	h.sendClient(feBindFrame("p1", "s1", nil, nil, nil))
	wantUp := append(feParseFrame("s1", "SELECT email", nil), feBindFrame("p1", "s1", nil, nil, nil)...)
	waitForAccumulated(t, h.upstream, wantUp)
	h.sendBackend(beEmpty(protocol.MsgBindComplete))
	wantClient := append(append([]byte{}, beEmpty(protocol.MsgParseComplete)...), beEmpty(protocol.MsgBindComplete)...)
	waitForAccumulated(t, h.clientBound, wantClient)

	h.sendClient(feDescribeFrame(protocol.TargetPortal, "p1"))
	wantUp = append(wantUp, feDescribeFrame(protocol.TargetPortal, "p1")...)
	waitForAccumulated(t, h.upstream, wantUp)
	rd := maskingBeRowDescription([]struct {
		name string
		fc   int16
	}{{"email", 0}})
	h.sendBackend(rd)
	wantClient = append(wantClient, rd...)
	waitForAccumulated(t, h.clientBound, wantClient)

	h.sendClient(feExecuteFrame("p1", 0))
	wantUp = append(wantUp, feExecuteFrame("p1", 0)...)
	waitForAccumulated(t, h.upstream, wantUp)

	dr := maskingBeDataRow([]protocol.DataCell{{Value: []byte("a@example.com")}})
	h.sendBackend(dr)
	row, _ := protocol.ParseDataRow(dr[5:])
	row, _ = row.WithCell(0, protocol.DataCell{Value: []byte("MASKED")})
	wantClient = append(wantClient, row.Build()...)
	waitForAccumulated(t, h.clientBound, wantClient)
}

func TestExtendedFrontendMasking_BlockedUnknownShapeExecute_RecoversAfterSync(t *testing.T) {
	h := newMaskingHarness(t, masking.NewConfig(true, []string{"email"}), &maskingFakeMasker{})
	defer h.close()

	h.sendClient(feParseFrame("s1", "SELECT 1", nil))
	waitForAccumulated(t, h.upstream, feParseFrame("s1", "SELECT 1", nil))
	h.sendBackend(beEmpty(protocol.MsgParseComplete))
	waitForAccumulated(t, h.clientBound, beEmpty(protocol.MsgParseComplete))

	h.sendClient(feBindFrame("p1", "s1", nil, nil, nil))
	wantUp := append(feParseFrame("s1", "SELECT 1", nil), feBindFrame("p1", "s1", nil, nil, nil)...)
	waitForAccumulated(t, h.upstream, wantUp)
	h.sendBackend(beEmpty(protocol.MsgBindComplete))
	wantClient := append(append([]byte{}, beEmpty(protocol.MsgParseComplete)...), beEmpty(protocol.MsgBindComplete)...)
	waitForAccumulated(t, h.clientBound, wantClient)

	// NO Describe at all - shape is unknown. Execute must be blocked
	// locally: exactly one synthetic ErrorResponse, no upstream Execute
	// bytes, discard-until-Sync.
	h.sendClient(feExecuteFrame("p1", 0))
	got := waitForSyntheticAfter(t, h, wantClient)
	if !bytes.Equal(h.upstream.Snapshot(), wantUp) {
		t.Fatalf("expected the blocked Execute never forwarded upstream, got %x want %x", h.upstream.Snapshot(), wantUp)
	}
	if protocol.MessageType(got[len(wantClient):][0]) != protocol.MsgErrorResponse {
		t.Fatalf("expected a synthetic ErrorResponse, got %x", got[len(wantClient):])
	}

	assertMaskingDiscardThenClears(t, h, wantUp, got)
}

func TestExtendedFrontendMasking_BlockedBinaryTargetExecute_RecoversAfterSync(t *testing.T) {
	h := newMaskingHarness(t, masking.NewConfig(true, []string{"email"}), &maskingFakeMasker{})
	defer h.close()

	h.sendClient(feParseFrame("s1", "SELECT email", nil))
	waitForAccumulated(t, h.upstream, feParseFrame("s1", "SELECT email", nil))
	h.sendBackend(beEmpty(protocol.MsgParseComplete))
	waitForAccumulated(t, h.clientBound, beEmpty(protocol.MsgParseComplete))

	h.sendClient(feDescribeFrame(protocol.TargetStatement, "s1"))
	wantUp := append(feParseFrame("s1", "SELECT email", nil), feDescribeFrame(protocol.TargetStatement, "s1")...)
	waitForAccumulated(t, h.upstream, wantUp)
	h.sendBackend(maskingBeParamDesc())
	h.sendBackend(maskingBeRowDescription([]struct {
		name string
		fc   int16
	}{{"email", 0}}))
	wantClient := append(append([]byte{}, beEmpty(protocol.MsgParseComplete)...), append(maskingBeParamDesc(), maskingBeRowDescription([]struct {
		name string
		fc   int16
	}{{"email", 0}})...)...)
	waitForAccumulated(t, h.clientBound, wantClient)

	// Bind requests BINARY format for the (only, target) column.
	h.sendClient(feBindFrame("p1", "s1", nil, nil, []int16{1}))
	wantUp = append(wantUp, feBindFrame("p1", "s1", nil, nil, []int16{1})...)
	waitForAccumulated(t, h.upstream, wantUp)
	h.sendBackend(beEmpty(protocol.MsgBindComplete))
	wantClient = append(wantClient, beEmpty(protocol.MsgBindComplete)...)
	waitForAccumulated(t, h.clientBound, wantClient)

	h.sendClient(feExecuteFrame("p1", 0))
	got := waitForSyntheticAfter(t, h, wantClient)
	if !bytes.Equal(h.upstream.Snapshot(), wantUp) {
		t.Fatalf("expected the blocked (binary-target) Execute never forwarded upstream, got %x want %x", h.upstream.Snapshot(), wantUp)
	}

	assertMaskingDiscardThenClears(t, h, wantUp, got)
}

// assertMaskingDiscardThenClears is the assertDiscardingThenClears pattern
// (bkz. extended_frontend_test.go) adapted for a harness that ALREADY has
// prior valid upstream traffic (Parse/Describe/Bind) before the blocked
// Execute - it proves discard is active relative to upstreamBefore (not an
// assumed-empty baseline), then proves Sync/next-cycle forwarding clears it.
func assertMaskingDiscardThenClears(t *testing.T, h *harness, upstreamBefore []byte, synthetic []byte) {
	t.Helper()

	h.sendClient(feBindFrame("p1", "s1", nil, nil, nil))
	time.Sleep(20 * time.Millisecond) // bounded settling for the (absence of) processing
	if !bytes.Equal(h.upstream.Snapshot(), upstreamBefore) {
		t.Fatalf("expected the discarded Bind never forwarded, got %x want %x", h.upstream.Snapshot(), upstreamBefore)
	}
	if !bytes.Equal(h.clientBound.Snapshot(), synthetic) {
		t.Fatalf("expected no additional synthetic error, got %x (was %x)", h.clientBound.Snapshot(), synthetic)
	}

	sync := feSyncFrame()
	h.sendClient(sync)
	wantUp := append(append([]byte{}, upstreamBefore...), sync...)
	waitForAccumulated(t, h.upstream, wantUp)

	parseNext := feParseFrame("next-cycle", "SELECT 1", nil)
	h.sendClient(parseNext)
	wantUp = append(wantUp, parseNext...)
	waitForAccumulated(t, h.upstream, wantUp)
}

func TestExtendedFrontendMasking_ShutdownDuringBlockedMasker(t *testing.T) {
	masker := &maskingFakeMasker{block: true, entered: make(chan struct{})}
	h := newMaskingHarness(t, masking.NewConfig(true, []string{"email"}), masker)

	h.sendClient(feParseFrame("s1", "SELECT email", nil))
	waitForAccumulated(t, h.upstream, feParseFrame("s1", "SELECT email", nil))
	h.sendBackend(beEmpty(protocol.MsgParseComplete))
	waitForAccumulated(t, h.clientBound, beEmpty(protocol.MsgParseComplete))

	h.sendClient(feDescribeFrame(protocol.TargetStatement, "s1"))
	wantUp := append(feParseFrame("s1", "SELECT email", nil), feDescribeFrame(protocol.TargetStatement, "s1")...)
	waitForAccumulated(t, h.upstream, wantUp)
	h.sendBackend(maskingBeParamDesc())
	h.sendBackend(maskingBeRowDescription([]struct {
		name string
		fc   int16
	}{{"email", 0}}))
	wantClient := append(append([]byte{}, beEmpty(protocol.MsgParseComplete)...), append(maskingBeParamDesc(), maskingBeRowDescription([]struct {
		name string
		fc   int16
	}{{"email", 0}})...)...)
	waitForAccumulated(t, h.clientBound, wantClient)

	h.sendClient(feBindFrame("p1", "s1", nil, nil, nil))
	wantUp = append(wantUp, feBindFrame("p1", "s1", nil, nil, nil)...)
	waitForAccumulated(t, h.upstream, wantUp)
	h.sendBackend(beEmpty(protocol.MsgBindComplete))
	wantClient = append(wantClient, beEmpty(protocol.MsgBindComplete)...)
	waitForAccumulated(t, h.clientBound, wantClient)

	h.sendClient(feExecuteFrame("p1", 0))
	wantUp = append(wantUp, feExecuteFrame("p1", 0)...)
	waitForAccumulated(t, h.upstream, wantUp)

	h.sendBackend(maskingBeDataRow([]protocol.DataCell{{Value: []byte("x@example.com")}}))

	select {
	case <-masker.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the Masker to be invoked")
	}

	// Shut the connection down WHILE the Masker call is blocked.
	h.close()
}

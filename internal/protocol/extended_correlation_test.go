package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// --- Test helpers -----------------------------------------------------

func backendMsg(t MessageType, body []byte) Message {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(body)+4))
	raw := append([]byte{byte(t)}, length...)
	raw = append(raw, body...)
	return Message{Direction: Backend, Type: t, Name: messageName(Backend, t), Length: len(body) + 4, Raw: raw}
}

func emptyBackendMsg(t MessageType) Message { return backendMsg(t, nil) }

func rfqMsg(status byte) Message { return backendMsg(MsgReadyForQuery, []byte{status}) }

func paramDescMsg(oids []uint32) Message {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(oids)))
	for _, o := range oids {
		ob := make([]byte, 4)
		binary.BigEndian.PutUint32(ob, o)
		b = append(b, ob...)
	}
	return backendMsg(MsgParameterDescription, b)
}

func rowDescMsg() Message { return backendMsg(MsgRowDescription, []byte{0, 0}) }
func dataRowMsg() Message { return backendMsg(MsgDataRow, []byte{0, 0}) }

func commandCompleteMsg(tag string) Message {
	return backendMsg(MsgCommandComplete, append([]byte(tag), 0))
}

func minimalErrorResponse() Message { return backendMsg(MsgErrorResponse, []byte{0}) }

func fieldedErrorResponse(text string) Message {
	body := []byte{'S'}
	body = append(body, []byte("ERROR")...)
	body = append(body, 0)
	body = append(body, 'M')
	body = append(body, []byte(text)...)
	body = append(body, 0)
	body = append(body, 0) // terminator
	return backendMsg(MsgErrorResponse, body)
}

func newCorrelator(t *testing.T) (*State, *BackendCorrelator) {
	t.Helper()
	s := NewState()
	c, err := NewBackendCorrelator(s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return s, c
}

// setupExecuteHead builds an unnamed statement + portal (both committed)
// and a pending Execute against that portal, so the correlator's head is
// exactly an Execute ready for DataRow*/terminal handling.
func setupExecuteHead(t *testing.T) (*State, *BackendCorrelator) {
	t.Helper()
	s, c := newCorrelator(t)
	if _, err := s.wrapCreateParse(""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.Handle(emptyBackendMsg(MsgParseComplete)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, _, err := s.CreateBind("", "", nil, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.Handle(emptyBackendMsg(MsgBindComplete)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.CreateExecute(""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return s, c
}

// wrapCreateParse is a tiny convenience so setupExecuteHead reads cleanly.
func (s *State) wrapCreateParse(name string) (PendingOperation, error) {
	op, _, err := s.CreateParse(name, "SELECT 1", nil)
	return op, err
}

type stateSnapshot struct {
	statements        int
	portals           int
	pendingOps        []PendingOperation
	outstandingCycles int
	txStatus          byte
	currentCycle      CycleID
}

func snapshotState(s *State) stateSnapshot {
	return stateSnapshot{
		statements:        s.StatementCount(),
		portals:           s.PortalCount(),
		pendingOps:        s.PendingOperations(),
		outstandingCycles: s.OutstandingCycleCount(),
		txStatus:          s.TransactionStatus(),
		currentCycle:      s.CurrentCycle(),
	}
}

func assertStateUnchanged(t *testing.T, before, after stateSnapshot) {
	t.Helper()
	if before.statements != after.statements || before.portals != after.portals ||
		before.outstandingCycles != after.outstandingCycles || before.txStatus != after.txStatus ||
		before.currentCycle != after.currentCycle {
		t.Fatalf("expected State counts/status unchanged, before=%+v after=%+v", before, after)
	}
	if len(before.pendingOps) != len(after.pendingOps) {
		t.Fatalf("expected pending op count unchanged: before=%d after=%d", len(before.pendingOps), len(after.pendingOps))
	}
	for i := range before.pendingOps {
		if before.pendingOps[i] != after.pendingOps[i] {
			t.Fatalf("expected pending op %d unchanged: before=%+v after=%+v", i, before.pendingOps[i], after.pendingOps[i])
		}
	}
}

// --- Parse correlation ----------------------------------------------------

func TestCorrelator_ParseComplete_CommitsNamedParse(t *testing.T) {
	s, c := newCorrelator(t)
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	res, err := c.Handle(emptyBackendMsg(MsgParseComplete))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted || res.OperationKind != OpParse || res.OperationID != op.ID {
		t.Fatalf("unexpected result: %+v", res)
	}
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected s1 committed")
	}
}

func TestCorrelator_ParseComplete_CommitsUnnamedParse(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("", "SELECT 1", nil)
	res, err := c.Handle(emptyBackendMsg(MsgParseComplete))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted {
		t.Fatal("expected completed")
	}
	if _, ok := s.CommittedStatement(""); !ok {
		t.Fatal("expected unnamed statement committed")
	}
}

func TestCorrelator_Parse_ErrorResponseFails(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsErrorResponse || res.OperationKind != OpParse {
		t.Fatalf("unexpected result: %+v", res)
	}
	if _, ok := s.CommittedStatement("s1"); ok {
		t.Fatal("expected s1 not committed")
	}
}

func TestCorrelator_Parse_WrongAcknowledgementRejectedWithoutMutation(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	before := snapshotState(s)
	_, err := c.Handle(emptyBackendMsg(MsgBindComplete))
	if !errors.Is(err, ErrAckKindMismatch) {
		t.Fatalf("expected ErrAckKindMismatch, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_MalformedParseComplete_RejectedWithoutMutation(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	before := snapshotState(s)
	_, err := c.Handle(backendMsg(MsgParseComplete, []byte{1}))
	if !errors.Is(err, ErrMalformedBackendMessage) {
		t.Fatalf("expected ErrMalformedBackendMessage, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

// --- Bind correlation -------------------------------------------------

func TestCorrelator_BindComplete_CommitsPortal(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	res, err := c.Handle(emptyBackendMsg(MsgBindComplete))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted || res.OperationID != bop.ID {
		t.Fatalf("unexpected result: %+v", res)
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected p1 committed")
	}
}

func TestCorrelator_Bind_ErrorResponseFails(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateBind("p1", "s1", nil, nil, nil)
	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsErrorResponse || res.OperationKind != OpBind {
		t.Fatalf("unexpected result: %+v", res)
	}
	if _, ok := s.CommittedPortal("p1"); ok {
		t.Fatal("expected p1 not committed")
	}
}

func TestCorrelator_Bind_WrongAcknowledgementRejected(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateBind("p1", "s1", nil, nil, nil)
	before := snapshotState(s)
	_, err := c.Handle(emptyBackendMsg(MsgParseComplete))
	if !errors.Is(err, ErrAckKindMismatch) {
		t.Fatalf("expected ErrAckKindMismatch, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_Bind_MalformedBindCompleteRejected(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateBind("p1", "s1", nil, nil, nil)
	before := snapshotState(s)
	_, err := c.Handle(backendMsg(MsgBindComplete, []byte{1}))
	if !errors.Is(err, ErrMalformedBackendMessage) {
		t.Fatalf("expected ErrMalformedBackendMessage, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

// --- Close correlation -------------------------------------------------

func TestCorrelator_CloseComplete_ClosesExactStatementGeneration(t *testing.T) {
	s, c := newCorrelator(t)
	_, sgen, _ := s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	cop, err := s.CreateCloseStatement("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, err := c.Handle(emptyBackendMsg(MsgCloseComplete))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted || res.OperationID != cop.ID {
		t.Fatalf("unexpected result: %+v", res)
	}
	if _, ok := s.Statement(sgen.ID); ok {
		t.Fatal("expected statement removed")
	}
}

func TestCorrelator_CloseComplete_ClosesExactPortalGeneration(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	_, pgen, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))
	cop, err := s.CreateClosePortal("p1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, err := c.Handle(emptyBackendMsg(MsgCloseComplete))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted || res.OperationID != cop.ID {
		t.Fatalf("unexpected result: %+v", res)
	}
	if _, ok := s.Portal(pgen.ID); ok {
		t.Fatal("expected portal removed")
	}
}

func TestCorrelator_StatementClose_CascadesToDependentPortals(t *testing.T) {
	s, c := newCorrelator(t)
	_, sgen, _ := s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	_, pgen, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))
	s.CreateCloseStatement("s1")
	if _, err := c.Handle(emptyBackendMsg(MsgCloseComplete)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.Statement(sgen.ID); ok {
		t.Fatal("expected statement removed")
	}
	if _, ok := s.Portal(pgen.ID); ok {
		t.Fatal("expected dependent portal cascaded away")
	}
}

func TestCorrelator_Close_ErrorResponsePreservesTargets(t *testing.T) {
	s, c := newCorrelator(t)
	_, sgen, _ := s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateCloseStatement("s1")
	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsErrorResponse {
		t.Fatal("expected IsErrorResponse")
	}
	if _, ok := s.Statement(sgen.ID); !ok {
		t.Fatal("expected statement preserved")
	}
}

func TestCorrelator_MalformedCloseCompleteRejected(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateCloseStatement("s1")
	before := snapshotState(s)
	_, err := c.Handle(backendMsg(MsgCloseComplete, []byte{1}))
	if !errors.Is(err, ErrMalformedBackendMessage) {
		t.Fatalf("expected ErrMalformedBackendMessage, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

// --- Describe statement -------------------------------------------------

func TestCorrelator_DescribeStatement_ParamDescThenRowDescription(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	dop, err := s.CreateDescribeStatement("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, err := c.Handle(paramDescMsg([]uint32{23}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Intermediate || res.OperationID != dop.ID {
		t.Fatalf("unexpected result: %+v", res)
	}
	res, err = c.Handle(rowDescMsg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted {
		t.Fatal("expected completed")
	}
}

func TestCorrelator_DescribeStatement_ParamDescThenNoData(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateDescribeStatement("s1")
	c.Handle(paramDescMsg(nil))
	res, err := c.Handle(emptyBackendMsg(MsgNoData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted {
		t.Fatal("expected completed")
	}
}

func TestCorrelator_DescribeStatement_ErrorResponseBeforeParamDesc(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateDescribeStatement("s1")
	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsErrorResponse {
		t.Fatal("expected IsErrorResponse")
	}
}

func TestCorrelator_DescribeStatement_ErrorResponseAfterParamDesc(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateDescribeStatement("s1")
	c.Handle(paramDescMsg(nil))
	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsErrorResponse {
		t.Fatal("expected IsErrorResponse")
	}
}

func TestCorrelator_DescribeStatement_RowDescriptionBeforeParamDescRejected(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateDescribeStatement("s1")
	before := snapshotState(s)
	_, err := c.Handle(rowDescMsg())
	if !errors.Is(err, ErrMissingParameterDescription) {
		t.Fatalf("expected ErrMissingParameterDescription, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_DescribeStatement_DuplicateParamDescRejected(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateDescribeStatement("s1")
	c.Handle(paramDescMsg(nil))
	before := snapshotState(s)
	_, err := c.Handle(paramDescMsg(nil))
	if !errors.Is(err, ErrDuplicateDescribeIntermediate) {
		t.Fatalf("expected ErrDuplicateDescribeIntermediate, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_DescribeStatement_SubstateClearedAfterCompletion(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	dop, _ := s.CreateDescribeStatement("s1")
	c.Handle(paramDescMsg(nil))
	c.Handle(rowDescMsg())
	if c.describeParamSeen[dop.ID] {
		t.Fatal("expected substate cleared after completion")
	}
}

func TestCorrelator_DescribeStatement_SubstateClearedAfterError(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	dop, _ := s.CreateDescribeStatement("s1")
	c.Handle(paramDescMsg(nil))
	c.Handle(minimalErrorResponse())
	if c.describeParamSeen[dop.ID] {
		t.Fatal("expected substate cleared after error")
	}
}

// --- Describe portal ------------------------------------------------------

func TestCorrelator_DescribePortal_RowDescriptionCompletes(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateBind("", "", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))
	dop, err := s.CreateDescribePortal("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, err := c.Handle(rowDescMsg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted || res.OperationID != dop.ID {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestCorrelator_DescribePortal_NoDataCompletes(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateBind("", "", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))
	s.CreateDescribePortal("")
	res, err := c.Handle(emptyBackendMsg(MsgNoData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted {
		t.Fatal("expected completed")
	}
}

func TestCorrelator_DescribePortal_ErrorResponseFails(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateBind("", "", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))
	s.CreateDescribePortal("")
	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsErrorResponse {
		t.Fatal("expected IsErrorResponse")
	}
}

func TestCorrelator_DescribePortal_ParameterDescriptionRejected(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateBind("", "", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))
	s.CreateDescribePortal("")
	before := snapshotState(s)
	_, err := c.Handle(paramDescMsg(nil))
	if !errors.Is(err, ErrImpossibleBackendOrdering) {
		t.Fatalf("expected ErrImpossibleBackendOrdering, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

// --- Execute ------------------------------------------------------------

func TestCorrelator_Execute_ZeroDataRowsThenCommandComplete(t *testing.T) {
	_, c := setupExecuteHead(t)
	res, err := c.Handle(commandCompleteMsg("SELECT 0"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted {
		t.Fatal("expected completed")
	}
}

func TestCorrelator_Execute_MultipleDataRowsThenCommandComplete(t *testing.T) {
	_, c := setupExecuteHead(t)
	for i := 0; i < 3; i++ {
		res, err := c.Handle(dataRowMsg())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Intermediate || res.OperationCompleted {
			t.Fatalf("expected intermediate, got %+v", res)
		}
	}
	res, err := c.Handle(commandCompleteMsg("SELECT 3"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted {
		t.Fatal("expected completed")
	}
}

func TestCorrelator_Execute_EmptyQueryResponse(t *testing.T) {
	_, c := setupExecuteHead(t)
	res, err := c.Handle(emptyBackendMsg(MsgEmptyQueryResponse))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted {
		t.Fatal("expected completed")
	}
}

func TestCorrelator_Execute_PortalSuspended(t *testing.T) {
	_, c := setupExecuteHead(t)
	res, err := c.Handle(emptyBackendMsg(MsgPortalSuspended))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OperationCompleted {
		t.Fatal("expected completed")
	}
}

func TestCorrelator_Execute_ErrorResponse(t *testing.T) {
	_, c := setupExecuteHead(t)
	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsErrorResponse {
		t.Fatal("expected IsErrorResponse")
	}
}

func TestCorrelator_Execute_RowDescriptionRejected(t *testing.T) {
	s, c := setupExecuteHead(t)
	before := snapshotState(s)
	_, err := c.Handle(rowDescMsg())
	if !errors.Is(err, ErrImpossibleBackendOrdering) {
		t.Fatalf("expected ErrImpossibleBackendOrdering, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_Execute_COPYResponseRejectedFailClosed(t *testing.T) {
	s, c := setupExecuteHead(t)
	before := snapshotState(s)
	_, err := c.Handle(backendMsg(MsgCopyOutResponse, []byte{0, 0, 0}))
	if !errors.Is(err, ErrUnsupportedCopyResponse) {
		t.Fatalf("expected ErrUnsupportedCopyResponse, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_Execute_MalformedCommandCompleteRejected(t *testing.T) {
	s, c := setupExecuteHead(t)
	before := snapshotState(s)
	_, err := c.Handle(backendMsg(MsgCommandComplete, []byte("SELECT 1"))) // no NUL terminator
	if !errors.Is(err, ErrMalformedBackendMessage) {
		t.Fatalf("expected ErrMalformedBackendMessage, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_Execute_IntermediateDataRow_DoesNotConsumeOperation(t *testing.T) {
	s, c := setupExecuteHead(t)
	before := snapshotState(s)
	if _, err := c.Handle(dataRowMsg()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

// --- Sync -----------------------------------------------------------------

func TestCorrelator_ReadyForQuery_I(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateSync()
	res, err := c.Handle(rfqMsg(TxStatusIdle))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.CycleCompleted {
		t.Fatal("expected CycleCompleted")
	}
}

func TestCorrelator_ReadyForQuery_T(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateSync()
	res, err := c.Handle(rfqMsg(TxStatusInTransaction))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.CycleCompleted {
		t.Fatal("expected CycleCompleted")
	}
}

func TestCorrelator_ReadyForQuery_E(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateSync()
	res, err := c.Handle(rfqMsg(TxStatusFailedTransaction))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.CycleCompleted {
		t.Fatal("expected CycleCompleted")
	}
}

func TestCorrelator_ReadyForQuery_Malformed(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateSync()
	before := snapshotState(s)
	_, err := c.Handle(backendMsg(MsgReadyForQuery, []byte{'I', 'X'}))
	if !errors.Is(err, ErrMalformedBackendMessage) {
		t.Fatalf("expected ErrMalformedBackendMessage, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_ReadyForQuery_InvalidStatus(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateSync()
	before := snapshotState(s)
	_, err := c.Handle(rfqMsg('X'))
	if !errors.Is(err, ErrInvalidTransactionStatus) {
		t.Fatalf("expected ErrInvalidTransactionStatus, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_ReadyForQuery_FIFOAcrossMultipleCycles(t *testing.T) {
	s, c := newCorrelator(t)
	sync1, _ := s.CreateSync()
	sync2, _ := s.CreateSync()
	res1, err := c.Handle(rfqMsg(TxStatusIdle))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res1.CompletedCycleID != sync1.Cycle {
		t.Fatalf("expected cycle %d completed first, got %d", sync1.Cycle, res1.CompletedCycleID)
	}
	res2, err := c.Handle(rfqMsg(TxStatusIdle))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res2.CompletedCycleID != sync2.Cycle {
		t.Fatalf("expected cycle %d completed second, got %d", sync2.Cycle, res2.CompletedCycleID)
	}
}

func TestCorrelator_ReadyForQuery_NoPendingSyncRejected(t *testing.T) {
	_, c := newCorrelator(t)
	_, err := c.Handle(rfqMsg(TxStatusIdle))
	if !errors.Is(err, ErrNoPendingOperation) {
		t.Fatalf("expected ErrNoPendingOperation, got %v", err)
	}
}

func TestCorrelator_ReadyForQuery_OtherOperationHeadRejected(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	before := snapshotState(s)
	_, err := c.Handle(rfqMsg(TxStatusIdle))
	if !errors.Is(err, ErrAckKindMismatch) {
		t.Fatalf("expected ErrAckKindMismatch, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

// --- Asynchronous ---------------------------------------------------------

func TestCorrelator_NoticeResponse_NoPendingOperation(t *testing.T) {
	_, c := newCorrelator(t)
	res, err := c.Handle(backendMsg(MsgNoticeResponse, []byte{'S', 'N', 'O', 'T', 'I', 'C', 'E', 0, 0}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Async {
		t.Fatal("expected Async result")
	}
}

func TestCorrelator_NoticeResponse_DuringExecute(t *testing.T) {
	s, c := setupExecuteHead(t)
	before := snapshotState(s)
	res, err := c.Handle(backendMsg(MsgNoticeResponse, []byte{0}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Async {
		t.Fatal("expected Async")
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_ParameterStatus_DuringDescribe(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateDescribeStatement("s1")
	before := snapshotState(s)
	res, err := c.Handle(backendMsg(MsgParameterStatus, []byte{'k', 0, 'v', 0}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Async {
		t.Fatal("expected Async")
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_NotificationResponse_WhileIdle(t *testing.T) {
	_, c := newCorrelator(t)
	res, err := c.Handle(backendMsg(MsgNotificationResponse, []byte{0, 0, 0, 1, 'c', 'h', 0, 'p', 0}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Async {
		t.Fatal("expected Async")
	}
}

// --- Real error abandonment ------------------------------------------

func TestCorrelator_HeadParseError_AbandonsLaterSameCycleOperations(t *testing.T) {
	s, c := newCorrelator(t)
	failOp, _, _ := s.CreateParse("s1", "SELECT bad", nil)
	laterOp, laterGen, _ := s.CreateParse("s2", "SELECT 2", nil)
	syncOp, _ := s.CreateSync()

	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OperationID != failOp.ID {
		t.Fatalf("expected failOp to fail, got %+v", res)
	}
	if len(res.AbandonedOperations) != 1 || res.AbandonedOperations[0].ID != laterOp.ID {
		t.Fatalf("expected laterOp abandoned, got %+v", res.AbandonedOperations)
	}
	head, ok := s.HeadPendingOperation()
	if !ok || head.ID != syncOp.ID {
		t.Fatalf("expected Sync entry to remain as new head, got %+v (ok=%v)", head, ok)
	}
	if _, ok := s.Statement(laterGen.ID); ok {
		t.Fatal("expected abandoned generation removed")
	}
	for _, op := range s.PendingOperations() {
		if op.ID == laterOp.ID {
			t.Fatal("expected abandoned op removed from queue")
		}
	}
}

func TestCorrelator_HeadBindError_AbandonsLaterSameCycleOperations(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	failOp, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	laterOp, err := s.CreateDescribeStatement("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.CreateSync()

	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OperationID != failOp.ID {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(res.AbandonedOperations) != 1 || res.AbandonedOperations[0].ID != laterOp.ID {
		t.Fatalf("expected laterOp abandoned, got %+v", res.AbandonedOperations)
	}
}

func TestCorrelator_HeadExecuteError_AbandonsLaterSameCycleOperations(t *testing.T) {
	s, c := setupExecuteHead(t)
	laterOp, err := s.CreateExecute("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.CreateSync()

	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.AbandonedOperations) != 1 || res.AbandonedOperations[0].ID != laterOp.ID {
		t.Fatalf("expected laterOp abandoned, got %+v", res.AbandonedOperations)
	}
}

func TestCorrelator_ErrorResponseAbandonment_LaterCycleUntouched(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT bad", nil)
	s.CreateSync()

	laterCycleOp, laterGen, _ := s.CreateParse("s2", "SELECT 2", nil)

	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.AbandonedOperations) != 0 {
		t.Fatalf("expected no abandonment (later cycle), got %+v", res.AbandonedOperations)
	}
	if _, ok := s.Statement(laterGen.ID); !ok {
		t.Fatal("expected later cycle's generation to remain")
	}
	found := false
	for _, op := range s.PendingOperations() {
		if op.ID == laterCycleOp.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("expected later cycle's op to remain queued")
	}
}

func TestCorrelator_ErrorResponseAbandonment_ReadyForQueryLaterCompletesFailedCycle(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT bad", nil)
	syncOp, _ := s.CreateSync()

	if _, err := c.Handle(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, err := c.Handle(rfqMsg(TxStatusIdle))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.CompletedCycleID != syncOp.Cycle {
		t.Fatalf("expected cycle %d completed, got %d", syncOp.Cycle, res.CompletedCycleID)
	}
}

// --- Skipped unnamed rollback ------------------------------------------

func TestCorrelator_SkippedUnnamedParse_RestoresPreviousStatement(t *testing.T) {
	s, c := newCorrelator(t)
	_, s0, _ := s.CreateParse("", "SELECT 0", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))

	s.CreateBind("", "", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))
	eop, _ := s.CreateExecute("")

	bParseOp, bGen, err := s.CreateParse("", "SELECT B", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cur, ok := s.ResolveStatement(""); !ok || cur.ID != bGen.ID {
		t.Fatalf("precondition failed: expected B current before abandonment")
	}

	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OperationID != eop.ID {
		t.Fatalf("expected eop to fail, got %+v", res)
	}
	if len(res.AbandonedOperations) != 1 || res.AbandonedOperations[0].ID != bParseOp.ID {
		t.Fatalf("expected B's Parse abandoned, got %+v", res.AbandonedOperations)
	}

	cur, ok := s.ResolveStatement("")
	if !ok || cur.ID != s0.ID {
		t.Fatalf("expected S0 restored as current, got %+v (ok=%v)", cur, ok)
	}
	if _, ok := s.Statement(bGen.ID); ok {
		t.Fatal("expected B's generation to be removed")
	}
}

func TestCorrelator_Parse_OwnErrorResponse_DoesNotRestorePrevious(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("", "SELECT 0", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))

	s.CreateParse("", "SELECT B", nil)
	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsErrorResponse {
		t.Fatal("expected IsErrorResponse")
	}
	if len(res.AbandonedOperations) != 0 {
		t.Fatal("expected no abandonment for own failure")
	}
	if _, ok := s.ResolveStatement(""); ok {
		t.Fatal("expected unnamed slot to remain EMPTY, not restored to S0")
	}
}

func TestCorrelator_SkippedUnnamedBind_RestoresPreviousPortal(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	_, p0, _ := s.CreateBind("", "", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))

	failOp, _, _ := s.CreateParse("sX", "SELECT bad", nil)
	bBindOp, bGen, err := s.CreateBind("", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OperationID != failOp.ID {
		t.Fatalf("expected failOp to fail, got %+v", res)
	}
	if len(res.AbandonedOperations) != 1 || res.AbandonedOperations[0].ID != bBindOp.ID {
		t.Fatalf("expected B's Bind abandoned, got %+v", res.AbandonedOperations)
	}

	cur, ok := s.ResolvePortal("")
	if !ok || cur.ID != p0.ID {
		t.Fatalf("expected P0 restored, got %+v (ok=%v)", cur, ok)
	}
	if _, ok := s.Portal(bGen.ID); ok {
		t.Fatal("expected B's portal generation removed")
	}
}

func TestCorrelator_Bind_OwnErrorResponse_DoesNotRestorePreviousPortal(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateBind("", "", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))

	s.CreateBind("", "", nil, nil, nil)
	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsErrorResponse {
		t.Fatal("expected IsErrorResponse")
	}
	if len(res.AbandonedOperations) != 0 {
		t.Fatal("expected no abandonment")
	}
	if _, ok := s.ResolvePortal(""); ok {
		t.Fatal("expected unnamed portal slot to remain EMPTY, not restored")
	}
}

func TestCorrelator_TwoSkippedUnnamedParses_UnwindToOriginal(t *testing.T) {
	s, c := newCorrelator(t)
	_, s0, _ := s.CreateParse("", "SELECT 0", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))

	s.CreateBind("", "", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))
	eop, _ := s.CreateExecute("")

	b1op, b1gen, _ := s.CreateParse("", "SELECT B1", nil)
	b2op, b2gen, _ := s.CreateParse("", "SELECT B2", nil)

	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OperationID != eop.ID {
		t.Fatalf("expected eop to fail, got %+v", res)
	}
	if len(res.AbandonedOperations) != 2 {
		t.Fatalf("expected 2 abandoned, got %d", len(res.AbandonedOperations))
	}
	if res.AbandonedOperations[0].ID != b1op.ID || res.AbandonedOperations[1].ID != b2op.ID {
		t.Fatalf("expected abandoned in creation order [B1,B2], got %+v", res.AbandonedOperations)
	}

	cur, ok := s.ResolveStatement("")
	if !ok || cur.ID != s0.ID {
		t.Fatalf("expected S0 restored, got %+v (ok=%v)", cur, ok)
	}
	if _, ok := s.Statement(b1gen.ID); ok {
		t.Fatal("expected B1 generation removed")
	}
	if _, ok := s.Statement(b2gen.ID); ok {
		t.Fatal("expected B2 generation removed")
	}
}

func TestCorrelator_TwoSkippedUnnamedBinds_UnwindToOriginal(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	_, p0, _ := s.CreateBind("", "", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))

	failOp, _, _ := s.CreateParse("sX", "SELECT bad", nil)
	b1op, b1gen, _ := s.CreateBind("", "", nil, nil, nil)
	b2op, b2gen, _ := s.CreateBind("", "", nil, nil, nil)

	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OperationID != failOp.ID {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(res.AbandonedOperations) != 2 {
		t.Fatalf("expected 2 abandoned, got %d", len(res.AbandonedOperations))
	}
	if res.AbandonedOperations[0].ID != b1op.ID || res.AbandonedOperations[1].ID != b2op.ID {
		t.Fatalf("expected order [B1,B2], got %+v", res.AbandonedOperations)
	}

	cur, ok := s.ResolvePortal("")
	if !ok || cur.ID != p0.ID {
		t.Fatalf("expected P0 restored, got %+v (ok=%v)", cur, ok)
	}
	if _, ok := s.Portal(b1gen.ID); ok {
		t.Fatal("expected B1 portal removed")
	}
	if _, ok := s.Portal(b2gen.ID); ok {
		t.Fatal("expected B2 portal removed")
	}
}

func TestCorrelator_MixedNamedUnnamedAbandonment_PreservesMappings(t *testing.T) {
	s, c := newCorrelator(t)
	_, ngen, _ := s.CreateParse("s1", "SELECT named", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))

	_, u0, _ := s.CreateParse("", "SELECT 0", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateBind("", "", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))
	eop, _ := s.CreateExecute("")

	_, dupGen, _ := s.CreateParse("s1", "SELECT dup", nil)
	_, bGen, _ := s.CreateParse("", "SELECT B", nil)

	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OperationID != eop.ID {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(res.AbandonedOperations) != 2 {
		t.Fatalf("expected 2 abandoned, got %d: %+v", len(res.AbandonedOperations), res.AbandonedOperations)
	}

	got, ok := s.CommittedStatement("s1")
	if !ok || got.ID != ngen.ID {
		t.Fatalf("expected original s1 committed generation to survive, got %+v (ok=%v)", got, ok)
	}
	if _, ok := s.Statement(dupGen.ID); ok {
		t.Fatal("expected duplicate named Parse generation removed")
	}
	cur, ok := s.ResolveStatement("")
	if !ok || cur.ID != u0.ID {
		t.Fatalf("expected unnamed restored to u0, got %+v (ok=%v)", cur, ok)
	}
	if _, ok := s.Statement(bGen.ID); ok {
		t.Fatal("expected B generation removed")
	}
}

func TestCorrelator_RollbackTarget_RetainedWhileNeeded(t *testing.T) {
	s := NewState()
	sop, s0, _ := s.CreateParse("", "SELECT 0", nil)
	s.ApplyParseComplete(sop.ID)
	s.CreateParse("", "SELECT B", nil)
	if _, ok := s.Statement(s0.ID); !ok {
		t.Fatal("expected S0 retained while B (its rollback dependent) is still pending")
	}
}

func TestCorrelator_RollbackTarget_CleanedWhenNoLongerNeeded(t *testing.T) {
	s := NewState()
	sop, s0, _ := s.CreateParse("", "SELECT 0", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateParse("", "SELECT B", nil)
	s.ApplyParseComplete(bop.ID)
	if _, ok := s.Statement(s0.ID); ok {
		t.Fatal("expected S0 cleaned up once B committed and no longer needs rollback")
	}
}

func TestCorrelator_AbandonedSnapshotMutation_DoesNotAffectState(t *testing.T) {
	s, c := newCorrelator(t)
	_, s0, _ := s.CreateParse("", "SELECT 0", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	s.CreateBind("", "", nil, nil, nil)
	c.Handle(emptyBackendMsg(MsgBindComplete))
	s.CreateExecute("")
	s.CreateParse("", "SELECT B", nil)

	res, err := c.Handle(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.AbandonedOperations) != 1 {
		t.Fatalf("expected 1 abandoned")
	}

	res.FailedOperation.ID = 9999
	res.AbandonedOperations[0].ID = 9999
	res.AbandonedOperations[0].TargetGeneration = 9999

	cur, ok := s.ResolveStatement("")
	if !ok || cur.ID != s0.ID {
		t.Fatalf("expected S0 still restored correctly, unaffected by snapshot mutation: got %+v (ok=%v)", cur, ok)
	}
}

// --- Atomicity ------------------------------------------------------------

func TestCorrelator_Atomicity_MalformedResponseLeavesStateUnchanged(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	before := snapshotState(s)
	_, err := c.Handle(backendMsg(MsgParseComplete, []byte{1}))
	if err == nil {
		t.Fatal("expected error")
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_Atomicity_WrongAcknowledgementLeavesStateUnchanged(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	before := snapshotState(s)
	_, err := c.Handle(emptyBackendMsg(MsgBindComplete))
	if err == nil {
		t.Fatal("expected error")
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_Atomicity_ErrorResponseAbandonmentValidationFailureLeavesStateUnchanged(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateSync()
	before := snapshotState(s)
	_, err := c.Handle(minimalErrorResponse())
	if !errors.Is(err, ErrErrorResponseForSync) {
		t.Fatalf("expected ErrErrorResponseForSync, got %v", err)
	}
	assertStateUnchanged(t, before, snapshotState(s))
}

func TestCorrelator_Atomicity_DescribeSubstateCorrectAfterRejectedMessages(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	c.Handle(emptyBackendMsg(MsgParseComplete))
	dop, err := s.CreateDescribeStatement("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := c.Handle(backendMsg(MsgParameterDescription, []byte{0})); err == nil {
		t.Fatal("expected malformed ParameterDescription to be rejected")
	}
	if c.describeParamSeen[dop.ID] {
		t.Fatal("expected substate NOT seen after malformed rejection")
	}

	if _, err := c.Handle(paramDescMsg(nil)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.describeParamSeen[dop.ID] {
		t.Fatal("expected substate seen after valid ParameterDescription")
	}
}

// --- Misc / secret non-disclosure ------------------------------------

func TestCorrelator_ErrorResponse_NeverDisclosesServerText(t *testing.T) {
	s, c := newCorrelator(t)
	s.CreateParse("s1", "SELECT 1", nil)
	const secret = "SECRET_SERVER_TEXT_DO_NOT_LEAK"
	res, err := c.Handle(fieldedErrorResponse(secret))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsErrorResponse {
		t.Fatal("expected IsErrorResponse")
	}
	// CorrelationResult carries only names/IDs (bkz. dosya basi
	// "YALNIZCA sinirli, guvenli metadata") - a %+v dump must never contain
	// the ErrorResponse field value we deliberately embedded above.
	dump := fmt.Sprintf("%+v", res)
	if strings.Contains(dump, secret) {
		t.Fatalf("CorrelationResult leaked server ErrorResponse text: %s", dump)
	}
}

func TestCorrelator_MalformedMessage_ErrorNeverContainsSecretMarker(t *testing.T) {
	_, c := newCorrelator(t)
	const secret = "SECRET_MALFORMED_MARKER"
	body := append([]byte(secret), 0xFF) // malformed CommandComplete-shaped body used against wrong head
	_, err := c.Handle(backendMsg(MsgCommandComplete, body))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error text leaked marker: %v", err)
	}
}

// --- Fuzz / randomized sequence test ---------------------------------
//
// FuzzBackendCorrelatorSequence drives a short, bounded, byte-driven
// pseudo-random mix of frontend State.Create* calls (to build up
// realistic pending operations) and BackendCorrelator.Handle calls
// (correct terminals, real ErrorResponses, async messages, malformed
// bodies, COPY responses) and checks invariants after every step. This
// mirrors the established pattern in extended_state_test.go's
// FuzzExtendedStateSequence (reusing its opReader/checkStructuralInvariants
// helpers, same package) - it is a short bounded property test, not an
// exhaustive model-checker.

// correctTerminalFor returns a well-formed, successful terminal backend
// message for the given pending-operation kind.
func correctTerminalFor(kind OperationKind) Message {
	switch kind {
	case OpParse:
		return emptyBackendMsg(MsgParseComplete)
	case OpBind:
		return emptyBackendMsg(MsgBindComplete)
	case OpCloseStatement, OpClosePortal:
		return emptyBackendMsg(MsgCloseComplete)
	case OpDescribeStatement, OpDescribePortal:
		return emptyBackendMsg(MsgNoData)
	case OpExecute:
		return emptyBackendMsg(MsgEmptyQueryResponse)
	case OpSync:
		return rfqMsg(TxStatusIdle)
	}
	return emptyBackendMsg(MsgParseComplete)
}

func FuzzBackendCorrelatorSequence(f *testing.F) {
	f.Add([]byte{0, 0, 8, 0, 1, 0, 7, 8, 0, 4, 0})
	f.Add([]byte{0, 1, 0, 4, 8, 9})
	f.Add([]byte{7, 9, 11, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %v: %v", data, r)
			}
		}()

		s := NewState()
		c, err := NewBackendCorrelator(s)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		r := &opReader{data: data}
		stmtNames := []string{"", "s1", "s2"}
		portalNames := []string{"", "p1", "p2"}
		const secretMarker = "SECRET_FUZZ_MARKER"

		checkErrNoSecret := func(err error) {
			if err != nil && strings.Contains(err.Error(), secretMarker) {
				t.Fatalf("error text leaked secret marker: %v", err)
			}
		}

		for step := 0; step < 300; step++ {
			opb, ok := r.next()
			if !ok {
				break
			}
			switch int(opb) % 15 {
			case 0: // frontend: CreateParse
				i, ok := r.pick(len(stmtNames))
				if !ok {
					continue
				}
				s.CreateParse(stmtNames[i], "SELECT 1", nil)
			case 1: // frontend: CreateBind
				pi, ok1 := r.pick(len(portalNames))
				si, ok2 := r.pick(len(stmtNames))
				if !ok1 || !ok2 {
					continue
				}
				s.CreateBind(portalNames[pi], stmtNames[si], nil, nil, nil)
			case 2:
				i, ok := r.pick(len(stmtNames))
				if !ok {
					continue
				}
				s.CreateDescribeStatement(stmtNames[i])
			case 3:
				i, ok := r.pick(len(portalNames))
				if !ok {
					continue
				}
				s.CreateDescribePortal(portalNames[i])
			case 4:
				i, ok := r.pick(len(portalNames))
				if !ok {
					continue
				}
				s.CreateExecute(portalNames[i])
			case 5:
				i, ok := r.pick(len(stmtNames))
				if !ok {
					continue
				}
				s.CreateCloseStatement(stmtNames[i])
			case 6:
				i, ok := r.pick(len(portalNames))
				if !ok {
					continue
				}
				s.CreateClosePortal(portalNames[i])
			case 7:
				s.CreateSync()
			case 8: // backend: correct terminal for the current head
				head, ok := s.HeadPendingOperation()
				if !ok {
					continue
				}
				res, err := c.Handle(correctTerminalFor(head.Kind))
				checkErrNoSecret(err)
				if err == nil {
					if res.Async {
						t.Fatalf("a terminal response must not be Async")
					}
					if !res.OperationCompleted {
						t.Fatalf("expected a successful terminal to complete the operation, got %+v", res)
					}
					newHead, hasNew := s.HeadPendingOperation()
					if hasNew && newHead.ID == head.ID {
						t.Fatalf("successful terminal response must consume exactly the matching operation")
					}
				}
			case 9: // backend: real ErrorResponse against the current head
				head, hadHead := s.HeadPendingOperation()
				res, err := c.Handle(fieldedErrorResponse(secretMarker))
				checkErrNoSecret(err)
				if err == nil {
					if !hadHead {
						t.Fatalf("ErrorResponse succeeded with no pending head")
					}
					if head.Kind == OpSync {
						t.Fatalf("ErrorResponse must never succeed against a Sync head")
					}
					if res.FailedOperation.Cycle != head.Cycle {
						t.Fatalf("failed operation cycle mismatch: %+v vs head %+v", res.FailedOperation, head)
					}
					for _, ab := range res.AbandonedOperations {
						if ab.Cycle != head.Cycle {
							t.Fatalf("abandoned operation from a different cycle: %+v (failed cycle %d)", ab, head.Cycle)
						}
						if ab.Kind == OpSync {
							t.Fatalf("Sync must never be abandoned: %+v", ab)
						}
					}
					newHead, hasNew := s.HeadPendingOperation()
					if hasNew && newHead.ID == head.ID {
						t.Fatalf("a real ErrorResponse must consume the failing head operation")
					}
				}
			case 10: // backend: asynchronous message
				b, ok := r.next()
				if !ok {
					continue
				}
				types := []MessageType{MsgNoticeResponse, MsgParameterStatus, MsgNotificationResponse}
				mt := types[int(b)%len(types)]
				before := snapshotState(s)
				res, err := c.Handle(backendMsg(mt, []byte(secretMarker+"\x00")))
				checkErrNoSecret(err)
				if err != nil {
					t.Fatalf("an asynchronous message must never error: %v", err)
				}
				if !res.Async {
					t.Fatalf("expected an Async result for %v", mt)
				}
				assertStateUnchanged(t, before, snapshotState(s))
			case 11: // backend: ReadyForQuery with a random (possibly invalid) status
				b, ok := r.next()
				if !ok {
					continue
				}
				statuses := []byte{TxStatusIdle, TxStatusInTransaction, TxStatusFailedTransaction, 'X'}
				status := statuses[int(b)%len(statuses)]
				_, err := c.Handle(rfqMsg(status))
				checkErrNoSecret(err)
			case 12: // backend: malformed random-body message against a random type
				b1, ok1 := r.next()
				n, ok2 := r.pick(4)
				if !ok1 || !ok2 {
					continue
				}
				body := make([]byte, 0, n)
				for i := 0; i < n; i++ {
					bb, ok := r.next()
					if !ok {
						break
					}
					body = append(body, bb)
				}
				allTypes := []MessageType{
					MsgParseComplete, MsgBindComplete, MsgCloseComplete, MsgNoData,
					MsgEmptyQueryResponse, MsgPortalSuspended, MsgReadyForQuery,
					MsgParameterDescription, MsgRowDescription, MsgDataRow,
					MsgCommandComplete, MsgErrorResponse,
				}
				mt := allTypes[int(b1)%len(allTypes)]
				before := snapshotState(s)
				_, err := c.Handle(backendMsg(mt, body))
				checkErrNoSecret(err)
				if err != nil {
					assertStateUnchanged(t, before, snapshotState(s))
				}
			case 13: // backend: COPY response - always a fixed fail-closed error
				b, ok := r.next()
				if !ok {
					continue
				}
				copyTypes := []MessageType{MsgCopyInResponse, MsgCopyOutResponse, MsgCopyBothResponse}
				before := snapshotState(s)
				_, err := c.Handle(backendMsg(copyTypes[int(b)%len(copyTypes)], nil))
				if !errors.Is(err, ErrUnsupportedCopyResponse) {
					t.Fatalf("expected ErrUnsupportedCopyResponse, got %v", err)
				}
				assertStateUnchanged(t, before, snapshotState(s))
			case 14: // backend: ParameterDescription intermediate against the current head
				res, err := c.Handle(paramDescMsg([]uint32{23, 25}))
				checkErrNoSecret(err)
				if err == nil && !res.Intermediate {
					t.Fatalf("expected a successful ParameterDescription to be Intermediate, got %+v", res)
				}
			}

			checkStructuralInvariants(t, s)

			// Portals must never reference a missing statement generation.
			for id, p := range s.portals {
				if _, ok := s.statements[p.StatementID]; !ok {
					t.Fatalf("portal %d references missing statement generation %d", id, p.StatementID)
				}
			}
		}
	})
}

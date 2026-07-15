package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// --- Local test helpers ----------------------------------------------------
//
// backendMsg/emptyBackendMsg/rfqMsg/rowDescMsg/dataRowMsg/commandCompleteMsg/
// minimalErrorResponse/terminalOnlyErrorResponse/fieldedErrorResponse/
// paramDescMsg/opReader are ALL reused, unchanged, from
// extended_correlation_test.go/extended_state_test.go (same package) - per
// the task's explicit instruction not to duplicate existing helpers.

// frontendMsg builds a well-formed FRONTEND-direction Message - used only
// to prove SimpleQueryTracker.Handle rejects the wrong direction.
func frontendMsg(t MessageType, body []byte) Message {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(body)+4))
	raw := append([]byte{byte(t)}, length...)
	raw = append(raw, body...)
	return Message{Direction: Frontend, Type: t, Name: messageName(Frontend, t), Length: len(body) + 4, Raw: raw}
}

// rowDescBodyWithColumnName builds a single-field RowDescription body whose
// column name is exactly "name" - used to prove no column name is ever
// retained/returned by SimpleQueryTracker.
func rowDescBodyWithColumnName(name string) []byte {
	b := make([]byte, 0, 2+len(name)+1+rowFieldFixedPartLen)
	b = append(b, 0, 1) // field count = 1
	b = append(b, []byte(name)...)
	b = append(b, 0) // NUL terminator
	b = append(b, make([]byte, rowFieldFixedPartLen)...)
	return b
}

// dataRowBodyWithCellValue builds a single-cell DataRow body whose cell
// value is exactly "value" - used to prove no cell value is ever
// retained/returned by SimpleQueryTracker.
func dataRowBodyWithCellValue(value string) []byte {
	b := []byte{0, 1} // field count = 1
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(value)))
	b = append(b, lenBuf...)
	b = append(b, []byte(value)...)
	return b
}

// fieldedNoticeMsg mirrors fieldedErrorResponse (extended_correlation_test.go)
// for NoticeResponse, which shares the identical field-framing wire format.
func fieldedNoticeMsg(text string) Message {
	body := []byte{'S'}
	body = append(body, []byte("NOTICE")...)
	body = append(body, 0)
	body = append(body, 'M')
	body = append(body, []byte(text)...)
	body = append(body, 0)
	body = append(body, 0) // terminator
	return backendMsg(MsgNoticeResponse, body)
}

func paramStatusMsgWith(key, value string) Message {
	body := append([]byte(key), 0)
	body = append(body, []byte(value)...)
	body = append(body, 0)
	return backendMsg(MsgParameterStatus, body)
}

func notificationMsgWith(channel, payload string) Message {
	body := []byte{0, 0, 0, 1} // PID = 1
	body = append(body, []byte(channel)...)
	body = append(body, 0)
	body = append(body, []byte(payload)...)
	body = append(body, 0)
	return backendMsg(MsgNotificationResponse, body)
}

// newTracker returns a freshly Reset (active, AwaitingFirstMessage)
// SimpleQueryTracker, ready for a new cycle.
func newTracker() *SimpleQueryTracker {
	tr := &SimpleQueryTracker{}
	tr.Reset()
	return tr
}

// advance feeds a sequence of messages that MUST all succeed, failing the
// test immediately (with full context) on the first unexpected error.
// Returns the final SimpleQueryResult.
func advance(t *testing.T, tr *SimpleQueryTracker, msgs ...Message) SimpleQueryResult {
	t.Helper()
	var res SimpleQueryResult
	for i, m := range msgs {
		var err error
		res, err = tr.Handle(m)
		if err != nil {
			t.Fatalf("step %d (%s): unexpected error: %v", i, messageName(m.Direction, m.Type), err)
		}
	}
	return res
}

// assertRejectedThenRecovers issues "rejected" against tr, checks the exact
// expected error via errors.Is, confirms the tracker is still USABLE by
// then successfully handling "recovery" - proving the rejection left no
// partial/corrupt mutation behind (bkz. gereksinim: "atomicity").
func assertRejectedThenRecovers(t *testing.T, tr *SimpleQueryTracker, rejected Message, wantErr error, recovery Message) {
	t.Helper()
	_, err := tr.Handle(rejected)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v for rejected message, got %v", wantErr, err)
	}
	if _, err := tr.Handle(recovery); err != nil {
		t.Fatalf("expected the tracker to still accept the originally-expected valid message after the rejection, got: %v", err)
	}
}

// --- Lifecycle: zero value, Reset, IsIdle -----------------------------------

func TestSimpleQueryTracker_ZeroValueIsIdle(t *testing.T) {
	var tr SimpleQueryTracker
	if !tr.IsIdle() {
		t.Fatal("expected the zero value to be idle")
	}
}

func TestSimpleQueryTracker_ResetMakesItActive(t *testing.T) {
	var tr SimpleQueryTracker
	tr.Reset()
	if tr.IsIdle() {
		t.Fatal("expected an active (Reset) tracker to not be idle")
	}
}

func TestSimpleQueryTracker_HandleWhileIdle(t *testing.T) {
	var tr SimpleQueryTracker // never Reset
	_, err := tr.Handle(commandCompleteMsg("SELECT 1"))
	if !errors.Is(err, ErrSimpleResponseOrderingViolation) {
		t.Fatalf("expected ErrSimpleResponseOrderingViolation, got %v", err)
	}
	if !tr.IsIdle() {
		t.Fatal("expected the tracker to remain idle after a rejected Handle call while idle")
	}
	// Recovery: Reset must still work normally afterward.
	tr.Reset()
	if _, err := tr.Handle(commandCompleteMsg("SELECT 1")); err != nil {
		t.Fatalf("expected normal operation after Reset following an idle Handle call: %v", err)
	}
}

func TestSimpleQueryTracker_HandleAfterCompletedCycleIsIdle(t *testing.T) {
	tr := newTracker()
	res := advance(t, tr, commandCompleteMsg("SELECT 1"), rfqMsg(TxStatusIdle))
	if !res.CycleCompleted {
		t.Fatal("expected the cycle to complete")
	}
	if !tr.IsIdle() {
		t.Fatal("expected the tracker to be idle after a completed cycle")
	}
	_, err := tr.Handle(commandCompleteMsg("SELECT 1"))
	if !errors.Is(err, ErrSimpleResponseOrderingViolation) {
		t.Fatalf("expected ErrSimpleResponseOrderingViolation for Handle after completion without Reset, got %v", err)
	}
}

func TestSimpleQueryTracker_ResetFromAnyActivePhaseIsSafe(t *testing.T) {
	tr := newTracker()
	advance(t, tr, rowDescMsg(), dataRowMsg()) // now InRows, mid-cycle
	tr.Reset()
	if tr.IsIdle() {
		t.Fatal("expected Reset to leave the tracker active")
	}
	// A fresh cycle must behave completely independently of the abandoned one.
	res := advance(t, tr, commandCompleteMsg("SELECT 1"), rfqMsg(TxStatusIdle))
	if !res.CycleCompleted {
		t.Fatal("expected the new cycle to complete normally after a mid-cycle Reset")
	}
}

// --- Transition table: every (phase, message-type) combination -------------

// phaseSetup returns a sequence of valid messages that, applied in order to
// a freshly Reset tracker, land it exactly in the named phase.
func phaseSetup(name string) []Message {
	switch name {
	case "AwaitingFirstMessage":
		return nil
	case "AwaitingGroupOrReady":
		return []Message{commandCompleteMsg("SELECT 1")}
	case "InRows":
		return []Message{rowDescMsg()}
	case "AwaitingReadyOnly":
		return []Message{minimalErrorResponse()}
	}
	panic("unknown phase name: " + name)
}

func TestSimpleQueryTracker_TransitionTable(t *testing.T) {
	type step struct {
		phase              string
		input              Message
		inputName          string
		wantErr            error // nil means accepted
		wantCycleCompleted bool
	}
	steps := []step{
		// AwaitingFirstMessage
		{"AwaitingFirstMessage", rowDescMsg(), "RowDescription", nil, false},
		{"AwaitingFirstMessage", dataRowMsg(), "DataRow", ErrSimpleResponseOrderingViolation, false},
		{"AwaitingFirstMessage", commandCompleteMsg("SELECT 1"), "CommandComplete", nil, false},
		{"AwaitingFirstMessage", emptyBackendMsg(MsgEmptyQueryResponse), "EmptyQueryResponse", nil, false},
		{"AwaitingFirstMessage", minimalErrorResponse(), "ErrorResponse", nil, false},
		{"AwaitingFirstMessage", rfqMsg(TxStatusIdle), "ReadyForQuery", ErrSimpleResponseOrderingViolation, false},

		// AwaitingGroupOrReady
		{"AwaitingGroupOrReady", rowDescMsg(), "RowDescription", nil, false},
		{"AwaitingGroupOrReady", dataRowMsg(), "DataRow", ErrSimpleResponseOrderingViolation, false},
		{"AwaitingGroupOrReady", commandCompleteMsg("SELECT 1"), "CommandComplete", nil, false},
		{"AwaitingGroupOrReady", emptyBackendMsg(MsgEmptyQueryResponse), "EmptyQueryResponse", ErrSimpleResponseOrderingViolation, false},
		{"AwaitingGroupOrReady", minimalErrorResponse(), "ErrorResponse", nil, false},
		{"AwaitingGroupOrReady", rfqMsg(TxStatusIdle), "ReadyForQuery", nil, true},

		// InRows
		{"InRows", rowDescMsg(), "RowDescription", ErrSimpleResponseOrderingViolation, false},
		{"InRows", dataRowMsg(), "DataRow", nil, false},
		{"InRows", commandCompleteMsg("SELECT 1"), "CommandComplete", nil, false},
		{"InRows", emptyBackendMsg(MsgEmptyQueryResponse), "EmptyQueryResponse", ErrSimpleResponseOrderingViolation, false},
		{"InRows", minimalErrorResponse(), "ErrorResponse", nil, false},
		{"InRows", rfqMsg(TxStatusIdle), "ReadyForQuery", ErrSimpleResponseOrderingViolation, false},

		// AwaitingReadyOnly
		{"AwaitingReadyOnly", rowDescMsg(), "RowDescription", ErrSimpleResponseOrderingViolation, false},
		{"AwaitingReadyOnly", dataRowMsg(), "DataRow", ErrSimpleResponseOrderingViolation, false},
		{"AwaitingReadyOnly", commandCompleteMsg("SELECT 1"), "CommandComplete", ErrSimpleResponseOrderingViolation, false},
		{"AwaitingReadyOnly", emptyBackendMsg(MsgEmptyQueryResponse), "EmptyQueryResponse", ErrSimpleResponseOrderingViolation, false},
		{"AwaitingReadyOnly", minimalErrorResponse(), "ErrorResponse", ErrSimpleResponseOrderingViolation, false},
		{"AwaitingReadyOnly", rfqMsg(TxStatusIdle), "ReadyForQuery", nil, true},
	}

	for _, s := range steps {
		name := fmt.Sprintf("%s/%s", s.phase, s.inputName)
		t.Run(name, func(t *testing.T) {
			tr := newTracker()
			advance(t, tr, phaseSetup(s.phase)...)

			res, err := tr.Handle(s.input)
			if s.wantErr != nil {
				if !errors.Is(err, s.wantErr) {
					t.Fatalf("expected %v, got %v", s.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.CycleCompleted != s.wantCycleCompleted {
				t.Fatalf("expected CycleCompleted=%v, got %v", s.wantCycleCompleted, res.CycleCompleted)
			}
		})
	}
}

// TestSimpleQueryTracker_StructuralValidationPrecedesOrderingCheck proves a
// malformed body in a phase where the message type would ALSO be wrong-
// order yields the STRUCTURAL error, not the ordering error - structural
// validation always runs first, independent of phase (bkz. Handle's own
// documented precedence).
func TestSimpleQueryTracker_StructuralValidationPrecedesOrderingCheck(t *testing.T) {
	tr := newTracker()
	advance(t, tr, minimalErrorResponse()) // now AwaitingReadyOnly - DataRow is wrong-order here too
	_, err := tr.Handle(backendMsg(MsgDataRow, []byte{0, 1}))
	if !errors.Is(err, ErrMalformedBackendMessage) {
		t.Fatalf("expected the STRUCTURAL error (ErrMalformedBackendMessage) to take precedence over the ordering error, got %v", err)
	}
}

// --- Valid complete sequences (design doc "Valid complete sequences" 1-15) -

func TestSimpleQueryTracker_Sequence1_CommandCompleteOnly(t *testing.T) {
	tr := newTracker()
	res := advance(t, tr, commandCompleteMsg("SELECT 1"), rfqMsg(TxStatusIdle))
	if !res.CycleCompleted || res.ReadyForQueryStatus != TxStatusIdle {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !tr.IsIdle() {
		t.Fatal("expected idle after completion")
	}
}

func TestSimpleQueryTracker_Sequence2_RowGroupThenCommandComplete(t *testing.T) {
	tr := newTracker()
	res := advance(t, tr, rowDescMsg(), commandCompleteMsg("SELECT 1"), rfqMsg(TxStatusIdle))
	if !res.CycleCompleted {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestSimpleQueryTracker_Sequence3_RowGroupWithMultipleDataRows(t *testing.T) {
	tr := newTracker()
	res := advance(t, tr, rowDescMsg(), dataRowMsg(), dataRowMsg(), dataRowMsg(), commandCompleteMsg("SELECT 3"), rfqMsg(TxStatusIdle))
	if !res.CycleCompleted {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestSimpleQueryTracker_Sequence4_EmptyQuery(t *testing.T) {
	tr := newTracker()
	res := advance(t, tr, emptyBackendMsg(MsgEmptyQueryResponse), rfqMsg(TxStatusIdle))
	if !res.CycleCompleted {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestSimpleQueryTracker_Sequence5_ImmediateError(t *testing.T) {
	tr := newTracker()
	res := advance(t, tr, minimalErrorResponse(), rfqMsg(TxStatusFailedTransaction))
	if !res.CycleCompleted || res.ReadyForQueryStatus != TxStatusFailedTransaction {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestSimpleQueryTracker_Sequence6_RowsThenMidStreamError(t *testing.T) {
	tr := newTracker()
	res := advance(t, tr, rowDescMsg(), dataRowMsg(), minimalErrorResponse(), rfqMsg(TxStatusIdle))
	if !res.CycleCompleted {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestSimpleQueryTracker_Sequence7_MultipleCommandCompleteGroups(t *testing.T) {
	tr := newTracker()
	res := advance(t, tr,
		commandCompleteMsg("INSERT 0 1"),
		commandCompleteMsg("INSERT 0 1"),
		commandCompleteMsg("INSERT 0 1"),
		rfqMsg(TxStatusIdle),
	)
	if !res.CycleCompleted {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestSimpleQueryTracker_Sequence8_CommandThenRowThenCommand(t *testing.T) {
	tr := newTracker()
	res := advance(t, tr,
		commandCompleteMsg("SET x = 1"),
		rowDescMsg(), dataRowMsg(), commandCompleteMsg("SELECT 1"),
		commandCompleteMsg("SET y = 2"),
		rfqMsg(TxStatusIdle),
	)
	if !res.CycleCompleted {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestSimpleQueryTracker_Sequence9_RowThenCommandThenRow(t *testing.T) {
	tr := newTracker()
	res := advance(t, tr,
		rowDescMsg(), dataRowMsg(), commandCompleteMsg("SELECT 1"),
		commandCompleteMsg("SET x = 1"),
		rowDescMsg(), dataRowMsg(), commandCompleteMsg("SELECT 1"),
		rfqMsg(TxStatusIdle),
	)
	if !res.CycleCompleted {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestSimpleQueryTracker_Sequence10_LaterStatementError(t *testing.T) {
	tr := newTracker()
	res := advance(t, tr,
		commandCompleteMsg("SELECT 1"),
		minimalErrorResponse(),
		rfqMsg(TxStatusIdle),
	)
	if !res.CycleCompleted {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestSimpleQueryTracker_Sequence11_AsyncBeforeFirstOrdinaryResponse(t *testing.T) {
	tr := newTracker()
	res, err := tr.Handle(fieldedNoticeMsg("hello"))
	if err != nil || !res.Async {
		t.Fatalf("expected an accepted async result, got res=%+v err=%v", res, err)
	}
	if tr.IsIdle() {
		t.Fatal("expected phase to remain unaffected (active) by an async message")
	}
	final := advance(t, tr, commandCompleteMsg("SELECT 1"), rfqMsg(TxStatusIdle))
	if !final.CycleCompleted {
		t.Fatalf("unexpected result: %+v", final)
	}
}

func TestSimpleQueryTracker_Sequence12_AsyncBetweenRowsAndCommand(t *testing.T) {
	tr := newTracker()
	advance(t, tr, rowDescMsg(), dataRowMsg())
	res, err := tr.Handle(paramStatusMsgWith("k", "v"))
	if err != nil || !res.Async {
		t.Fatalf("expected an accepted async result mid-rows, got res=%+v err=%v", res, err)
	}
	final := advance(t, tr, dataRowMsg(), commandCompleteMsg("SELECT 2"), rfqMsg(TxStatusIdle))
	if !final.CycleCompleted {
		t.Fatalf("unexpected result: %+v", final)
	}
}

func TestSimpleQueryTracker_Sequence13_AsyncAfterErrorBeforeReady(t *testing.T) {
	tr := newTracker()
	advance(t, tr, minimalErrorResponse())
	res, err := tr.Handle(notificationMsgWith("ch", "payload"))
	if err != nil || !res.Async {
		t.Fatalf("expected an accepted async result after ErrorResponse, got res=%+v err=%v", res, err)
	}
	final := advance(t, tr, rfqMsg(TxStatusIdle))
	if !final.CycleCompleted {
		t.Fatalf("unexpected result: %+v", final)
	}
}

func TestSimpleQueryTracker_Sequence14_TerminalStatusesITE(t *testing.T) {
	for _, status := range []byte{TxStatusIdle, TxStatusInTransaction, TxStatusFailedTransaction} {
		tr := newTracker()
		res := advance(t, tr, commandCompleteMsg("SELECT 1"), rfqMsg(status))
		if !res.CycleCompleted || res.ReadyForQueryStatus != status {
			t.Fatalf("status %q: unexpected result: %+v", status, res)
		}
		if !tr.IsIdle() {
			t.Fatalf("status %q: expected idle after completion", status)
		}
	}
}

func TestSimpleQueryTracker_Sequence15_ReuseAcrossManyResetCycles(t *testing.T) {
	tr := newTracker() // one instance, reused - never reallocated
	for i := 0; i < 500; i++ {
		if i > 0 {
			tr.Reset()
		}
		res := advance(t, tr, commandCompleteMsg("SELECT 1"), rfqMsg(TxStatusIdle))
		if !res.CycleCompleted {
			t.Fatalf("cycle %d: unexpected result: %+v", i, res)
		}
		if !tr.IsIdle() {
			t.Fatalf("cycle %d: expected idle after completion", i)
		}
	}
}

// --- Invalid ordering: every rejected transition, atomicity-checked --------

func TestSimpleQueryTracker_Reject_BareReadyForQuery(t *testing.T) {
	tr := newTracker()
	assertRejectedThenRecovers(t, tr, rfqMsg(TxStatusIdle), ErrSimpleResponseOrderingViolation, commandCompleteMsg("SELECT 1"))
}

func TestSimpleQueryTracker_Reject_DataRowBeforeRowDescription(t *testing.T) {
	tr := newTracker()
	assertRejectedThenRecovers(t, tr, dataRowMsg(), ErrSimpleResponseOrderingViolation, commandCompleteMsg("SELECT 1"))
}

func TestSimpleQueryTracker_Reject_DuplicateRowDescription(t *testing.T) {
	tr := newTracker()
	advance(t, tr, rowDescMsg())
	assertRejectedThenRecovers(t, tr, rowDescMsg(), ErrSimpleResponseOrderingViolation, dataRowMsg())
}

func TestSimpleQueryTracker_Reject_ReadyForQueryDuringInRows(t *testing.T) {
	tr := newTracker()
	advance(t, tr, rowDescMsg())
	assertRejectedThenRecovers(t, tr, rfqMsg(TxStatusIdle), ErrSimpleResponseOrderingViolation, dataRowMsg())
}

func TestSimpleQueryTracker_Reject_EmptyQueryResponseAfterAnotherGroup(t *testing.T) {
	tr := newTracker()
	advance(t, tr, commandCompleteMsg("SELECT 1"))
	assertRejectedThenRecovers(t, tr, emptyBackendMsg(MsgEmptyQueryResponse), ErrSimpleResponseOrderingViolation, commandCompleteMsg("SELECT 2"))
}

func TestSimpleQueryTracker_Reject_AnythingExceptReadyForQueryAfterEmptyQueryResponse(t *testing.T) {
	for name, msg := range map[string]Message{
		"RowDescription":  rowDescMsg(),
		"DataRow":         dataRowMsg(),
		"CommandComplete": commandCompleteMsg("SELECT 1"),
		"ErrorResponse":   minimalErrorResponse(),
	} {
		t.Run(name, func(t *testing.T) {
			tr := newTracker()
			advance(t, tr, emptyBackendMsg(MsgEmptyQueryResponse))
			assertRejectedThenRecovers(t, tr, msg, ErrSimpleResponseOrderingViolation, rfqMsg(TxStatusIdle))
		})
	}
}

func TestSimpleQueryTracker_Reject_AnythingExceptReadyForQueryAfterErrorResponse(t *testing.T) {
	for name, msg := range map[string]Message{
		"RowDescription":  rowDescMsg(),
		"DataRow":         dataRowMsg(),
		"CommandComplete": commandCompleteMsg("SELECT 1"),
	} {
		t.Run(name, func(t *testing.T) {
			tr := newTracker()
			advance(t, tr, minimalErrorResponse())
			assertRejectedThenRecovers(t, tr, msg, ErrSimpleResponseOrderingViolation, rfqMsg(TxStatusIdle))
		})
	}
}

func TestSimpleQueryTracker_Reject_DuplicateErrorResponse(t *testing.T) {
	tr := newTracker()
	advance(t, tr, minimalErrorResponse())
	assertRejectedThenRecovers(t, tr, minimalErrorResponse(), ErrSimpleResponseOrderingViolation, rfqMsg(TxStatusIdle))
}

func TestSimpleQueryTracker_Reject_PortalSuspendedInEveryPhase(t *testing.T) {
	for _, phase := range []string{"AwaitingFirstMessage", "AwaitingGroupOrReady", "InRows", "AwaitingReadyOnly"} {
		t.Run(phase, func(t *testing.T) {
			tr := newTracker()
			advance(t, tr, phaseSetup(phase)...)
			_, err := tr.Handle(emptyBackendMsg(MsgPortalSuspended))
			if !errors.Is(err, ErrSimpleResponseOrderingViolation) {
				t.Fatalf("expected ErrSimpleResponseOrderingViolation, got %v", err)
			}
		})
	}
}

func TestSimpleQueryTracker_Reject_ExtendedOnlyBackendMessages(t *testing.T) {
	extendedOnly := map[string]Message{
		"ParseComplete":        emptyBackendMsg(MsgParseComplete),
		"BindComplete":         emptyBackendMsg(MsgBindComplete),
		"CloseComplete":        emptyBackendMsg(MsgCloseComplete),
		"ParameterDescription": paramDescMsg(nil),
		"NoData":               emptyBackendMsg(MsgNoData),
	}
	for name, msg := range extendedOnly {
		t.Run(name, func(t *testing.T) {
			tr := newTracker()
			_, err := tr.Handle(msg)
			if !errors.Is(err, ErrSimpleResponseOrderingViolation) {
				t.Fatalf("expected ErrSimpleResponseOrderingViolation, got %v", err)
			}
			if tr.IsIdle() {
				t.Fatal("expected phase to remain unaffected by a rejected Extended-only message")
			}
		})
	}
}

func TestSimpleQueryTracker_Reject_StartupOnlyMessages(t *testing.T) {
	for name, msg := range map[string]Message{
		"Authentication": emptyBackendMsg(MsgAuthentication),
		"BackendKeyData": emptyBackendMsg(MsgBackendKeyData),
	} {
		t.Run(name, func(t *testing.T) {
			tr := newTracker()
			assertRejectedThenRecovers(t, tr, msg, ErrWrongBackendPhase, commandCompleteMsg("SELECT 1"))
		})
	}
}

func TestSimpleQueryTracker_Reject_COPYResponsesInEveryPhase(t *testing.T) {
	copyTypes := []MessageType{MsgCopyInResponse, MsgCopyOutResponse, MsgCopyBothResponse}
	for _, phase := range []string{"AwaitingFirstMessage", "AwaitingGroupOrReady", "InRows", "AwaitingReadyOnly"} {
		for _, ct := range copyTypes {
			t.Run(fmt.Sprintf("%s/%s", phase, messageName(Backend, ct)), func(t *testing.T) {
				tr := newTracker()
				advance(t, tr, phaseSetup(phase)...)
				_, err := tr.Handle(emptyBackendMsg(ct))
				if !errors.Is(err, ErrSimpleQueryCOPYUnsupported) {
					t.Fatalf("expected ErrSimpleQueryCOPYUnsupported, got %v", err)
				}
			})
		}
	}
}

func TestSimpleQueryTracker_Reject_UnknownMessageType(t *testing.T) {
	tr := newTracker()
	assertRejectedThenRecovers(t, tr, backendMsg(MessageType('?'), nil), ErrSimpleResponseOrderingViolation, commandCompleteMsg("SELECT 1"))
}

func TestSimpleQueryTracker_Reject_WrongDirection(t *testing.T) {
	tr := newTracker()
	assertRejectedThenRecovers(t, tr, frontendMsg(MsgQuery, []byte("SELECT 1\x00")), ErrWrongBackendPhase, commandCompleteMsg("SELECT 1"))
}

func TestSimpleQueryTracker_Reject_TruncatedMessage(t *testing.T) {
	tr := newTracker()
	truncated := Message{Direction: Backend, Type: MsgCommandComplete, Raw: []byte{'C', 0, 0}}
	assertRejectedThenRecovers(t, tr, truncated, ErrMalformedBackendMessage, commandCompleteMsg("SELECT 1"))
}

// --- Malformed bodies for every accepted message type -----------------------

func TestSimpleQueryTracker_Reject_MalformedRowDescription(t *testing.T) {
	tr := newTracker()
	malformed := backendMsg(MsgRowDescription, []byte{0, 1}) // claims 1 field, no data follows
	assertRejectedThenRecovers(t, tr, malformed, ErrMalformedBackendMessage, rowDescMsg())
}

func TestSimpleQueryTracker_Reject_MalformedDataRow(t *testing.T) {
	tr := newTracker()
	advance(t, tr, rowDescMsg()) // now InRows
	malformed := backendMsg(MsgDataRow, []byte{0, 1})
	assertRejectedThenRecovers(t, tr, malformed, ErrMalformedBackendMessage, dataRowMsg())
}

func TestSimpleQueryTracker_Reject_MalformedCommandComplete(t *testing.T) {
	tr := newTracker()
	missingTerminator := backendMsg(MsgCommandComplete, []byte("SELECT 1")) // no trailing NUL
	assertRejectedThenRecovers(t, tr, missingTerminator, ErrMalformedBackendMessage, commandCompleteMsg("SELECT 1"))

	tr2 := newTracker()
	trailingByte := backendMsg(MsgCommandComplete, append([]byte("SELECT 1\x00"), 'X'))
	assertRejectedThenRecovers(t, tr2, trailingByte, ErrMalformedBackendMessage, commandCompleteMsg("SELECT 1"))
}

func TestSimpleQueryTracker_Reject_MalformedErrorResponse(t *testing.T) {
	tr := newTracker()
	assertRejectedThenRecovers(t, tr, terminalOnlyErrorResponse(), ErrMalformedBackendMessage, minimalErrorResponse())
}

func TestSimpleQueryTracker_Reject_MalformedEmptyQueryResponse(t *testing.T) {
	tr := newTracker()
	nonEmpty := backendMsg(MsgEmptyQueryResponse, []byte{1})
	assertRejectedThenRecovers(t, tr, nonEmpty, ErrMalformedBackendMessage, emptyBackendMsg(MsgEmptyQueryResponse))
}

func TestSimpleQueryTracker_Reject_MalformedAsyncMessages(t *testing.T) {
	t.Run("Notice", func(t *testing.T) {
		tr := newTracker()
		assertRejectedThenRecovers(t, tr, backendMsg(MsgNoticeResponse, []byte{0}), ErrMalformedBackendMessage, fieldedNoticeMsg("ok"))
	})
	t.Run("ParameterStatus", func(t *testing.T) {
		tr := newTracker()
		assertRejectedThenRecovers(t, tr, backendMsg(MsgParameterStatus, []byte{'k', 0}), ErrMalformedBackendMessage, paramStatusMsgWith("k", "v"))
	})
	t.Run("NotificationResponse", func(t *testing.T) {
		tr := newTracker()
		assertRejectedThenRecovers(t, tr, backendMsg(MsgNotificationResponse, []byte{0, 0, 0}), ErrMalformedBackendMessage, notificationMsgWith("ch", "p"))
	})
}

func TestSimpleQueryTracker_Reject_InvalidReadyForQueryStatus(t *testing.T) {
	tr := newTracker()
	advance(t, tr, commandCompleteMsg("SELECT 1")) // AwaitingGroupOrReady
	assertRejectedThenRecovers(t, tr, rfqMsg('X'), ErrInvalidTransactionStatus, rfqMsg(TxStatusIdle))
}

func TestSimpleQueryTracker_Reject_ReadyForQueryWrongBodyLength(t *testing.T) {
	tr := newTracker()
	advance(t, tr, commandCompleteMsg("SELECT 1"))
	tooLong := backendMsg(MsgReadyForQuery, []byte{TxStatusIdle, TxStatusIdle})
	assertRejectedThenRecovers(t, tr, tooLong, ErrMalformedBackendMessage, rfqMsg(TxStatusIdle))
}

// --- Async behavior never mutates the active phase --------------------------

func TestSimpleQueryTracker_AsyncNeverChangesPhase(t *testing.T) {
	for _, phase := range []string{"AwaitingFirstMessage", "AwaitingGroupOrReady", "InRows", "AwaitingReadyOnly"} {
		t.Run(phase, func(t *testing.T) {
			tr := newTracker()
			advance(t, tr, phaseSetup(phase)...)
			for _, m := range []Message{fieldedNoticeMsg("x"), paramStatusMsgWith("k", "v"), notificationMsgWith("ch", "p")} {
				res, err := tr.Handle(m)
				if err != nil || !res.Async {
					t.Fatalf("expected accepted async result in phase %s, got res=%+v err=%v", phase, res, err)
				}
			}
			// The phase is provably unaffected: whatever the phase accepted
			// before the async messages, it still accepts (or still
			// rejects) the same way afterward. We confirm by checking
			// IsIdle() is still false (still active, still mid-cycle) and
			// that a message specific to this phase's setup continuation
			// still works where expected.
			if tr.IsIdle() {
				t.Fatalf("expected tracker to remain active (not idle) in phase %s after async messages", phase)
			}
		})
	}
}

// --- SimpleQueryResult field contract ---------------------------------------

func TestSimpleQueryResult_ZeroValueReadyForQueryStatusForNonCompletingMessages(t *testing.T) {
	tr := newTracker()
	res, err := tr.Handle(commandCompleteMsg("SELECT 1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.CycleCompleted {
		t.Fatal("did not expect CycleCompleted for a non-terminal CommandComplete")
	}
	if res.ReadyForQueryStatus != 0 {
		t.Fatalf("expected zero-value ReadyForQueryStatus for a non-completing message, got %q", res.ReadyForQueryStatus)
	}
}

func TestSimpleQueryResult_MessageTypeAlwaysSetOnSuccess(t *testing.T) {
	tr := newTracker()
	res, err := tr.Handle(rowDescMsg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.MessageType != MsgRowDescription {
		t.Fatalf("expected MessageType MsgRowDescription, got %v", res.MessageType)
	}
}

// TestSimpleQueryResult_NoStringOrByteSliceFields is a light, non-brittle
// structural guarantee (reflection-based, no field names hardcoded): as
// long as SimpleQueryResult never gains a string/slice-kinded exported
// field, no payload-sourced content (SQL, tags, values, names) can ever be
// smuggled through it, even by a future, careless edit.
func TestSimpleQueryResult_NoStringOrByteSliceFields(t *testing.T) {
	typ := reflect.TypeOf(SimpleQueryResult{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		switch f.Type.Kind() {
		case reflect.String, reflect.Slice, reflect.Map, reflect.Ptr, reflect.Interface:
			t.Fatalf("SimpleQueryResult.%s has kind %s - result fields must be bounded value types only", f.Name, f.Type.Kind())
		}
	}
}

// --- CommandComplete lifecycle-effect classification ------------------------
//
// Verified against the official PostgreSQL 18 source
// (src/include/tcop/cmdtaglist.h, src/backend/tcop/utility.c's
// CreateCommandTag) and postgresql.org/docs/current/sql-discard.html,
// sql-commit-prepared.html, sql-prepare-transaction.html - see
// docs/design/0002-mixed-query-routing.md's "CommandComplete lifecycle-
// effect classification" section for the full citations.

func TestSimpleQueryTracker_CommandCompleteLifecycleClassification(t *testing.T) {
	cases := []struct {
		tag        string
		wantEffect SimpleQueryLifecycleEffect
	}{
		// Ordinary counted DML/query tags - never lifecycle-affecting.
		{"SELECT 1", SimpleQueryLifecycleNone},
		{"INSERT 0 5", SimpleQueryLifecycleNone},
		{"UPDATE 3", SimpleQueryLifecycleNone},
		{"DELETE 2", SimpleQueryLifecycleNone},
		{"MERGE 1", SimpleQueryLifecycleNone},
		{"COPY 10", SimpleQueryLifecycleNone},

		// COMMIT-family: PostgreSQL's CreateCommandTag maps COMMIT, END, and
		// COMMIT AND CHAIN all to the single tag "COMMIT" (TRANS_STMT_COMMIT,
		// unconditional on the chain flag) - current-transaction-ending,
		// portal-invalidating.
		{"COMMIT", SimpleQueryInvalidatePortals},

		// ROLLBACK-family: PostgreSQL's CreateCommandTag maps ROLLBACK,
		// ABORT, ROLLBACK AND CHAIN, AND ROLLBACK TO SAVEPOINT all to the
		// single tag "ROLLBACK" ("case TRANS_STMT_ROLLBACK: case
		// TRANS_STMT_ROLLBACK_TO: tag = CMDTAG_ROLLBACK;") - the tag alone
		// cannot distinguish a savepoint-only rollback from a full
		// transaction rollback, so this is deliberately, conservatively
		// classified as portal-invalidating for every occurrence.
		{"ROLLBACK", SimpleQueryInvalidatePortals},

		// PREPARE TRANSACTION: "not unlike a ROLLBACK command: after
		// executing it, there is no active current transaction"
		// (sql-prepare-transaction.html) - portal-invalidating.
		{"PREPARE TRANSACTION", SimpleQueryInvalidatePortals},

		// COMMIT PREPARED/ROLLBACK PREPARED operate on an EXTERNALLY
		// prepared (two-phase-commit) transaction by name, never the
		// current session transaction - sql-commit-prepared.html: "This
		// command cannot be executed inside a transaction block" - no
		// effect on currently-tracked portals.
		{"COMMIT PREPARED", SimpleQueryLifecycleNone},
		{"ROLLBACK PREPARED", SimpleQueryLifecycleNone},

		// DEALLOCATE (named or ALL): destroys prepared statement(s); the
		// tag never carries the deallocated name, so every tracked
		// statement AND portal is conservatively invalidated.
		{"DEALLOCATE", SimpleQueryInvalidateStatementsAndPortals},
		{"DEALLOCATE ALL", SimpleQueryInvalidateStatementsAndPortals},

		// DISCARD ALL is documented as equivalent to "CLOSE ALL; ...;
		// DEALLOCATE ALL; ...; DISCARD PLANS; DISCARD TEMP; DISCARD
		// SEQUENCES" (sql-discard.html) - both statements and portals gone.
		{"DISCARD ALL", SimpleQueryInvalidateStatementsAndPortals},

		// DISCARD PLANS/SEQUENCES/TEMP do NOT drop prepared statements or
		// portals (sql-discard.html: DISCARD PLANS "does NOT drop or
		// destroy prepared statements... only releases the cached query
		// plans") - no effect. Must NOT receive the ALL effect.
		{"DISCARD PLANS", SimpleQueryLifecycleNone},
		{"DISCARD SEQUENCES", SimpleQueryLifecycleNone},
		{"DISCARD TEMP", SimpleQueryLifecycleNone},

		// SQL cursor-close commands: CLOSE <name> -> "CLOSE CURSOR"; CLOSE
		// ALL -> "CLOSE CURSOR ALL" (utility.c's T_ClosePortalStmt handling)
		// - neither tag carries the closed cursor's name, so every tracked
		// portal is conservatively invalidated; statements unaffected.
		{"CLOSE CURSOR", SimpleQueryInvalidatePortals},
		{"CLOSE CURSOR ALL", SimpleQueryInvalidatePortals},

		// DECLARE CURSOR creates a new SQL-level cursor never imported into
		// protocol.State (see the SQL-created-object fail-closed
		// limitation) - nothing tracked is destroyed.
		{"DECLARE CURSOR", SimpleQueryLifecycleNone},

		// FETCH only reads rows from an existing cursor; MOVE only
		// repositions one - neither ever destroys a cursor/portal
		// (utility.c: stmt->ismove picks FETCH vs MOVE, no destructive
		// dimension in the tag).
		{"FETCH 1", SimpleQueryLifecycleNone},
		{"MOVE 1", SimpleQueryLifecycleNone},

		// Transaction-starting/savepoint-manipulating commands never
		// destroy any currently-tracked object.
		{"BEGIN", SimpleQueryLifecycleNone},
		{"START TRANSACTION", SimpleQueryLifecycleNone},
		{"SAVEPOINT", SimpleQueryLifecycleNone},
		{"RELEASE", SimpleQueryLifecycleNone},

		// SQL PREPARE/EXECUTE create/use an SQL-level prepared statement
		// never imported into protocol.State - nothing tracked is
		// destroyed.
		{"PREPARE", SimpleQueryLifecycleNone},
		{"EXECUTE", SimpleQueryLifecycleNone},

		// Guard explicitly against prefix/substring-matching confusion:
		// none of these must be classified the same as their "real" tag
		// prefix, since classification is EXACT full-string equality only.
		{"COMMIT PREPAREDX", SimpleQueryLifecycleNone},
		{"DISCARD ALLX", SimpleQueryLifecycleNone},
		{"XDISCARD ALL", SimpleQueryLifecycleNone},
		{"COMMIT ", SimpleQueryLifecycleNone}, // trailing space is not "COMMIT"
	}

	for _, c := range cases {
		t.Run(c.tag, func(t *testing.T) {
			tr := newTracker()
			res, err := tr.Handle(commandCompleteMsg(c.tag))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.LifecycleEffect != c.wantEffect {
				t.Fatalf("tag %q: expected effect %v, got %v", c.tag, c.wantEffect, res.LifecycleEffect)
			}
		})
	}
}

func TestSimpleQueryTracker_CommandCompleteLifecycleEffect_MalformedReturnsNone(t *testing.T) {
	tr := newTracker()
	malformed := backendMsg(MsgCommandComplete, []byte("COMMIT")) // no NUL terminator
	res, err := tr.Handle(malformed)
	if !errors.Is(err, ErrMalformedBackendMessage) {
		t.Fatalf("expected ErrMalformedBackendMessage, got %v", err)
	}
	if res.LifecycleEffect != SimpleQueryLifecycleNone {
		t.Fatalf("expected no lifecycle effect on a malformed CommandComplete, got %v", res.LifecycleEffect)
	}
}

func TestSimpleQueryTracker_CommandCompleteLifecycleEffect_OrderingInvalidReturnsNone(t *testing.T) {
	tr := newTracker()
	advance(t, tr, minimalErrorResponse()) // now AwaitingReadyOnly - CommandComplete is ordering-invalid here
	res, err := tr.Handle(commandCompleteMsg("COMMIT"))
	if !errors.Is(err, ErrSimpleResponseOrderingViolation) {
		t.Fatalf("expected ErrSimpleResponseOrderingViolation, got %v", err)
	}
	if res.LifecycleEffect != SimpleQueryLifecycleNone {
		t.Fatalf("expected no lifecycle effect on an ordering-invalid CommandComplete, got %v", res.LifecycleEffect)
	}
	if _, err := tr.Handle(rfqMsg(TxStatusIdle)); err != nil {
		t.Fatalf("expected the tracker to still recover normally: %v", err)
	}
}

func TestSimpleQueryTracker_LifecycleEffect_NoMarkerLeakage(t *testing.T) {
	const marker = "SECRET_LIFECYCLE_MARKER"
	tr := newTracker()
	res, err := tr.Handle(commandCompleteMsg("SELECT-" + marker))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.LifecycleEffect != SimpleQueryLifecycleNone {
		t.Fatalf("expected no effect for an unrecognized tag, got %v", res.LifecycleEffect)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		s := fmt.Sprintf(format, res)
		if strings.Contains(s, marker) {
			t.Fatalf("marker leaked via %s: %s", format, s)
		}
	}

	// Also confirm a RECOGNIZED lifecycle tag's own result never contains
	// row-count/tag/marker text - only the fixed enum value.
	tr2 := newTracker()
	res2, err := tr2.Handle(commandCompleteMsg("DEALLOCATE"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res2.LifecycleEffect != SimpleQueryInvalidateStatementsAndPortals {
		t.Fatalf("expected SimpleQueryInvalidateStatementsAndPortals, got %v", res2.LifecycleEffect)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		s := fmt.Sprintf(format, res2)
		if strings.Contains(s, "DEALLOCATE") {
			t.Fatalf("raw tag text leaked via %s: %s", format, s)
		}
	}
}

// --- Privacy: no marker-bearing payload content ever leaks ------------------

func TestSimpleQueryTracker_NoMarkerLeakage(t *testing.T) {
	const marker = "SECRET_SIMPLEQUERY_MARKER"
	tr := newTracker()

	checkNoLeak := func(label string, v interface{}) {
		t.Helper()
		for _, format := range []string{"%v", "%+v", "%#v"} {
			s := fmt.Sprintf(format, v)
			if strings.Contains(s, marker) {
				t.Fatalf("%s: marker leaked via %s: %s", label, format, s)
			}
		}
	}

	res, err := tr.Handle(backendMsg(MsgRowDescription, rowDescBodyWithColumnName(marker)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkNoLeak("RowDescription result", res)

	res, err = tr.Handle(backendMsg(MsgDataRow, dataRowBodyWithCellValue(marker)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkNoLeak("DataRow result", res)

	res, err = tr.Handle(commandCompleteMsg(marker))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkNoLeak("CommandComplete result", res)

	res, err = tr.Handle(fieldedErrorResponse(marker))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkNoLeak("ErrorResponse result", res)

	res, err = tr.Handle(rfqMsg(TxStatusIdle))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkNoLeak("ReadyForQuery result", res)
	if !res.CycleCompleted {
		t.Fatal("expected the cycle to complete")
	}

	// Also confirm markers never leak through async message results, or
	// through a rejected-message error string.
	tr2 := newTracker()
	res, err = tr2.Handle(fieldedNoticeMsg(marker))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkNoLeak("Notice async result", res)

	res, err = tr2.Handle(paramStatusMsgWith(marker, marker))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkNoLeak("ParameterStatus async result", res)

	res, err = tr2.Handle(notificationMsgWith(marker, marker))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checkNoLeak("NotificationResponse async result", res)

	_, err = tr2.Handle(backendMsg(MsgRowDescription, []byte{0, 1})) // malformed while InRows-invalid; just needs an error path
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("marker leaked via error text: %s", err.Error())
	}
}

// --- Fuzz -------------------------------------------------------------------
//
// FuzzSimpleQueryTracker drives a short, bounded, byte-driven pseudo-random
// mix of every SimpleQueryTracker.Handle input class (valid/malformed
// ordinary messages, valid/malformed async messages, COPY, PortalSuspended,
// Extended-only/startup-only messages, and status-byte variation for
// ReadyForQuery) against a single, reused tracker instance, checking
// invariants after every step. This mirrors the established pattern in
// extended_correlation_test.go's FuzzBackendCorrelatorSequence (same
// package, same opReader helper) - a short, bounded property test, not an
// exhaustive model-checker.
func FuzzSimpleQueryTracker(f *testing.F) {
	f.Add([]byte{6, 13, 'I', 20})
	f.Add([]byte{2, 13, 'T', 20})
	f.Add([]byte{0, 4, 6, 13, 'E', 20})
	f.Add([]byte{9, 13, 'I', 20})
	f.Add([]byte{10, 13, 'I', 20})
	f.Add([]byte{16, 17, 18, 19})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %v: %v", data, r)
			}
		}()

		const secretMarker = "SECRET_SIMPLEQUERY_FUZZ_MARKER"
		r := &opReader{data: data}
		tr := &SimpleQueryTracker{}
		tr.Reset()

		checkNoMarker := func(s string) {
			if strings.Contains(s, secretMarker) {
				t.Fatalf("marker leaked: %s", s)
			}
		}

		const maxSteps = 300
		for step := 0; step < maxSteps; step++ {
			opb, ok := r.next()
			if !ok {
				break
			}
			var m Message
			switch int(opb) % 21 {
			case 0:
				m = rowDescMsg()
			case 1:
				m = backendMsg(MsgRowDescription, rowDescBodyWithColumnName(secretMarker))
			case 2:
				m = backendMsg(MsgRowDescription, []byte{0, 1})
			case 3:
				m = dataRowMsg()
			case 4:
				m = backendMsg(MsgDataRow, dataRowBodyWithCellValue(secretMarker))
			case 5:
				m = backendMsg(MsgDataRow, []byte{0, 1})
			case 6:
				m = commandCompleteMsg("SELECT 1")
			case 7:
				m = commandCompleteMsg(secretMarker)
			case 8:
				m = backendMsg(MsgCommandComplete, []byte("SELECT-NO-NUL"))
			case 9:
				m = emptyBackendMsg(MsgEmptyQueryResponse)
			case 10:
				m = minimalErrorResponse()
			case 11:
				m = fieldedErrorResponse(secretMarker)
			case 12:
				m = terminalOnlyErrorResponse()
			case 13:
				statuses := []byte{TxStatusIdle, TxStatusInTransaction, TxStatusFailedTransaction, 'X'}
				i, ok := r.pick(len(statuses))
				if !ok {
					continue
				}
				m = rfqMsg(statuses[i])
			case 14:
				m = fieldedNoticeMsg(secretMarker)
			case 15:
				m = paramStatusMsgWith(secretMarker, secretMarker)
			case 16:
				m = notificationMsgWith(secretMarker, secretMarker)
			case 17:
				copyTypes := []MessageType{MsgCopyInResponse, MsgCopyOutResponse, MsgCopyBothResponse}
				i, ok := r.pick(len(copyTypes))
				if !ok {
					continue
				}
				m = emptyBackendMsg(copyTypes[i])
			case 18:
				m = emptyBackendMsg(MsgPortalSuspended)
			case 19:
				types := []MessageType{MsgParseComplete, MsgBindComplete, MsgCloseComplete, MsgNoData, MsgAuthentication, MsgBackendKeyData}
				i, ok := r.pick(len(types))
				if !ok {
					continue
				}
				m = emptyBackendMsg(types[i])
			case 20:
				// Lifecycle-relevant CommandComplete tags specifically -
				// exercises classifySimpleQueryCommandTag's exact-match
				// table, including the deliberately-adjacent-but-distinct
				// pairs (COMMIT vs COMMIT PREPARED, DISCARD ALL vs DISCARD
				// PLANS) that must never be confused with each other.
				tags := []string{
					"COMMIT", "ROLLBACK", "PREPARE TRANSACTION",
					"COMMIT PREPARED", "ROLLBACK PREPARED",
					"DEALLOCATE", "DEALLOCATE ALL",
					"DISCARD ALL", "DISCARD PLANS", "DISCARD SEQUENCES", "DISCARD TEMP",
					"CLOSE CURSOR", "CLOSE CURSOR ALL", "DECLARE CURSOR",
					"BEGIN", "START TRANSACTION", "SAVEPOINT", "RELEASE",
					"PREPARE", "EXECUTE", "FETCH 1", "MOVE 1",
				}
				i, ok := r.pick(len(tags))
				if !ok {
					continue
				}
				m = commandCompleteMsg(tags[i])
			}

			wasIdle := tr.IsIdle()
			res, err := tr.Handle(m)
			if err != nil {
				checkNoMarker(err.Error())
				if wasIdle && !errors.Is(err, ErrSimpleResponseOrderingViolation) {
					t.Fatalf("expected ErrSimpleResponseOrderingViolation for Handle while idle, got %v", err)
				}
				if tr.IsIdle() != wasIdle {
					t.Fatalf("IsIdle() changed across a REJECTED Handle call: before=%v after=%v", wasIdle, tr.IsIdle())
				}
				continue
			}

			checkNoMarker(fmt.Sprintf("%+v", res))

			switch res.LifecycleEffect {
			case SimpleQueryLifecycleNone, SimpleQueryInvalidatePortals, SimpleQueryInvalidateStatementsAndPortals:
			default:
				t.Fatalf("Handle produced an undefined LifecycleEffect value: %v", res.LifecycleEffect)
			}
			if res.MessageType != MsgCommandComplete && res.LifecycleEffect != SimpleQueryLifecycleNone {
				t.Fatalf("non-CommandComplete result (%v) unexpectedly carries a non-zero LifecycleEffect %v", res.MessageType, res.LifecycleEffect)
			}

			if res.CycleCompleted {
				if res.MessageType != MsgReadyForQuery {
					t.Fatalf("CycleCompleted=true for non-ReadyForQuery message type %v", res.MessageType)
				}
				if res.ReadyForQueryStatus != TxStatusIdle && res.ReadyForQueryStatus != TxStatusInTransaction && res.ReadyForQueryStatus != TxStatusFailedTransaction {
					t.Fatalf("CycleCompleted with invalid ReadyForQueryStatus %q", res.ReadyForQueryStatus)
				}
				if !tr.IsIdle() {
					t.Fatal("expected the tracker to be idle immediately after CycleCompleted=true")
				}
				tr.Reset() // start a fresh, independent cycle - proves reusability without reallocation
			} else {
				if res.ReadyForQueryStatus != 0 {
					t.Fatalf("non-completing result unexpectedly carries a non-zero ReadyForQueryStatus %q", res.ReadyForQueryStatus)
				}
				if tr.IsIdle() {
					t.Fatal("tracker became idle after a non-completing accepted message")
				}
			}
		}
	})
}

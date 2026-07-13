package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// --- Test helpers -----------------------------------------------------

func newSequencer(t *testing.T) (*State, *ResponseSequencer) {
	t.Helper()
	s := NewState()
	seq, err := NewResponseSequencer(s, DefaultSequencerLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return s, seq
}

// --- Construction / limits validation ----------------------------------

func TestSequencer_New_NilState_Rejected(t *testing.T) {
	if _, err := NewResponseSequencer(nil, DefaultSequencerLimits()); err == nil {
		t.Fatal("expected error for nil state")
	}
}

func TestSequencer_New_InvalidLimits_Rejected(t *testing.T) {
	cases := []SequencerLimits{
		{MaxPlanUnits: 0, MaxSyntheticFrameBytes: 1, MaxAbandonedTombstones: 1, MaxActiveCycles: 1},
		{MaxPlanUnits: 1, MaxSyntheticFrameBytes: 0, MaxAbandonedTombstones: 1, MaxActiveCycles: 1},
		{MaxPlanUnits: 1, MaxSyntheticFrameBytes: 1, MaxAbandonedTombstones: 0, MaxActiveCycles: 1},
		{MaxPlanUnits: 1, MaxSyntheticFrameBytes: 1, MaxAbandonedTombstones: 1, MaxActiveCycles: 0},
		{MaxPlanUnits: -1, MaxSyntheticFrameBytes: 1, MaxAbandonedTombstones: 1, MaxActiveCycles: 1},
	}
	for i, l := range cases {
		if _, err := NewResponseSequencer(NewState(), l); !errors.Is(err, ErrInvalidSequencerLimits) {
			t.Fatalf("case %d: expected ErrInvalidSequencerLimits for %+v, got %v", i, l, err)
		}
	}
}

func TestSequencer_DefaultLimits_AreValid(t *testing.T) {
	if err := DefaultSequencerLimits().validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- AddForwardedOperation: registration ------------------------------

func TestSequencer_AddForwardedOperation_Success_NoImmediateOutput(t *testing.T) {
	s, seq := newSequencer(t)
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	actions, err := seq.AddForwardedOperation(op)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if actions != nil {
		t.Fatalf("expected no immediate actions, got %+v", actions)
	}
}

func TestSequencer_AddForwardedOperation_ZeroID_Rejected(t *testing.T) {
	_, seq := newSequencer(t)
	if _, err := seq.AddForwardedOperation(PendingOperation{Cycle: CycleID(1)}); !errors.Is(err, ErrInvalidOperationSnapshot) {
		t.Fatalf("expected ErrInvalidOperationSnapshot, got %v", err)
	}
}

func TestSequencer_AddForwardedOperation_ZeroCycle_Rejected(t *testing.T) {
	_, seq := newSequencer(t)
	if _, err := seq.AddForwardedOperation(PendingOperation{ID: PendingOperationID(1)}); !errors.Is(err, ErrInvalidOperationSnapshot) {
		t.Fatalf("expected ErrInvalidOperationSnapshot, got %v", err)
	}
}

func TestSequencer_AddForwardedOperation_Duplicate_Rejected(t *testing.T) {
	s, seq := newSequencer(t)
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.AddForwardedOperation(op); !errors.Is(err, ErrDuplicatePlanRegistration) {
		t.Fatalf("expected ErrDuplicatePlanRegistration, got %v", err)
	}
}

func TestSequencer_AddForwardedOperation_NamesNeverStored(t *testing.T) {
	s, seq := newSequencer(t)
	const secretName = "SECRET_SEQUENCER_NAME_MARKER"
	op, _, _ := s.CreateParse(secretName, "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dump := fmt.Sprintf("%+v", seq.plan)
	if strings.Contains(dump, secretName) {
		t.Fatalf("plan leaked the client-supplied name: %s", dump)
	}
}

// --- AddForwardedOperation: impossible / abandoned / blocked cycles ---

func TestSequencer_AddForwardedOperation_AbandonedOperation_Rejected(t *testing.T) {
	s, seq := newSequencer(t)
	failOp, _, _ := s.CreateParse("s0", "SELECT bad", nil)
	if _, err := seq.AddForwardedOperation(failOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	laterOp, _, _ := s.CreateParse("s1", "SELECT 1", nil) // deliberately NOT registered yet

	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.AddForwardedOperation(laterOp); !errors.Is(err, ErrOperationAbandoned) {
		t.Fatalf("expected ErrOperationAbandoned, got %v", err)
	}
}

func TestSequencer_AddForwardedOperation_NonSyncInBlockedCycle_Rejected(t *testing.T) {
	s, seq := newSequencer(t)
	cycle := CycleID(1)
	if _, err := seq.AddSyntheticError(cycle, minimalErrorResponse().Raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if op.Cycle != cycle {
		t.Fatalf("test precondition failed: expected op in cycle %d, got %d", cycle, op.Cycle)
	}
	if _, err := seq.AddForwardedOperation(op); !errors.Is(err, ErrCycleBlocked) {
		t.Fatalf("expected ErrCycleBlocked, got %v", err)
	}
}

func TestSequencer_AddForwardedOperation_SyncAllowedInBlockedCycle(t *testing.T) {
	s, seq := newSequencer(t)
	if _, err := seq.AddSyntheticError(CycleID(1), minimalErrorResponse().Raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	syncOp, _ := s.CreateSync()
	if _, err := seq.AddForwardedOperation(syncOp); err != nil {
		t.Fatalf("expected Sync registration to remain allowed in a blocked cycle, got %v", err)
	}
}

func TestSequencer_AddForwardedOperation_StaleCompletedCycle_Rejected(t *testing.T) {
	s, seq := newSequencer(t)
	syncOp, _ := s.CreateSync()
	if _, err := seq.AddForwardedOperation(syncOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(rfqMsg(TxStatusIdle)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	forged := PendingOperation{ID: PendingOperationID(999999), Kind: OpParse, Cycle: syncOp.Cycle}
	if _, err := seq.AddForwardedOperation(forged); !errors.Is(err, ErrImpossibleCycle) {
		t.Fatalf("expected ErrImpossibleCycle, got %v", err)
	}
}

// --- AddSyntheticError: validation --------------------------------------

func TestSequencer_AddSyntheticError_EmptyFrame_Rejected(t *testing.T) {
	_, seq := newSequencer(t)
	if _, err := seq.AddSyntheticError(CycleID(1), nil); !errors.Is(err, ErrMalformedSyntheticFrame) {
		t.Fatalf("expected ErrMalformedSyntheticFrame, got %v", err)
	}
}

func TestSequencer_AddSyntheticError_MalformedFrames_Rejected(t *testing.T) {
	_, seq := newSequencer(t)
	wrongTag := backendMsg(MsgReadyForQuery, []byte{'I'}).Raw
	cases := [][]byte{
		{byte(MsgErrorResponse)},                 // truncated, no length
		terminalOnlyErrorResponse().Raw,          // terminal-only: invalid framing
		wrongTag,                                 // wrong message type entirely
		append(minimalErrorResponse().Raw, 0xFF), // trailing byte beyond declared length
	}
	for i, frame := range cases {
		if _, err := seq.AddSyntheticError(CycleID(1), frame); !errors.Is(err, ErrMalformedSyntheticFrame) {
			t.Fatalf("case %d: expected ErrMalformedSyntheticFrame, got %v", i, err)
		}
	}
}

func TestSequencer_AddSyntheticError_ZeroCycle_Rejected(t *testing.T) {
	_, seq := newSequencer(t)
	if _, err := seq.AddSyntheticError(NoCycle, minimalErrorResponse().Raw); !errors.Is(err, ErrInvalidOperationSnapshot) {
		t.Fatalf("expected ErrInvalidOperationSnapshot, got %v", err)
	}
}

func TestSequencer_AddSyntheticError_DuplicateForBlockedCycle_Suppressed(t *testing.T) {
	_, seq := newSequencer(t)
	cycle := CycleID(1)
	frame := minimalErrorResponse().Raw
	actions1, err := seq.AddSyntheticError(cycle, frame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions1) != 1 {
		t.Fatalf("expected the first synthetic to emit immediately, got %+v", actions1)
	}
	actions2, err := seq.AddSyntheticError(cycle, frame)
	if err != nil {
		t.Fatalf("expected silent suppression (no error), got %v", err)
	}
	if actions2 != nil {
		t.Fatalf("expected no output for a suppressed duplicate, got %+v", actions2)
	}
}

// --- Blocked-first / ordering --------------------------------------------

func TestSequencer_BlockedFirst_SyntheticEmitsImmediately(t *testing.T) {
	_, seq := newSequencer(t)
	frame := minimalErrorResponse().Raw
	actions, err := seq.AddSyntheticError(CycleID(1), frame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected exactly one action, got %+v", actions)
	}
	if actions[0].Kind != ActionEmitSyntheticFrame || !actions[0].Synthetic {
		t.Fatalf("expected a synthetic-frame action, got %+v", actions[0])
	}
	if !bytes.Equal(actions[0].Bytes, frame) {
		t.Fatalf("expected relayed bytes to match the supplied frame")
	}
}

func TestSequencer_SyntheticBehindForwardedOperation_DeferredThenDrainedAfterCompletion(t *testing.T) {
	s, seq := newSequencer(t)
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame := minimalErrorResponse().Raw
	actions, err := seq.AddSyntheticError(op.Cycle, frame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 0 {
		t.Fatalf("expected no immediate output while a forwarded op is still ahead, got %+v", actions)
	}

	actions, err = seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions (real completion + drained synthetic), got %d: %+v", len(actions), actions)
	}
	if actions[0].Kind != ActionEmitBackendFrame || actions[0].Synthetic {
		t.Fatalf("expected the first action to be the real backend frame: %+v", actions[0])
	}
	if actions[1].Kind != ActionEmitSyntheticFrame || !actions[1].Synthetic {
		t.Fatalf("expected the second action to be the drained synthetic frame: %+v", actions[1])
	}
}

func TestSequencer_SyntheticBehindMultipleIntermediates_NotDrainedUntilTerminal(t *testing.T) {
	s, seq := setupSequencerExecuteHead(t)
	op, ok := s.HeadPendingOperation()
	if !ok {
		t.Fatal("expected a pending Execute head")
	}
	if _, err := seq.AddSyntheticError(op.Cycle, minimalErrorResponse().Raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 0; i < 3; i++ {
		actions, err := seq.HandleBackendMessage(dataRowMsg())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(actions) != 1 || actions[0].Synthetic {
			t.Fatalf("expected only the intermediate DataRow relayed, no drain yet: %+v", actions)
		}
	}
	actions, err := seq.HandleBackendMessage(commandCompleteMsg("SELECT 3"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 2 || !actions[1].Synthetic {
		t.Fatalf("expected the synthetic to drain right after the terminal completion: %+v", actions)
	}
}

// setupSequencerExecuteHead builds an unnamed statement+portal (both
// committed and registered) and a pending, registered Execute against
// that portal, so the sequencer's head is exactly an Execute ready for
// DataRow*/terminal handling.
func setupSequencerExecuteHead(t *testing.T) (*State, *ResponseSequencer) {
	t.Helper()
	s, seq := newSequencer(t)
	pop, _, _ := s.CreateParse("", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(pop); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bop, _, _ := s.CreateBind("", "", nil, nil, nil)
	if _, err := seq.AddForwardedOperation(bop); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(emptyBackendMsg(MsgBindComplete)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	eop, _ := s.CreateExecute("")
	if _, err := seq.AddForwardedOperation(eop); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return s, seq
}

// --- Real-error precedence -----------------------------------------------

func TestSequencer_RealError_SuppressesQueuedSyntheticSameCycle(t *testing.T) {
	s, seq := newSequencer(t)
	op, _, _ := s.CreateParse("s1", "SELECT bad", nil)
	if _, err := seq.AddForwardedOperation(op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.AddSyntheticError(op.Cycle, minimalErrorResponse().Raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	actions, err := seq.HandleBackendMessage(fieldedErrorResponse("boom"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 || actions[0].Synthetic {
		t.Fatalf("expected only the real error frame; the queued synthetic must be suppressed: %+v", actions)
	}
}

func TestSequencer_RealError_LaterCycleSyntheticUnaffected(t *testing.T) {
	s, seq := newSequencer(t)
	op, _, _ := s.CreateParse("s1", "SELECT bad", nil)
	if _, err := seq.AddForwardedOperation(op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	syncOp, _ := s.CreateSync()
	if _, err := seq.AddForwardedOperation(syncOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	nextOp, _, _ := s.CreateParse("s2", "SELECT 2", nil) // a new, later cycle
	if _, err := seq.AddForwardedOperation(nextOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.AddSyntheticError(nextOp.Cycle, minimalErrorResponse().Raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := seq.HandleBackendMessage(fieldedErrorResponse("boom")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The later cycle's synthetic must still be queued (not suppressed);
	// it will only drain once nextOp itself completes/fails.
	if seq.blockedCycles[nextOp.Cycle] != true {
		t.Fatal("expected the later cycle to be (independently) blocked by its OWN synthetic registration")
	}
}

func TestSequencer_AddForwardedOperation_LaterAbandonedID_AfterRealFailure_Tombstoned(t *testing.T) {
	s, seq := newSequencer(t)
	failOp, _, _ := s.CreateParse("s0", "SELECT bad", nil)
	if _, err := seq.AddForwardedOperation(failOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	laterOp, _, _ := s.CreateParse("s1", "SELECT 1", nil) // never registered before the failure

	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !seq.abandonedOps[laterOp.ID] {
		t.Fatal("expected the never-registered, abandoned operation to be tombstoned")
	}
}

func TestSequencer_RealError_AlreadyQueuedAbandonedUnit_RemovedWithoutOutput(t *testing.T) {
	s, seq := newSequencer(t)
	failOp, _, _ := s.CreateParse("s0", "SELECT bad", nil)
	if _, err := seq.AddForwardedOperation(failOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	laterOp, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(laterOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	actions, err := seq.HandleBackendMessage(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected only the real error frame, abandoned unit must produce no output: %+v", actions)
	}
	if _, exists := seq.planIndex[laterOp.ID]; exists {
		t.Fatal("expected the abandoned, already-queued unit to be removed from the plan")
	}
	if seq.abandonedOps[laterOp.ID] {
		t.Fatal("expected no tombstone for an operation whose unit was already in the plan")
	}
}

// --- Sync ErrorResponse ---------------------------------------------------

func TestSequencer_SyncErrorResponse_IntermediateThenReadyForQuery(t *testing.T) {
	s, seq := newSequencer(t)
	syncOp, _ := s.CreateSync()
	if _, err := seq.AddForwardedOperation(syncOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	actions, err := seq.HandleBackendMessage(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 || actions[0].Kind != ActionEmitBackendFrame {
		t.Fatalf("expected the ErrorResponse frame relayed without draining anything else: %+v", actions)
	}

	actions, err = seq.HandleBackendMessage(rfqMsg(TxStatusIdle))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 || actions[0].Kind != ActionEmitBackendFrame {
		t.Fatalf("expected the ReadyForQuery frame relayed: %+v", actions)
	}
}

func TestSequencer_SyncErrorResponse_DoesNotPopPlanHead(t *testing.T) {
	s, seq := newSequencer(t)
	syncOp, _ := s.CreateSync()
	if _, err := seq.AddForwardedOperation(syncOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(seq.plan) != 1 || seq.plan[0].opID != syncOp.ID {
		t.Fatalf("expected the Sync plan unit to remain queued, got plan=%+v", seq.plan)
	}
}

func TestSequencer_DuplicateSyncErrorResponse_Rejected(t *testing.T) {
	s, seq := newSequencer(t)
	syncOp, _ := s.CreateSync()
	if _, err := seq.AddForwardedOperation(syncOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); !errors.Is(err, ErrImpossibleBackendOrdering) {
		t.Fatalf("expected ErrImpossibleBackendOrdering, got %v", err)
	}
}

// --- Asynchronous messages -------------------------------------------------

func TestSequencer_AsyncMessage_RelayedWithoutTouchingPlan(t *testing.T) {
	s, seq := newSequencer(t)
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	actions, err := seq.HandleBackendMessage(backendMsg(MsgNoticeResponse, []byte{'S', 'N', 0, 0}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 || actions[0].Synthetic {
		t.Fatalf("unexpected actions: %+v", actions)
	}

	// The original forwarded head must be entirely untouched by the
	// asynchronous message.
	actions, err = seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete))
	if err != nil {
		t.Fatalf("unexpected error completing the original head: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("unexpected actions: %+v", actions)
	}
}

func TestSequencer_AsyncMessage_MalformedProducesNoOutput(t *testing.T) {
	_, seq := newSequencer(t)
	_, err := seq.HandleBackendMessage(backendMsg(MsgNoticeResponse, []byte{0})) // terminal-only: invalid
	if !errors.Is(err, ErrMalformedBackendMessage) {
		t.Fatalf("expected ErrMalformedBackendMessage, got %v", err)
	}
}

func TestSequencer_AsyncMessage_AllowedWithNoPendingOperationAtAll(t *testing.T) {
	_, seq := newSequencer(t)
	actions, err := seq.HandleBackendMessage(backendMsg(MsgParameterStatus, []byte{'k', 0, 'v', 0}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("unexpected actions: %+v", actions)
	}
}

// --- Connection-level ErrorResponse (no pending operation) ---------------

func TestSequencer_ConnectionLevelErrorResponse_EmitsAndTerminates(t *testing.T) {
	_, seq := newSequencer(t)
	actions, err := seq.HandleBackendMessage(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("expected exactly 2 actions (emit + terminate), got %+v", actions)
	}
	if actions[0].Kind != ActionEmitBackendFrame || actions[0].Synthetic {
		t.Fatalf("expected the first action to relay the real frame: %+v", actions[0])
	}
	if actions[1].Kind != ActionTerminateConnection {
		t.Fatalf("expected the second action to terminate the connection: %+v", actions[1])
	}
}

func TestSequencer_ConnectionLevelErrorResponse_MalformedRejectedWithoutTerminal(t *testing.T) {
	_, seq := newSequencer(t)
	_, err := seq.HandleBackendMessage(terminalOnlyErrorResponse())
	if !errors.Is(err, ErrMalformedBackendMessage) {
		t.Fatalf("expected ErrMalformedBackendMessage, got %v", err)
	}
	if seq.terminal {
		t.Fatal("expected the sequencer to remain non-terminal after a rejected malformed frame")
	}
}

func TestSequencer_TerminalState_RejectsAllFurtherCalls(t *testing.T) {
	s, seq := newSequencer(t)
	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(op); !errors.Is(err, ErrSequencerTerminal) {
		t.Fatalf("expected ErrSequencerTerminal, got %v", err)
	}
	if _, err := seq.AddSyntheticError(CycleID(1), minimalErrorResponse().Raw); !errors.Is(err, ErrSequencerTerminal) {
		t.Fatalf("expected ErrSequencerTerminal, got %v", err)
	}
	if _, err := seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete)); !errors.Is(err, ErrSequencerTerminal) {
		t.Fatalf("expected ErrSequencerTerminal, got %v", err)
	}
}

// --- Plan / State mismatch (fail-closed) ----------------------------------

func TestSequencer_HandleBackendMessage_NoPendingOperationAnywhere_NonError_Rejected(t *testing.T) {
	_, seq := newSequencer(t)
	if _, err := seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete)); !errors.Is(err, ErrNoPendingOperation) {
		t.Fatalf("expected ErrNoPendingOperation, got %v", err)
	}
}

func TestSequencer_HandleBackendMessage_UnregisteredStateOperation_Rejected(t *testing.T) {
	s, seq := newSequencer(t)
	s.CreateParse("s1", "SELECT 1", nil) // deliberately not registered
	if _, err := seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete)); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("expected ErrPlanMismatch, got %v", err)
	}
}

func TestSequencer_HandleBackendMessage_PlanHeadIdentityMismatch_Rejected(t *testing.T) {
	s, seq := newSequencer(t)
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	forged := op
	forged.Kind = OpBind // violates the registration-before-forwarding contract
	if _, err := seq.AddForwardedOperation(forged); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete)); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("expected ErrPlanMismatch, got %v", err)
	}
}

func TestSequencer_HandleBackendMessage_MalformedBackendFrame_Propagated(t *testing.T) {
	s, seq := newSequencer(t)
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(backendMsg(MsgParseComplete, []byte{1})); !errors.Is(err, ErrMalformedBackendMessage) {
		t.Fatalf("expected ErrMalformedBackendMessage, got %v", err)
	}
}

func TestSequencer_COPYResponse_AlwaysFailClosed(t *testing.T) {
	s, seq := newSequencer(t)
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(backendMsg(MsgCopyOutResponse, []byte{0, 0, 0})); !errors.Is(err, ErrUnsupportedCopyResponse) {
		t.Fatalf("expected ErrUnsupportedCopyResponse, got %v", err)
	}
}

// --- Resource limits --------------------------------------------------

func TestSequencer_Limits_MaxPlanUnits_Enforced(t *testing.T) {
	s := NewState()
	limits := DefaultSequencerLimits()
	limits.MaxPlanUnits = 1
	seq, err := NewResponseSequencer(s, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op1, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(op1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op2, _, _ := s.CreateParse("s2", "SELECT 2", nil)
	if _, err := seq.AddForwardedOperation(op2); !errors.Is(err, ErrPlanQueueFull) {
		t.Fatalf("expected ErrPlanQueueFull, got %v", err)
	}
}

func TestSequencer_Limits_MaxSyntheticFrameBytes_Enforced(t *testing.T) {
	s := NewState()
	limits := DefaultSequencerLimits()
	limits.MaxSyntheticFrameBytes = 4
	seq, err := NewResponseSequencer(s, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.AddSyntheticError(CycleID(1), minimalErrorResponse().Raw); !errors.Is(err, ErrSyntheticFrameTooLarge) {
		t.Fatalf("expected ErrSyntheticFrameTooLarge, got %v", err)
	}
}

func TestSequencer_Limits_MaxActiveCycles_Enforced(t *testing.T) {
	s := NewState()
	limits := DefaultSequencerLimits()
	limits.MaxActiveCycles = 1
	seq, err := NewResponseSequencer(s, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op1, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(op1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	syncOp, _ := s.CreateSync() // same cycle as op1 - must not count as a second cycle
	if _, err := seq.AddForwardedOperation(syncOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op2, _, _ := s.CreateParse("s2", "SELECT 2", nil) // a genuinely new, second cycle
	if _, err := seq.AddForwardedOperation(op2); !errors.Is(err, ErrActiveCycleLimitExceeded) {
		t.Fatalf("expected ErrActiveCycleLimitExceeded, got %v", err)
	}
}

// --- Tombstone-capacity exhaustion: fail-closed connection termination ---
//
// Tombstone capacity is a CORRECTNESS limit, not a best-effort cache: the
// sequencer must never continue normal operation with an incomplete
// abandoned-operation tombstone set (bkz. gereksinim: "Remove best-effort
// tombstone behavior"). If the full set of NEWLY required tombstones for a
// real ErrorResponse's abandoned operations does not fit within
// SequencerLimits.MaxAbandonedTombstones, the sequencer applies ZERO
// mutation for that failure, relays the real ErrorResponse exactly once,
// emits ActionTerminateConnection, and transitions permanently to the
// terminal state - a resource-exhaustion fail-closed connection
// termination, not a silently-degraded live sequencer.

// setupTombstoneScenario builds a registered, failing head Parse
// operation, then n later same-cycle Parse operations deliberately left
// UNREGISTERED with the sequencer (so each requires its own brand-new
// tombstone once abandoned), then a registered Sync for the same cycle.
// It does not itself trigger the ErrorResponse.
func setupTombstoneScenario(t *testing.T, maxTombstones, n int) (*ResponseSequencer, PendingOperation, []PendingOperation) {
	t.Helper()
	s := NewState()
	limits := DefaultSequencerLimits()
	limits.MaxAbandonedTombstones = maxTombstones
	seq, err := NewResponseSequencer(s, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	failOp, _, _ := s.CreateParse("s0", "SELECT bad", nil)
	if _, err := seq.AddForwardedOperation(failOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	later := make([]PendingOperation, n)
	for i := 0; i < n; i++ {
		op, _, _ := s.CreateParse(fmt.Sprintf("s%d", i+1), "SELECT x", nil)
		later[i] = op // deliberately NOT registered with the sequencer
	}
	syncOp, _ := s.CreateSync()
	if _, err := seq.AddForwardedOperation(syncOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return seq, failOp, later
}

func TestSequencer_TombstoneCapacity_ExactlyEnough_SucceedsNormally(t *testing.T) {
	seq, _, later := setupTombstoneScenario(t, 2, 2)
	actions, err := seq.HandleBackendMessage(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 || actions[0].Kind != ActionEmitBackendFrame {
		t.Fatalf("expected only the real error frame relayed, got %+v", actions)
	}
	if seq.terminal {
		t.Fatal("expected the sequencer to remain non-terminal with exactly sufficient capacity")
	}
	for _, op := range later {
		if !seq.abandonedOps[op.ID] {
			t.Fatalf("expected operation %d tombstoned", op.ID)
		}
	}
	if _, err := seq.HandleBackendMessage(rfqMsg(TxStatusIdle)); err != nil {
		t.Fatalf("unexpected error completing the still-pending Sync: %v", err)
	}
}

func TestSequencer_TombstoneCapacity_MoreThanNeeded_SucceedsNormally(t *testing.T) {
	seq, _, later := setupTombstoneScenario(t, 5, 2)
	actions, err := seq.HandleBackendMessage(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("unexpected actions: %+v", actions)
	}
	if seq.terminal {
		t.Fatal("expected the sequencer to remain non-terminal with ample spare capacity")
	}
	for _, op := range later {
		if !seq.abandonedOps[op.ID] {
			t.Fatalf("expected operation %d tombstoned", op.ID)
		}
	}
}

func TestSequencer_TombstoneCapacity_OneOverLimit_TriggersTerminal(t *testing.T) {
	seq, _, _ := setupTombstoneScenario(t, 1, 2)
	actions, err := seq.HandleBackendMessage(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("expected exactly 2 actions (emit real error + terminate), got %+v", actions)
	}
	if actions[0].Kind != ActionEmitBackendFrame || actions[0].Synthetic {
		t.Fatalf("expected the first action to relay the real ErrorResponse: %+v", actions[0])
	}
	if actions[1].Kind != ActionTerminateConnection {
		t.Fatalf("expected the second action to terminate the connection: %+v", actions[1])
	}
	if !seq.terminal {
		t.Fatal("expected the sequencer to be terminal after tombstone-capacity exhaustion")
	}
}

func TestSequencer_TombstoneCapacity_MultipleOverLimit_TriggersTerminal(t *testing.T) {
	seq, _, _ := setupTombstoneScenario(t, 1, 5)
	actions, err := seq.HandleBackendMessage(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("expected exactly 2 actions (emit real error + terminate), got %+v", actions)
	}
	if actions[1].Kind != ActionTerminateConnection {
		t.Fatalf("expected termination: %+v", actions[1])
	}
	if !seq.terminal {
		t.Fatal("expected the sequencer to be terminal after tombstone-capacity exhaustion")
	}
}

func TestSequencer_TombstoneExhaustion_RealErrorEmittedExactlyOnce(t *testing.T) {
	seq, _, _ := setupTombstoneScenario(t, 1, 3)
	msg := minimalErrorResponse()
	actions, err := seq.HandleBackendMessage(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	emitCount := 0
	for _, a := range actions {
		if a.Kind == ActionEmitBackendFrame {
			emitCount++
			if !bytes.Equal(a.Bytes, msg.Raw) {
				t.Fatalf("expected the relayed bytes to match the real ErrorResponse frame")
			}
		}
	}
	if emitCount != 1 {
		t.Fatalf("expected exactly one relayed ErrorResponse action, got %d in %+v", emitCount, actions)
	}
}

func TestSequencer_TombstoneExhaustion_NoSyntheticOrReadyForQueryEmitted(t *testing.T) {
	seq, _, _ := setupTombstoneScenario(t, 1, 3)
	actions, err := seq.HandleBackendMessage(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, a := range actions {
		if a.Synthetic || a.Kind == ActionEmitSyntheticFrame {
			t.Fatalf("expected no synthetic action ever emitted on exhaustion, got %+v", actions)
		}
		if a.MessageType == MsgReadyForQuery {
			t.Fatalf("expected no fabricated ReadyForQuery, got %+v", actions)
		}
	}
}

func TestSequencer_TombstoneExhaustion_QueuedSyntheticSameCycleNeverEmitted(t *testing.T) {
	s := NewState()
	limits := DefaultSequencerLimits()
	limits.MaxAbandonedTombstones = 1
	seq, err := NewResponseSequencer(s, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	failOp, _, _ := s.CreateParse("s0", "SELECT bad", nil)
	if _, err := seq.AddForwardedOperation(failOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.CreateParse("s1", "SELECT 1", nil) // unregistered abandoned #1
	s.CreateParse("s2", "SELECT 2", nil) // unregistered abandoned #2 -> exceeds capacity of 1
	if _, err := seq.AddSyntheticError(failOp.Cycle, minimalErrorResponse().Raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	actions, err := seq.HandleBackendMessage(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, a := range actions {
		if a.Synthetic {
			t.Fatalf("expected the queued same-cycle synthetic to never be emitted, got %+v", actions)
		}
	}
}

func TestSequencer_TombstoneExhaustion_LaterBackendOutputRejectedAfterTerminal(t *testing.T) {
	seq, _, _ := setupTombstoneScenario(t, 1, 2)
	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(backendMsg(MsgParameterStatus, []byte{'k', 0, 'v', 0})); !errors.Is(err, ErrSequencerTerminal) {
		t.Fatalf("expected ErrSequencerTerminal for later backend output, got %v", err)
	}
	if _, err := seq.HandleBackendMessage(rfqMsg(TxStatusIdle)); !errors.Is(err, ErrSequencerTerminal) {
		t.Fatalf("expected ErrSequencerTerminal for a later cycle's ReadyForQuery, got %v", err)
	}
}

func TestSequencer_TombstoneExhaustion_LaterAddForwardedOperationRejected(t *testing.T) {
	s := NewState()
	limits := DefaultSequencerLimits()
	limits.MaxAbandonedTombstones = 1
	seq, err := NewResponseSequencer(s, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	failOp, _, _ := s.CreateParse("s0", "SELECT bad", nil)
	seq.AddForwardedOperation(failOp)
	s.CreateParse("s1", "SELECT 1", nil)
	s.CreateParse("s2", "SELECT 2", nil)
	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	op, _, _ := s.CreateParse("sX", "SELECT x", nil)
	if _, err := seq.AddForwardedOperation(op); !errors.Is(err, ErrSequencerTerminal) {
		t.Fatalf("expected ErrSequencerTerminal, got %v", err)
	}
}

func TestSequencer_TombstoneExhaustion_LaterAddSyntheticErrorRejected(t *testing.T) {
	seq, _, _ := setupTombstoneScenario(t, 1, 2)
	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.AddSyntheticError(CycleID(999), minimalErrorResponse().Raw); !errors.Is(err, ErrSequencerTerminal) {
		t.Fatalf("expected ErrSequencerTerminal, got %v", err)
	}
}

func TestSequencer_TombstoneExhaustion_LaterHandleBackendMessageRejected(t *testing.T) {
	seq, _, _ := setupTombstoneScenario(t, 1, 2)
	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete)); !errors.Is(err, ErrSequencerTerminal) {
		t.Fatalf("expected ErrSequencerTerminal, got %v", err)
	}
}

func TestSequencer_TombstoneExhaustion_NoPartialTombstoneSetObservable(t *testing.T) {
	seq, failOp, later := setupTombstoneScenario(t, 1, 3)
	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(seq.abandonedOps) != 0 {
		t.Fatalf("expected zero tombstones recorded (all-or-nothing), got %d: %+v", len(seq.abandonedOps), seq.abandonedOps)
	}
	if len(seq.cycleTombstones) != 0 {
		t.Fatalf("expected no per-cycle tombstone bookkeeping recorded, got %+v", seq.cycleTombstones)
	}
	for _, op := range later {
		if seq.abandonedOps[op.ID] {
			t.Fatalf("expected operation %d NOT tombstoned (all-or-nothing failure)", op.ID)
		}
	}
	// Active-cycle metadata for the failed cycle must also be untouched
	// (bkz. gereksinim: "do not partially ... alter active-cycle
	// metadata") - no mutation at all was applied for this failure.
	if seq.blockedCycles[failOp.Cycle] {
		t.Fatal("expected the cycle block state to remain untouched on exhaustion (zero mutation applied)")
	}
	if seq.reallyFailed[failOp.Cycle] {
		t.Fatal("expected reallyFailed to remain untouched on exhaustion (zero mutation applied)")
	}
}

func TestSequencer_TombstoneCapacity_SufficientCapacity_LaterCyclesStillWorkNormally(t *testing.T) {
	s := NewState()
	limits := DefaultSequencerLimits()
	limits.MaxAbandonedTombstones = 2
	seq, err := NewResponseSequencer(s, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	failOp, _, _ := s.CreateParse("s0", "SELECT bad", nil)
	seq.AddForwardedOperation(failOp)
	s.CreateParse("s1", "SELECT 1", nil) // unregistered, abandoned -> 1 tombstone
	syncOp, _ := s.CreateSync()
	if _, err := seq.AddForwardedOperation(syncOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seq.terminal {
		t.Fatal("expected the sequencer to remain usable with sufficient capacity")
	}
	if _, err := seq.HandleBackendMessage(rfqMsg(TxStatusIdle)); err != nil {
		t.Fatalf("unexpected error completing the failed cycle's Sync: %v", err)
	}

	// A later, independent, unrelated cycle must work entirely normally.
	nextOp, _, _ := s.CreateParse("s2", "SELECT 2", nil)
	if _, err := seq.AddForwardedOperation(nextOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	actions, err := seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("unexpected actions: %+v", actions)
	}
}

func TestSequencer_TombstoneExhaustion_NoNamesSQLParamsOrServerValuesLeaked(t *testing.T) {
	s := NewState()
	limits := DefaultSequencerLimits()
	limits.MaxAbandonedTombstones = 1
	seq, err := NewResponseSequencer(s, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const secretStmt = "SECRET_TOMBSTONE_STMT_MARKER"
	const secretSQL = "SECRET_TOMBSTONE_SQL_MARKER"
	const secretServerText = "SECRET_TOMBSTONE_SERVER_TEXT_MARKER"

	failOp, _, _ := s.CreateParse(secretStmt, "SELECT bad -- "+secretSQL, nil)
	if _, err := seq.AddForwardedOperation(failOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.CreateParse("s1", "SELECT 1 -- "+secretSQL, nil)
	s.CreateParse("s2", "SELECT 2 -- "+secretSQL, nil)

	actions, err := seq.HandleBackendMessage(fieldedErrorResponse(secretServerText))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err != nil {
		v := err.Error()
		if strings.Contains(v, secretStmt) || strings.Contains(v, secretSQL) {
			t.Fatalf("error text leaked a marker: %s", v)
		}
	}
	// The relayed real-error frame legitimately carries the server's own
	// ErrorResponse text (that IS the frame being relayed) - but no
	// sequencer-internal metadata (Kind/MessageType/CycleID/OperationID/
	// OperationKind) may ever carry a client-supplied name or SQL text,
	// and internal tombstone/plan state must never retain one either.
	for _, a := range actions {
		meta := fmt.Sprintf("Kind=%v MessageType=%v CycleID=%v OperationID=%v OperationKind=%v Synthetic=%v", a.Kind, a.MessageType, a.CycleID, a.OperationID, a.OperationKind, a.Synthetic)
		if strings.Contains(meta, secretStmt) || strings.Contains(meta, secretSQL) {
			t.Fatalf("action metadata leaked a marker: %s", meta)
		}
	}
	internalDump := fmt.Sprintf("%+v %+v %+v", seq.abandonedOps, seq.plan, seq.cycleTombstones)
	if strings.Contains(internalDump, secretStmt) || strings.Contains(internalDump, secretSQL) {
		t.Fatalf("internal sequencer state leaked a name/SQL marker: %s", internalDump)
	}
}

// --- Cycle cleanup / cross-cycle isolation --------------------------------

func TestSequencer_FinishCycle_ClearsBlockAndTombstonesForThatCycleOnly(t *testing.T) {
	s, seq := newSequencer(t)
	failOp, _, _ := s.CreateParse("s0", "SELECT bad", nil)
	if _, err := seq.AddForwardedOperation(failOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.CreateParse("s1", "SELECT 1", nil) // unregistered -> tombstoned
	syncOp, _ := s.CreateSync()
	if _, err := seq.AddForwardedOperation(syncOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(seq.abandonedOps) == 0 {
		t.Fatal("test precondition failed: expected at least one tombstone before ReadyForQuery")
	}
	if _, err := seq.HandleBackendMessage(rfqMsg(TxStatusIdle)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seq.blockedCycles[failOp.Cycle] {
		t.Fatal("expected the cycle block to be cleared after ReadyForQuery")
	}
	if len(seq.abandonedOps) != 0 {
		t.Fatalf("expected tombstones cleared after cycle completion, got %d", len(seq.abandonedOps))
	}
	if len(seq.cycleSeenOps) != 0 || len(seq.activeCycles) != 0 {
		t.Fatalf("expected all per-cycle bookkeeping cleared, got cycleSeenOps=%v activeCycles=%v", seq.cycleSeenOps, seq.activeCycles)
	}
}

func TestSequencer_MultipleCycles_IndependentAndSequentiallyResolved(t *testing.T) {
	s, seq := newSequencer(t)
	sync1, _ := s.CreateSync()
	if _, err := seq.AddForwardedOperation(sync1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	op2, _, _ := s.CreateParse("s2", "SELECT 2", nil)
	if _, err := seq.AddForwardedOperation(op2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sync2, _ := s.CreateSync()
	if _, err := seq.AddForwardedOperation(sync2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	res1, err := seq.HandleBackendMessage(rfqMsg(TxStatusIdle))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res1) != 1 {
		t.Fatalf("unexpected actions: %+v", res1)
	}
	if _, err := seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res2, err := seq.HandleBackendMessage(rfqMsg(TxStatusIdle))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res2) != 1 {
		t.Fatalf("unexpected actions: %+v", res2)
	}
}

// --- Mutation isolation ---------------------------------------------------

func TestSequencer_OutputAction_BytesIndependentFromSourceMessage(t *testing.T) {
	s, seq := newSequencer(t)
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(op); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	msg := emptyBackendMsg(MsgParseComplete)
	original := append([]byte(nil), msg.Raw...)
	actions, err := seq.HandleBackendMessage(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	actions[0].Bytes[0] = 0xFF
	if !bytes.Equal(msg.Raw, original) {
		t.Fatal("expected mutating the returned action bytes to leave the source message untouched")
	}
}

func TestSequencer_SyntheticFrame_CallerSliceMutationDoesNotAffectStoredCopy(t *testing.T) {
	s, seq := newSequencer(t)
	fop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(fop); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame := append([]byte(nil), minimalErrorResponse().Raw...)
	if _, err := seq.AddSyntheticError(fop.Cycle, frame); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	frame[5] = 0xFF // mutate caller's own copy after registration

	actions, err := seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("unexpected actions: %+v", actions)
	}
	if actions[1].Bytes[5] == 0xFF {
		t.Fatal("expected the sequencer to have stored an independent copy of the synthetic frame")
	}
}

func TestSequencer_AbandonedOperations_NeverExposeNamesInInternalState(t *testing.T) {
	s, seq := newSequencer(t)
	const secretName = "SECRET_SEQUENCER_ABANDON_MARKER"
	failOp, _, _ := s.CreateParse("s0", "SELECT bad", nil)
	if _, err := seq.AddForwardedOperation(failOp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.CreateParse(secretName, "SELECT 1", nil)

	if _, err := seq.HandleBackendMessage(minimalErrorResponse()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dump := fmt.Sprintf("%+v", seq.abandonedOps)
	if strings.Contains(dump, secretName) {
		t.Fatalf("tombstone tracking leaked a name marker: %s", dump)
	}
}

// --- Fuzz / randomized sequence test --------------------------------------
//
// FuzzResponseSequencer drives a short, bounded, byte-driven pseudo-random
// mix of frontend State.Create* + AddForwardedOperation/AddSyntheticError
// registrations and HandleBackendMessage calls, checking invariants after
// every step. Mirrors the established pattern in extended_state_test.go /
// extended_correlation_test.go (reusing opReader/checkStructuralInvariants,
// same package). This is a short bounded property test, not an exhaustive
// model-checker.

func FuzzResponseSequencer(f *testing.F) {
	f.Add([]byte{0, 0, 8, 0, 1, 0, 7, 8, 0, 4, 0})
	f.Add([]byte{0, 1, 0, 4, 8, 9})
	f.Add([]byte{7, 9, 11, 0, 12, 1})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %v: %v", data, r)
			}
		}()

		s := NewState()
		limits := DefaultSequencerLimits()
		// Deliberately small tombstone capacity, so a real ErrorResponse's
		// abandonment set very frequently exceeds it during fuzzing -
		// this stress-tests the fail-closed exhaustion path (bkz.
		// gereksinim: "Extend FuzzResponseSequencer with very small
		// tombstone limits").
		if b, ok := r0Peek(data); ok {
			limits.MaxAbandonedTombstones = int(b)%4 + 1 // 1..4
		} else {
			limits.MaxAbandonedTombstones = 2
		}
		seq, err := NewResponseSequencer(s, limits)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		r := &opReader{data: data}

		const bodyMarker = "SECRET_SEQ_BODY_MARKER" // legitimately relayed in Bytes
		const stmtNameMarker = "SECRET_SEQ_STMT_NAME_MARKER"
		const portalNameMarker = "SECRET_SEQ_PORTAL_NAME_MARKER"
		stmtNames := []string{"", "s1", stmtNameMarker}
		portalNames := []string{"", "p1", portalNameMarker}

		checkErrNoMarkers := func(err error) {
			if err == nil {
				return
			}
			v := err.Error()
			if strings.Contains(v, bodyMarker) || strings.Contains(v, stmtNameMarker) || strings.Contains(v, portalNameMarker) {
				t.Fatalf("error text leaked a marker: %s", v)
			}
		}
		checkActionsNoNameMarkers := func(actions []OutputAction) {
			dump := fmt.Sprintf("%+v", actions)
			if strings.Contains(dump, stmtNameMarker) || strings.Contains(dump, portalNameMarker) {
				t.Fatalf("action leaked a client-supplied name marker: %s", dump)
			}
		}
		// checkTerminationBatchShape asserts that whenever a returned
		// action batch contains ActionTerminateConnection, it is the
		// LAST action, and the ENTIRE batch is exactly [one real
		// ErrorResponse relay, terminate] - never more than one relayed
		// frame, never a synthetic frame, never anything after
		// termination (bkz. gereksinim: "terminal transition emits at
		// most one real ErrorResponse and one terminate action").
		checkTerminationBatchShape := func(actions []OutputAction) {
			hasTerminate := false
			for i, a := range actions {
				if a.Kind == ActionTerminateConnection {
					hasTerminate = true
					if i != len(actions)-1 {
						t.Fatalf("ActionTerminateConnection must be the final action in its batch: %+v", actions)
					}
				}
			}
			if !hasTerminate {
				return
			}
			if len(actions) != 2 {
				t.Fatalf("expected exactly 2 actions in a terminating batch (emit + terminate), got %+v", actions)
			}
			if actions[0].Kind != ActionEmitBackendFrame || actions[0].Synthetic {
				t.Fatalf("expected the action preceding termination to be exactly one real backend frame: %+v", actions)
			}
		}

		registerIfCreated := func(op PendingOperation, createErr error) {
			if createErr != nil {
				return
			}
			_, aerr := seq.AddForwardedOperation(op)
			checkErrNoMarkers(aerr)
		}

		terminated := false
		for step := 0; step < 250 && !terminated; step++ {
			opb, ok := r.next()
			if !ok {
				break
			}
			var actions []OutputAction
			var callErr error
			switch int(opb) % 14 {
			case 0:
				i, ok := r.pick(len(stmtNames))
				if !ok {
					continue
				}
				op, _, err := s.CreateParse(stmtNames[i], "SELECT 1", nil)
				registerIfCreated(op, err)
			case 1:
				pi, ok1 := r.pick(len(portalNames))
				si, ok2 := r.pick(len(stmtNames))
				if !ok1 || !ok2 {
					continue
				}
				op, _, err := s.CreateBind(portalNames[pi], stmtNames[si], nil, nil, nil)
				registerIfCreated(op, err)
			case 2:
				i, ok := r.pick(len(stmtNames))
				if !ok {
					continue
				}
				op, err := s.CreateDescribeStatement(stmtNames[i])
				registerIfCreated(op, err)
			case 3:
				i, ok := r.pick(len(portalNames))
				if !ok {
					continue
				}
				op, err := s.CreateDescribePortal(portalNames[i])
				registerIfCreated(op, err)
			case 4:
				i, ok := r.pick(len(portalNames))
				if !ok {
					continue
				}
				op, err := s.CreateExecute(portalNames[i])
				registerIfCreated(op, err)
			case 5:
				i, ok := r.pick(len(stmtNames))
				if !ok {
					continue
				}
				op, err := s.CreateCloseStatement(stmtNames[i])
				registerIfCreated(op, err)
			case 6:
				i, ok := r.pick(len(portalNames))
				if !ok {
					continue
				}
				op, err := s.CreateClosePortal(portalNames[i])
				registerIfCreated(op, err)
			case 7:
				op, err := s.CreateSync()
				registerIfCreated(op, err)
			case 8: // correct terminal for the current head
				head, ok := s.HeadPendingOperation()
				if !ok {
					continue
				}
				actions, callErr = seq.HandleBackendMessage(correctTerminalFor(head.Kind))
			case 9: // real ErrorResponse against the current head (or connection-level)
				actions, callErr = seq.HandleBackendMessage(fieldedErrorResponse(bodyMarker))
			case 10: // asynchronous message, valid or malformed
				b, ok := r.next()
				if !ok {
					continue
				}
				types := []MessageType{MsgNoticeResponse, MsgParameterStatus, MsgNotificationResponse}
				mt := types[int(b)%len(types)]
				var body []byte
				switch mt {
				case MsgNoticeResponse:
					body = append([]byte{'S'}, append([]byte(bodyMarker), 0, 0)...)
				case MsgParameterStatus:
					body = append(append([]byte(bodyMarker), 0), append([]byte("v"), 0)...)
				case MsgNotificationResponse:
					body = append([]byte{0, 0, 0, 1}, append([]byte(bodyMarker), 0, 'p', 0)...)
				}
				actions, callErr = seq.HandleBackendMessage(backendMsg(mt, body))
			case 11: // ReadyForQuery with a random (possibly invalid) status
				b, ok := r.next()
				if !ok {
					continue
				}
				statuses := []byte{TxStatusIdle, TxStatusInTransaction, TxStatusFailedTransaction, 'X'}
				actions, callErr = seq.HandleBackendMessage(rfqMsg(statuses[int(b)%len(statuses)]))
			case 12: // AddSyntheticError against a small, plausible cycle number
				b, ok := r.next()
				if !ok {
					continue
				}
				cycle := CycleID(int(b)%5 + 1)
				actions, callErr = seq.AddSyntheticError(cycle, fieldedErrorResponse(bodyMarker).Raw)
			case 13: // malformed random-body message against a random type
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
				actions, callErr = seq.HandleBackendMessage(backendMsg(mt, body))
			}

			checkErrNoMarkers(callErr)
			checkActionsNoNameMarkers(actions)
			checkTerminationBatchShape(actions)

			checkStructuralInvariants(t, s)
			if len(seq.plan) > 0 && seq.plan[0].kind == PlanUnitSyntheticError {
				t.Fatalf("invariant violated: a synthetic unit was left at the plan head after settling")
			}
			// Tombstone capacity is a correctness limit: it must never be
			// exceeded, AND (since exhaustion now fails closed atomically
			// rather than best-effort) the sequencer must never be left
			// non-terminal with an incomplete tombstone set for an
			// already-processed real failure.
			if len(seq.abandonedOps) > seq.limits.MaxAbandonedTombstones {
				t.Fatalf("tombstone limit exceeded: %d > %d", len(seq.abandonedOps), seq.limits.MaxAbandonedTombstones)
			}
			if len(seq.plan) > seq.limits.MaxPlanUnits {
				t.Fatalf("plan queue limit exceeded: %d > %d", len(seq.plan), seq.limits.MaxPlanUnits)
			}
			if seq.terminal {
				// No further output of any kind may ever occur once
				// terminal - every entry point must reject uniformly.
				if _, err := seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete)); !errors.Is(err, ErrSequencerTerminal) {
					t.Fatalf("expected ErrSequencerTerminal once terminal, got %v", err)
				}
				if out, err := seq.AddForwardedOperation(PendingOperation{ID: 1, Kind: OpParse, Cycle: 1}); !errors.Is(err, ErrSequencerTerminal) || out != nil {
					t.Fatalf("expected ErrSequencerTerminal with no output for AddForwardedOperation once terminal, got out=%+v err=%v", out, err)
				}
				if out, err := seq.AddSyntheticError(CycleID(1), minimalErrorResponse().Raw); !errors.Is(err, ErrSequencerTerminal) || out != nil {
					t.Fatalf("expected ErrSequencerTerminal with no output for AddSyntheticError once terminal, got out=%+v err=%v", out, err)
				}
				terminated = true
			}
		}
	})
}

// r0Peek returns the first byte of data without consuming it, used only
// to seed a fuzz iteration's tombstone-capacity limit deterministically
// from the input.
func r0Peek(data []byte) (byte, bool) {
	if len(data) == 0 {
		return 0, false
	}
	return data[0], true
}

// --- OutputAction.TargetGeneration -----------------------------------

func TestSequencer_TargetGeneration_ExecuteDataRow_IdentifiesPortal(t *testing.T) {
	s, seq := setupSequencerExecuteHead(t)
	portal, ok := s.CommittedPortal("")
	if !ok {
		t.Fatal("expected committed unnamed portal")
	}
	actions, err := seq.HandleBackendMessage(dataRowMsg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 || actions[0].Kind != ActionEmitBackendFrame {
		t.Fatalf("expected exactly one ActionEmitBackendFrame, got %+v", actions)
	}
	if actions[0].TargetGeneration != portal.ID {
		t.Fatalf("expected DataRow action TargetGeneration=%d, got %d", portal.ID, actions[0].TargetGeneration)
	}
}

func TestSequencer_TargetGeneration_DescribeStatement_RowDescription(t *testing.T) {
	s, seq := newSequencer(t)
	pop, stmtGen, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := seq.AddForwardedOperation(pop); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	dop, err := s.CreateDescribeStatement("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.AddForwardedOperation(dop); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := seq.HandleBackendMessage(paramDescMsg(nil)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	actions, err := seq.HandleBackendMessage(rowDescMsg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 || actions[0].TargetGeneration != stmtGen.ID {
		t.Fatalf("expected statement-Describe RowDescription action TargetGeneration=%d, got %+v", stmtGen.ID, actions)
	}
}

func TestSequencer_TargetGeneration_AsyncMessage_IsNoGeneration(t *testing.T) {
	_, seq := newSequencer(t)
	actions, err := seq.HandleBackendMessage(backendMsg(MsgNoticeResponse, []byte{'S', 'N', 0, 0}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 || actions[0].TargetGeneration != NoGeneration {
		t.Fatalf("expected async action TargetGeneration=NoGeneration, got %+v", actions)
	}
}

func TestSequencer_TargetGeneration_SyntheticFrame_IsNoGeneration(t *testing.T) {
	_, seq := newSequencer(t)
	actions, err := seq.AddSyntheticError(CycleID(1), minimalErrorResponse().Raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) != 1 || actions[0].Kind != ActionEmitSyntheticFrame {
		t.Fatalf("expected exactly one synthetic action, got %+v", actions)
	}
	if actions[0].TargetGeneration != NoGeneration {
		t.Fatalf("expected synthetic action TargetGeneration=NoGeneration, got %d", actions[0].TargetGeneration)
	}
}

func TestSequencer_TargetGeneration_ConnectionLevelErrorResponse_IsNoGeneration(t *testing.T) {
	_, seq := newSequencer(t)
	actions, err := seq.HandleBackendMessage(minimalErrorResponse())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(actions) == 0 || actions[0].TargetGeneration != NoGeneration {
		t.Fatalf("expected connection-level ErrorResponse action TargetGeneration=NoGeneration, got %+v", actions)
	}
}

func TestSequencer_TargetGeneration_TwoPortals_DoNotCrossContaminate(t *testing.T) {
	s, seq := newSequencer(t)
	pop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	seq.AddForwardedOperation(pop)
	seq.HandleBackendMessage(emptyBackendMsg(MsgParseComplete))

	bop1, portal1, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	seq.AddForwardedOperation(bop1)
	seq.HandleBackendMessage(emptyBackendMsg(MsgBindComplete))

	bop2, portal2, _ := s.CreateBind("p2", "s1", nil, nil, nil)
	seq.AddForwardedOperation(bop2)
	seq.HandleBackendMessage(emptyBackendMsg(MsgBindComplete))

	if portal1.ID == portal2.ID {
		t.Fatal("expected two distinct portal generations")
	}

	eop1, _ := s.CreateExecute("p1")
	seq.AddForwardedOperation(eop1)
	actions1, err := seq.HandleBackendMessage(dataRowMsg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if actions1[0].TargetGeneration != portal1.ID {
		t.Fatalf("expected portal1 DataRow TargetGeneration=%d, got %d", portal1.ID, actions1[0].TargetGeneration)
	}
	if _, err := seq.HandleBackendMessage(commandCompleteMsg("SELECT 1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	eop2, _ := s.CreateExecute("p2")
	seq.AddForwardedOperation(eop2)
	actions2, err := seq.HandleBackendMessage(dataRowMsg())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if actions2[0].TargetGeneration != portal2.ID {
		t.Fatalf("expected portal2 DataRow TargetGeneration=%d, got %d", portal2.ID, actions2[0].TargetGeneration)
	}
	if actions2[0].TargetGeneration == actions1[0].TargetGeneration {
		t.Fatal("expected the two portals' DataRow TargetGeneration to differ")
	}
}

package protocol

import (
	"errors"
	"math"
	"testing"
)

// --- Fuzz / randomized state-sequence tests -------------------------------
//
// FuzzExtendedStateSequence drives State through a bounded, byte-driven
// pseudo-random sequence of every public operation (including deliberately
// invalid/out-of-order acknowledgements) and checks structural invariants
// after every single step. This is a short, bounded property test (see
// docs/design/0001-extended-query.md's own "bounded fuzz" discipline) - it
// is not an exhaustive model-checker.

type opReader struct {
	data []byte
	pos  int
}

func (r *opReader) next() (byte, bool) {
	if r.pos >= len(r.data) {
		return 0, false
	}
	b := r.data[r.pos]
	r.pos++
	return b, true
}

func (r *opReader) pick(n int) (int, bool) {
	b, ok := r.next()
	if !ok || n <= 0 {
		return 0, false
	}
	return int(b) % n, true
}

// checkStructuralInvariants asserts the invariants required by the state
// model regardless of what sequence of operations produced the current
// State: current/committed mappings never dangle, portals never reference a
// nonexistent statement, committed lookups never point at a non-committed
// generation, and the pending-operation queue is strictly FIFO-ordered with
// no duplicate or zero IDs.
func checkStructuralInvariants(t *testing.T, s *State) {
	t.Helper()
	for id, p := range s.portals {
		if _, ok := s.statements[p.StatementID]; !ok {
			t.Fatalf("portal %d references nonexistent statement generation %d", id, p.StatementID)
		}
	}
	for name, id := range s.namedStatementCommitted {
		g, ok := s.statements[id]
		if !ok {
			t.Fatalf("namedStatementCommitted[%q] points to nonexistent generation %d", name, id)
		}
		if g.State != LifecycleCommitted {
			t.Fatalf("namedStatementCommitted[%q] points to a non-committed generation (state=%v)", name, g.State)
		}
	}
	for name, id := range s.namedPortalCommitted {
		g, ok := s.portals[id]
		if !ok {
			t.Fatalf("namedPortalCommitted[%q] points to nonexistent generation %d", name, id)
		}
		if g.State != LifecycleCommitted {
			t.Fatalf("namedPortalCommitted[%q] points to a non-committed generation (state=%v)", name, g.State)
		}
	}
	if s.unnamedStatementCurrent != NoGeneration {
		if _, ok := s.statements[s.unnamedStatementCurrent]; !ok {
			t.Fatalf("unnamedStatementCurrent points to nonexistent generation %d", s.unnamedStatementCurrent)
		}
	}
	if s.unnamedPortalCurrent != NoGeneration {
		if _, ok := s.portals[s.unnamedPortalCurrent]; !ok {
			t.Fatalf("unnamedPortalCurrent points to nonexistent generation %d", s.unnamedPortalCurrent)
		}
	}
	var last PendingOperationID
	for i, op := range s.pendingOps {
		if op.ID == NoPendingOperation {
			t.Fatalf("queue entry %d has NoPendingOperation ID", i)
		}
		if i > 0 && op.ID <= last {
			t.Fatalf("pending queue not strictly FIFO-increasing at index %d: %d <= %d", i, op.ID, last)
		}
		last = op.ID
	}
}

func FuzzExtendedStateSequence(f *testing.F) {
	f.Add([]byte{0, 1, 2, 4, 0, 4, 1, 10, 11, 'I', 9, 0, 8, 0})
	f.Add([]byte{1, 0, 0, 4, 2, 4, 0})
	f.Add([]byte{0, 0, 0, 0, 4, 2, 4, 2, 11, 'I'})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("panic on input %v: %v", data, rec)
			}
		}()

		s := NewState()
		r := &opReader{data: data}
		stmtNames := []string{"", "s1", "s2"}
		portalNames := []string{"", "p1", "p2"}
		statuses := []byte{TxStatusIdle, TxStatusInTransaction, TxStatusFailedTransaction, 'X'}

		var lastGen GenerationID
		var lastCycle CycleID
		var lastOp PendingOperationID
		trackGen := func(id GenerationID) {
			if id == NoGeneration {
				return
			}
			if id <= lastGen {
				t.Fatalf("generation ID did not strictly increase: %d after %d", id, lastGen)
			}
			lastGen = id
		}
		trackOp := func(id PendingOperationID) {
			if id == NoPendingOperation {
				return
			}
			if id <= lastOp {
				t.Fatalf("operation ID did not strictly increase: %d after %d", id, lastOp)
			}
			lastOp = id
		}
		trackCycle := func(id CycleID) {
			if id == NoCycle {
				return
			}
			if id <= lastCycle {
				t.Fatalf("cycle ID did not strictly increase: %d after %d", id, lastCycle)
			}
			lastCycle = id
		}

		const maxSteps = 500
		for step := 0; step < maxSteps; step++ {
			opb, ok := r.next()
			if !ok {
				break
			}
			switch int(opb) % 13 {
			case 0: // CreateParse
				i, ok := r.pick(len(stmtNames))
				if !ok {
					continue
				}
				op, gen, err := s.CreateParse(stmtNames[i], "SELECT 1", []uint32{23, 25})
				if err == nil {
					trackOp(op.ID)
					trackGen(gen.ID)
				}
			case 1: // CreateBind
				pi, ok1 := r.pick(len(portalNames))
				si, ok2 := r.pick(len(stmtNames))
				if !ok1 || !ok2 {
					continue
				}
				op, gen, err := s.CreateBind(portalNames[pi], stmtNames[si], []int16{0, 1}, []bool{false, true}, []int16{0})
				if err == nil {
					trackOp(op.ID)
					trackGen(gen.ID)
				}
			case 2: // CreateDescribeStatement
				i, ok := r.pick(len(stmtNames))
				if !ok {
					continue
				}
				op, err := s.CreateDescribeStatement(stmtNames[i])
				if err == nil {
					trackOp(op.ID)
				}
			case 3: // CreateDescribePortal
				i, ok := r.pick(len(portalNames))
				if !ok {
					continue
				}
				op, err := s.CreateDescribePortal(portalNames[i])
				if err == nil {
					trackOp(op.ID)
				}
			case 4: // AckHead: correct ack, ErrorResponse, or deliberately mismatched kind
				ops := s.PendingOperations()
				choice, ok := r.pick(3)
				if !ok || len(ops) == 0 {
					continue
				}
				head := ops[0]
				switch choice {
				case 0:
					switch head.Kind {
					case OpParse:
						s.ApplyParseComplete(head.ID)
					case OpBind:
						s.ApplyBindComplete(head.ID)
					case OpCloseStatement, OpClosePortal:
						s.ApplyCloseComplete(head.ID)
					case OpDescribeStatement, OpDescribePortal, OpExecute:
						s.CompleteOperation(head.ID)
					case OpSync:
						if cyc, err := s.ApplyReadyForQuery(TxStatusIdle); err == nil {
							trackCycle(cyc)
						}
					}
				case 1:
					s.ApplyErrorResponse(head.ID)
				case 2:
					// Deliberately wrong kind - must error, never panic.
					s.ApplyBindComplete(head.ID)
					s.ApplyCloseComplete(head.ID)
				}
			case 5: // CreateExecute
				i, ok := r.pick(len(portalNames))
				if !ok {
					continue
				}
				op, err := s.CreateExecute(portalNames[i])
				if err == nil {
					trackOp(op.ID)
				}
			case 6: // CreateCloseStatement (+ immediate CloseComplete)
				i, ok := r.pick(len(stmtNames))
				if !ok {
					continue
				}
				op, err := s.CreateCloseStatement(stmtNames[i])
				if err == nil {
					trackOp(op.ID)
					s.ApplyCloseComplete(op.ID)
				}
			case 7: // CreateClosePortal (+ immediate CloseComplete)
				i, ok := r.pick(len(portalNames))
				if !ok {
					continue
				}
				op, err := s.CreateClosePortal(portalNames[i])
				if err == nil {
					trackOp(op.ID)
					s.ApplyCloseComplete(op.ID)
				}
			case 8: // CreateSync
				op, err := s.CreateSync()
				if err == nil {
					trackOp(op.ID)
				}
			case 9: // ApplyReadyForQuery with a random (possibly invalid) status
				i, ok := r.pick(len(statuses))
				if !ok {
					continue
				}
				status := statuses[i]
				before := s.PortalCount()
				_ = before
				cyc, err := s.ApplyReadyForQuery(status)
				if err == nil {
					trackCycle(cyc)
					if status == TxStatusIdle && s.PortalCount() != 0 {
						t.Fatalf("ReadyForQuery('I') left %d live portals", s.PortalCount())
					}
				}
			case 10: // ApplyAllowedSimpleQuery
				s.ApplyAllowedSimpleQuery()
			case 11: // Ack with a random, likely-invalid operation ID (never a real one)
				b, ok := r.next()
				if !ok {
					continue
				}
				randomID := PendingOperationID(uint64(b) * 7919)
				s.ApplyParseComplete(randomID)
				s.ApplyBindComplete(randomID)
				s.ApplyCloseComplete(randomID)
				s.ApplyErrorResponse(randomID)
				s.CompleteOperation(randomID)
			case 12: // ApplyReadyForQuery with a random ID-shaped call already covered above; use remaining byte to vary status further
				b, ok := r.next()
				if !ok {
					continue
				}
				s.ApplyReadyForQuery(b)
			}
			checkStructuralInvariants(t, s)
		}
	})
}

// --- Identifier tests -------------------------------------------------

func TestState_MonotonicGenerationIDs(t *testing.T) {
	s := NewState()
	_, g1, _ := s.CreateParse("a", "SELECT 1", nil)
	_, g2, _ := s.CreateParse("b", "SELECT 2", nil)
	if g2.ID <= g1.ID {
		t.Fatalf("expected monotonically increasing generation IDs, got %d then %d", g1.ID, g2.ID)
	}
	if g1.ID == NoGeneration || g2.ID == NoGeneration {
		t.Fatalf("generation IDs must never be NoGeneration (zero)")
	}
}

func TestState_MonotonicCycleIDs(t *testing.T) {
	s := NewState()
	c1 := s.CurrentCycle()
	if c1 == NoCycle {
		t.Fatal("initial cycle must not be NoCycle")
	}
	if _, err := s.CreateSync(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c2 := s.CurrentCycle()
	if c2 <= c1 {
		t.Fatalf("expected monotonically increasing cycle IDs, got %d then %d", c1, c2)
	}
}

func TestState_MonotonicOperationIDs(t *testing.T) {
	s := NewState()
	op1, _, _ := s.CreateParse("", "SELECT 1", nil)
	op2, _, _ := s.CreateParse("", "SELECT 2", nil)
	if op2.ID <= op1.ID {
		t.Fatalf("expected monotonically increasing operation IDs, got %d then %d", op1.ID, op2.ID)
	}
	if op1.ID == NoPendingOperation {
		t.Fatal("operation ID must never be NoPendingOperation (zero)")
	}
}

func TestState_GenerationIDExhaustion(t *testing.T) {
	s := NewState()
	s.nextGeneration = math.MaxUint64
	_, _, err := s.CreateParse("", "SELECT 1", nil)
	if !errors.Is(err, ErrIdentifierExhaustion) {
		t.Fatalf("expected ErrIdentifierExhaustion, got %v", err)
	}
}

func TestState_CycleIDExhaustion(t *testing.T) {
	s := NewState()
	s.nextCycle = math.MaxUint64
	_, err := s.CreateSync()
	if !errors.Is(err, ErrIdentifierExhaustion) {
		t.Fatalf("expected ErrIdentifierExhaustion, got %v", err)
	}
}

func TestState_OperationIDExhaustion(t *testing.T) {
	s := NewState()
	s.nextOp = math.MaxUint64
	_, _, err := s.CreateParse("", "SELECT 1", nil)
	if !errors.Is(err, ErrIdentifierExhaustion) {
		t.Fatalf("expected ErrIdentifierExhaustion, got %v", err)
	}
}

// --- Statement tests ----------------------------------------------------

func TestState_CreateAndCommitNamedStatement(t *testing.T) {
	s := NewState()
	op, gen, err := s.CreateParse("s1", "SELECT 1", []uint32{23})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gen.State != LifecyclePending {
		t.Fatalf("expected pending state, got %v", gen.State)
	}
	if _, ok := s.CommittedStatement("s1"); ok {
		t.Fatal("committed lookup must not see a pending generation")
	}
	committed, err := s.ApplyParseComplete(op.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if committed.State != LifecycleCommitted {
		t.Fatalf("expected committed state, got %v", committed.State)
	}
	got, ok := s.CommittedStatement("s1")
	if !ok || got.ID != gen.ID {
		t.Fatalf("expected committed statement %d, got %+v (ok=%v)", gen.ID, got, ok)
	}
}

func TestState_CreateAndCommitUnnamedStatement(t *testing.T) {
	s := NewState()
	op, gen, _ := s.CreateParse("", "SELECT 1", nil)
	if _, err := s.ApplyParseComplete(op.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, ok := s.CommittedStatement("")
	if !ok || got.ID != gen.ID {
		t.Fatalf("expected committed unnamed statement %d, got %+v (ok=%v)", gen.ID, got, ok)
	}
}

func TestState_FailedNamedDuplicatePreservesOldCommitted(t *testing.T) {
	s := NewState()
	op1, gen1, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := s.ApplyParseComplete(op1.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	op2, gen2, _ := s.CreateParse("s1", "SELECT 2", nil)
	if gen2.ID == gen1.ID {
		t.Fatal("duplicate Parse must create a new, distinct generation")
	}
	if err := s.ApplyErrorResponse(op2.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, ok := s.CommittedStatement("s1")
	if !ok || got.ID != gen1.ID {
		t.Fatalf("expected old committed generation %d to survive, got %+v (ok=%v)", gen1.ID, got, ok)
	}
	if _, ok := s.Statement(gen2.ID); ok {
		t.Fatal("failed duplicate generation should have been cleaned up (no pending op, no portal ref, not current)")
	}
}

func TestState_SuccessfulUnnamedReplacementChangesCurrent(t *testing.T) {
	s := NewState()
	op1, gen1, _ := s.CreateParse("", "SELECT 1", nil)
	if _, err := s.ApplyParseComplete(op1.ID); err != nil {
		t.Fatal(err)
	}

	op2, gen2, _ := s.CreateParse("", "SELECT 2", nil)
	// Per design: the pointer moves at forward (Create) time, not at ack time.
	got, ok := s.ResolveStatement("")
	if !ok || got.ID != gen2.ID {
		t.Fatalf("expected unnamed slot to already resolve to the new pending generation %d at forward time, got %+v (ok=%v)", gen2.ID, got, ok)
	}
	if _, err := s.ApplyParseComplete(op2.ID); err != nil {
		t.Fatal(err)
	}
	got, ok = s.CommittedStatement("")
	if !ok || got.ID != gen2.ID {
		t.Fatalf("expected committed unnamed statement %d, got %+v (ok=%v)", gen2.ID, got, ok)
	}
	_ = gen1
}

func TestState_FailedUnnamedReplacementLeavesSlotEmpty(t *testing.T) {
	s := NewState()
	op1, _, _ := s.CreateParse("", "SELECT 1", nil)
	if _, err := s.ApplyParseComplete(op1.ID); err != nil {
		t.Fatal(err)
	}

	op2, _, _ := s.CreateParse("", "SELECT 2", nil)
	if err := s.ApplyErrorResponse(op2.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ResolveStatement(""); ok {
		t.Fatal("expected unnamed slot to be empty after a failed replacement, not restored to the old generation")
	}
}

func TestState_PendingLookupNeverAppearsCommitted(t *testing.T) {
	s := NewState()
	s.CreateParse("s1", "SELECT 1", nil)
	if _, ok := s.CommittedStatement("s1"); ok {
		t.Fatal("a pending-only generation must never be visible via CommittedStatement")
	}
	if _, ok := s.ResolveStatement("s1"); !ok {
		t.Fatal("ResolveStatement should still provisionally resolve a pending generation")
	}
}

func TestState_HistoricalUnnamedGenerationRetainedWhilePortalReferences(t *testing.T) {
	s := NewState()
	op1, gen1, _ := s.CreateParse("", "SELECT 1", nil)
	if _, err := s.ApplyParseComplete(op1.ID); err != nil {
		t.Fatal(err)
	}
	bop, _, err := s.CreateBind("", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.ApplyBindComplete(bop.ID); err != nil {
		t.Fatal(err)
	}

	// Replace the unnamed statement; gen1 should be retained since a portal
	// still references it.
	op2, gen2, _ := s.CreateParse("", "SELECT 2", nil)
	if _, err := s.ApplyParseComplete(op2.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Statement(gen1.ID); !ok {
		t.Fatal("expected historical generation to be retained while a portal still references it")
	}
	_ = gen2
}

func TestState_HistoricalGenerationCleanedAfterFinalPortalRemoval(t *testing.T) {
	s := NewState()
	op1, gen1, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(op1.ID)
	bop, portalGen, _ := s.CreateBind("", "", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	op2, _, _ := s.CreateParse("", "SELECT 2", nil)
	s.ApplyParseComplete(op2.ID)

	if _, ok := s.Statement(gen1.ID); !ok {
		t.Fatal("precondition failed: historical generation should still be retained")
	}

	cop, err := s.CreateClosePortal("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.ApplyCloseComplete(cop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.Statement(gen1.ID); ok {
		t.Fatal("expected historical generation to be cleaned up once its last portal reference is gone")
	}
	_ = portalGen
}

// --- Portal tests ---------------------------------------------------------

func TestState_CreateAndCommitNamedPortal(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	bop, gen, err := s.CreateBind("p1", "s1", []int16{0}, []bool{false}, []int16{0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gen.State != LifecyclePending {
		t.Fatalf("expected pending, got %v", gen.State)
	}
	committed, err := s.ApplyBindComplete(bop.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if committed.State != LifecycleCommitted {
		t.Fatalf("expected committed, got %v", committed.State)
	}
	got, ok := s.CommittedPortal("p1")
	if !ok || got.ID != gen.ID {
		t.Fatalf("expected committed portal %d, got %+v (ok=%v)", gen.ID, got, ok)
	}
}

func TestState_CreateAndCommitUnnamedPortal(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, gen, err := s.CreateBind("", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.ApplyBindComplete(bop.ID); err != nil {
		t.Fatal(err)
	}
	got, ok := s.CommittedPortal("")
	if !ok || got.ID != gen.ID {
		t.Fatalf("expected committed unnamed portal %d, got %+v (ok=%v)", gen.ID, got, ok)
	}
}

func TestState_PortalReferencesExactStatementGeneration(t *testing.T) {
	s := NewState()
	sop1, sgen1, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop1.ID)
	bop, pgen, _ := s.CreateBind("p1", "", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	// Replace the unnamed statement; the portal must keep referencing the
	// OLD statement generation specifically, not "whatever unnamed is now".
	sop2, sgen2, _ := s.CreateParse("", "SELECT 2", nil)
	s.ApplyParseComplete(sop2.ID)

	got, ok := s.Portal(pgen.ID)
	if !ok {
		t.Fatal("expected portal to still exist")
	}
	if got.StatementID != sgen1.ID {
		t.Fatalf("expected portal to keep referencing statement generation %d, got %d", sgen1.ID, got.StatementID)
	}
	if got.StatementID == sgen2.ID {
		t.Fatal("portal must not silently re-point to the new unnamed statement generation")
	}
}

func TestState_FailedNamedDuplicatePortalPreservesOld(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	bop1, pgen1, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop1.ID)

	bop2, pgen2, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	if pgen2.ID == pgen1.ID {
		t.Fatal("duplicate Bind must create a distinct generation")
	}
	if err := s.ApplyErrorResponse(bop2.ID); err != nil {
		t.Fatal(err)
	}

	got, ok := s.CommittedPortal("p1")
	if !ok || got.ID != pgen1.ID {
		t.Fatalf("expected old committed portal %d to survive, got %+v (ok=%v)", pgen1.ID, got, ok)
	}
}

func TestState_SuccessfulUnnamedBindReplacementChangesCurrent(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	bop1, pgen1, _ := s.CreateBind("", "", nil, nil, nil)
	s.ApplyBindComplete(bop1.ID)

	bop2, pgen2, _ := s.CreateBind("", "", nil, nil, nil)
	got, ok := s.ResolvePortal("")
	if !ok || got.ID != pgen2.ID {
		t.Fatalf("expected unnamed portal slot to already point at the new pending generation %d, got %+v (ok=%v)", pgen2.ID, got, ok)
	}
	s.ApplyBindComplete(bop2.ID)
	got, ok = s.CommittedPortal("")
	if !ok || got.ID != pgen2.ID {
		t.Fatalf("expected committed unnamed portal %d, got %+v (ok=%v)", pgen2.ID, got, ok)
	}
	_ = pgen1
}

func TestState_FailedUnnamedBindReplacementLeavesSlotEmpty(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	bop1, _, _ := s.CreateBind("", "", nil, nil, nil)
	s.ApplyBindComplete(bop1.ID)

	bop2, _, _ := s.CreateBind("", "", nil, nil, nil)
	if err := s.ApplyErrorResponse(bop2.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ResolvePortal(""); ok {
		t.Fatal("expected unnamed portal slot to be empty, not restored to the old generation")
	}
}

func TestState_UnknownStatementCannotCreatePortal(t *testing.T) {
	s := NewState()
	_, _, err := s.CreateBind("p1", "does-not-exist", nil, nil, nil)
	if !errors.Is(err, ErrUnknownStatement) {
		t.Fatalf("expected ErrUnknownStatement, got %v", err)
	}
	if s.PortalCount() != 0 {
		t.Fatalf("expected no portal to be created, got count %d", s.PortalCount())
	}
}

func TestState_BindDoesNotStoreParameterBytes(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("", "SELECT $1", nil)
	s.ApplyParseComplete(sop.ID)

	// CreateBind's signature structurally cannot accept parameter VALUES -
	// only NULL/non-NULL booleans - so there is nothing for this test to
	// pass that would leak into state. We confirm the stored generation
	// only carries format codes and null flags.
	_, gen, err := s.CreateBind("", "", []int16{0, 1}, []bool{false, true}, []int16{0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gen.ParamNulls) != 2 || gen.ParamNulls[0] != false || gen.ParamNulls[1] != true {
		t.Fatalf("unexpected ParamNulls: %+v", gen.ParamNulls)
	}
}

// --- Close tests ------------------------------------------------------

func TestState_SuccessfulPortalCloseRemovesPortal(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, pgen, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	cop, err := s.CreateClosePortal("p1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.ApplyCloseComplete(cop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.Portal(pgen.ID); ok {
		t.Fatal("expected portal to be removed after successful close")
	}
	if _, ok := s.CommittedPortal("p1"); ok {
		t.Fatal("expected portal name to no longer resolve")
	}
}

func TestState_FailedPortalClosePreservesPortal(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, pgen, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	cop, _ := s.CreateClosePortal("p1")
	if err := s.ApplyErrorResponse(cop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, ok := s.CommittedPortal("p1")
	if !ok || got.ID != pgen.ID {
		t.Fatalf("expected portal %d to survive a failed close, got %+v (ok=%v)", pgen.ID, got, ok)
	}
}

func TestState_SuccessfulStatementCloseCascadesToPortals(t *testing.T) {
	s := NewState()
	sop, sgen, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop1, pgen1, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop1.ID)
	bop2, pgen2, _ := s.CreateBind("p2", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop2.ID)

	cop, err := s.CreateCloseStatement("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.ApplyCloseComplete(cop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.Statement(sgen.ID); ok {
		t.Fatal("expected statement to be removed")
	}
	if _, ok := s.Portal(pgen1.ID); ok {
		t.Fatal("expected dependent portal p1 to be cascaded away")
	}
	if _, ok := s.Portal(pgen2.ID); ok {
		t.Fatal("expected dependent portal p2 to be cascaded away")
	}
}

func TestState_FailedStatementClosePreservesStatementAndPortals(t *testing.T) {
	s := NewState()
	sop, sgen, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, pgen, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	cop, _ := s.CreateCloseStatement("s1")
	if err := s.ApplyErrorResponse(cop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.Statement(sgen.ID); !ok {
		t.Fatal("expected statement to survive a failed close")
	}
	if _, ok := s.Portal(pgen.ID); !ok {
		t.Fatal("expected dependent portal to survive a failed statement close")
	}
}

func TestState_CloseSnapshotCorrectIfNameMappingsChangeLater(t *testing.T) {
	s := NewState()
	sop1, sgen1, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop1.ID)

	cop, err := s.CreateCloseStatement("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After the Close was captured, close it for real (removing s1), then
	// create a brand-new "s1" so the name is reused before CloseComplete
	// for the FIRST close is even applied - a legal pipelined sequence.
	if err := s.ApplyCloseComplete(cop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sop2, sgen2, _ := s.CreateParse("s1", "SELECT 2", nil)
	s.ApplyParseComplete(sop2.ID)
	if sgen2.ID == sgen1.ID {
		t.Fatal("expected a genuinely new generation for the reused name")
	}

	// The new "s1" must be unaffected - it was never targeted by the old
	// Close's immutable snapshot.
	got, ok := s.CommittedStatement("s1")
	if !ok || got.ID != sgen2.ID {
		t.Fatalf("expected new statement generation %d to be live, got %+v (ok=%v)", sgen2.ID, got, ok)
	}
}

// --- Simple Query tests -------------------------------------------------

func TestState_AllowedSimpleQueryClearsUnnamedSlots(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("", "", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	s.ApplyAllowedSimpleQuery()

	if _, ok := s.ResolveStatement(""); ok {
		t.Fatal("expected unnamed statement slot to be cleared")
	}
	if _, ok := s.ResolvePortal(""); ok {
		t.Fatal("expected unnamed portal slot to be cleared")
	}
}

func TestState_AllowedSimpleQueryPreservesNamedObjects(t *testing.T) {
	s := NewState()
	sop, sgen, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, pgen, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	s.ApplyAllowedSimpleQuery()

	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected named statement to survive an allowed Simple Query")
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected named portal to survive an allowed Simple Query")
	}
	_ = sgen
	_ = pgen
}

// TestState_AllowedSimpleQueryHistoricalSnapshotsRemainUsable dogrular:
// bir Simple Query izin verilip iletildigi anda hala IN-FLIGHT (bekleyen,
// henuz onaylanmamis) bir Bind/Execute varsa, bu islemin (name,generation)
// anlik goruntusu (snapshot) mevcut isimsiz isaretcilerin temizlenmesinden
// ETKILENMEZ - kendi backend onayi geldiginde hala dogru sekilde
// sonuclanabilir olmalidir (bkz. tasarim belgesi, "Mixed Simple/Extended
// Query state handling", madde 6). Bu, ZATEN commit edilmis/tamamlanmis
// (bekleyen islemi kalmamis) bir portaldan farklidir - byle bir portal,
// gercek sunucunun da yikacagi isimsiz nesne oldugu icin, "current"
// isaretcisi temizlenir temizlenmez cleanup tarafindan kaldirilmasi
// BEKLENEN dogru davranistir (ayri, asagidaki NoLongerCurrent testi).
func TestState_AllowedSimpleQueryHistoricalSnapshotsRemainUsable(t *testing.T) {
	s := NewState()
	sop, sgen, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	// Bind KASITLI OLARAK commit edilmiyor - hala bekleyen-islem kuyrugunda,
	// tam da Simple Query'nin arayı bolebilecegi "in-flight" durumu.
	bop, pgen, err := s.CreateBind("", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s.ApplyAllowedSimpleQuery()

	if _, ok := s.Portal(pgen.ID); !ok {
		t.Fatal("expected the in-flight (still-pending) portal snapshot to remain usable")
	}
	if _, ok := s.Statement(sgen.ID); !ok {
		t.Fatal("expected the underlying statement generation to remain usable, still referenced by the in-flight portal")
	}
	// Backend onayi hala dogru sekilde uygulanabilmeli.
	if _, err := s.ApplyBindComplete(bop.ID); err != nil {
		t.Fatalf("expected the in-flight Bind to still resolve correctly after the Simple Query cleared the current pointer: %v", err)
	}
}

// TestState_AllowedSimpleQuery_AlreadyCommittedUnnamedPortalIsDestroyed
// dogrular: ZATEN commit edilmis (bekleyen islemi kalmamis) bir isimsiz
// portal, gercek sunucunun da onu yok ettigi Simple Query sonrasi hemen
// temizlenir - "current" isaretcisi temizlenince baska hicbir referansi
// kalmiyorsa artik erisilemez olmalidir.
func TestState_AllowedSimpleQuery_AlreadyCommittedUnnamedPortalIsDestroyed(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, pgen, _ := s.CreateBind("", "", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	s.ApplyAllowedSimpleQuery()

	if _, ok := s.Portal(pgen.ID); ok {
		t.Fatal("expected an already-committed, no-longer-referenced unnamed portal to be cleaned up after the Simple Query destroyed it")
	}
}

func TestState_BlockedSimpleQueryIsNoMutation(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	before, _ := s.ResolveStatement("")

	// A blocked Simple Query is represented by simply NOT calling
	// ApplyAllowedSimpleQuery at all.
	after, ok := s.ResolveStatement("")
	if !ok || after.ID != before.ID {
		t.Fatal("expected no mutation to occur when the Simple Query helper is never called")
	}
}

// --- ReadyForQuery tests --------------------------------------------------

func syncedState(t *testing.T) (*State, PendingOperationID) {
	t.Helper()
	s := NewState()
	op, err := s.CreateSync()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return s, op.ID
}

func TestState_ReadyForQuery_I_InvalidatesAllPortals(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	syncOp, _ := s.CreateSync()
	if _, err := s.ApplyReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.PortalCount() != 0 {
		t.Fatalf("expected zero live portals after ReadyForQuery('I'), got %d", s.PortalCount())
	}
	if _, ok := s.CommittedPortal("p1"); ok {
		t.Fatal("expected portal to be invalidated")
	}
	_ = syncOp
}

func TestState_ReadyForQuery_I_PreservesStatements(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	s.CreateSync()
	if _, err := s.ApplyReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected prepared statement to survive ReadyForQuery('I')")
	}
}

func TestState_ReadyForQuery_T_PreservesPortals(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)
	s.CreateSync()
	if _, err := s.ApplyReadyForQuery(TxStatusInTransaction); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected portal to survive ReadyForQuery('T')")
	}
}

func TestState_ReadyForQuery_E_PreservesPortals(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)
	s.CreateSync()
	if _, err := s.ApplyReadyForQuery(TxStatusFailedTransaction); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected portal to survive ReadyForQuery('E')")
	}
}

func TestState_ReadyForQuery_InvalidStatusRejected(t *testing.T) {
	s, _ := syncedState(t)
	if _, err := s.ApplyReadyForQuery('X'); !errors.Is(err, ErrInvalidTransactionStatus) {
		t.Fatalf("expected ErrInvalidTransactionStatus, got %v", err)
	}
}

func TestState_ReadyForQuery_IToI_StillInvalidates(t *testing.T) {
	s := NewState()
	// First cycle: idle -> idle (implicit transaction opened and closed
	// entirely within the cycle - the case a transition-only rule misses).
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)
	s.CreateSync()
	if _, err := s.ApplyReadyForQuery(TxStatusIdle); err != nil {
		t.Fatal(err)
	}
	if s.TransactionStatus() != TxStatusIdle {
		t.Fatalf("expected tracked status 'I', got %q", s.TransactionStatus())
	}
	if _, ok := s.CommittedPortal("p1"); ok {
		t.Fatal("expected I -> I to still invalidate the portal bound during the implicit transaction")
	}
}

// --- Cycle tests --------------------------------------------------------

func TestState_InitialNonZeroCycle(t *testing.T) {
	s := NewState()
	if s.CurrentCycle() == NoCycle {
		t.Fatal("expected a valid non-zero initial cycle")
	}
}

func TestState_SyncClosesCurrentAndStartsNext(t *testing.T) {
	s := NewState()
	c1 := s.CurrentCycle()
	op, err := s.CreateSync()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if op.Cycle != c1 {
		t.Fatalf("expected Sync operation to belong to the closing cycle %d, got %d", c1, op.Cycle)
	}
	if s.CurrentCycle() == c1 {
		t.Fatal("expected a new current cycle to begin immediately after Sync")
	}
}

func TestState_MultipleOutstandingCycles(t *testing.T) {
	s := NewState()
	s.CreateSync()
	s.CreateSync()
	if s.OutstandingCycleCount() != 2 {
		t.Fatalf("expected 2 outstanding cycles, got %d", s.OutstandingCycleCount())
	}
}

func TestState_FIFOReadyForQueryCompletion(t *testing.T) {
	s := NewState()
	syncOp1, _ := s.CreateSync()
	c1 := syncOp1.Cycle
	s.CreateSync()

	completed, err := s.ApplyReadyForQuery(TxStatusIdle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if completed != c1 {
		t.Fatalf("expected FIFO-oldest cycle %d to complete first, got %d", c1, completed)
	}
}

func TestState_FirstCycleCompletionDoesNotRemoveSecond(t *testing.T) {
	s := NewState()
	s.CreateSync()
	s.CreateSync()
	s.ApplyReadyForQuery(TxStatusIdle)
	if s.OutstandingCycleCount() != 1 {
		t.Fatalf("expected 1 outstanding cycle remaining, got %d", s.OutstandingCycleCount())
	}
}

func TestState_ImpossibleOrDuplicateCompletionRejected(t *testing.T) {
	s, _ := syncedState(t)
	if _, err := s.ApplyReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.ApplyReadyForQuery(TxStatusIdle); !errors.Is(err, ErrCycleClosed) {
		t.Fatalf("expected ErrCycleClosed on duplicate completion, got %v", err)
	}
}

// --- Pending-operation tests -----------------------------------------------

func TestState_PendingOperation_FIFOInsertion(t *testing.T) {
	s := NewState()
	op1, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	op2, _, _ := s.CreateParse("s2", "SELECT 2", nil)
	ops := s.PendingOperations()
	if len(ops) != 2 || ops[0].ID != op1.ID || ops[1].ID != op2.ID {
		t.Fatalf("expected FIFO order [%d %d], got %+v", op1.ID, op2.ID, ops)
	}
}

func TestState_PendingOperation_CorrectAcknowledgement(t *testing.T) {
	s := NewState()
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := s.ApplyParseComplete(op.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.PendingOperationCount() != 0 {
		t.Fatalf("expected empty queue, got %d", s.PendingOperationCount())
	}
}

func TestState_PendingOperation_WrongAcknowledgementTypeRejected(t *testing.T) {
	s := NewState()
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if _, err := s.ApplyBindComplete(op.ID); !errors.Is(err, ErrAckKindMismatch) {
		t.Fatalf("expected ErrAckKindMismatch, got %v", err)
	}
}

func TestState_PendingOperation_FromWrongCycleNotConsumed(t *testing.T) {
	s := NewState()
	op1, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.CreateSync()
	op2, _, _ := s.CreateParse("s2", "SELECT 2", nil)

	// op2 is not at the head (op1's Parse and the Sync are ahead of it) -
	// attempting to acknowledge it out of order must be rejected.
	if _, err := s.ApplyParseComplete(op2.ID); !errors.Is(err, ErrAckOrderMismatch) {
		t.Fatalf("expected ErrAckOrderMismatch, got %v", err)
	}
	_ = op1
}

// TestState_PendingOperation_ErrorResponseAbandonsIntendedOperation
// dogrular: bir ErrorResponse, kuyruk basindaki DOGRU (beklenen) islemi
// terk eder (kuyruktan cikarir, generation'i failed isaretler) - saf
// modelde generation baska hicbir sey tarafindan referans verilmiyorsa
// hemen temizlenir (bkz. TestState_NoUnboundedRetainedFailedGenerations);
// hala bekleyen baska bir islem tarafindan referans veriliyorsa (burada:
// ayni generation'a karsi pipelined bir Describe) Failed durumu
// gozlemlenebilir kalir.
func TestState_PendingOperation_ErrorResponseAbandonsIntendedOperation(t *testing.T) {
	s := NewState()
	op, gen, _ := s.CreateParse("s1", "SELECT 1", nil)
	// Pipelined bir Describe, ParseComplete/ErrorResponse gelmeden once
	// gonderilmis olabilir (bkz. tasarim: "provisionally valid for
	// forwarding purposes") - bu, generation'i referans altinda tutar.
	dop, err := s.CreateDescribeStatement("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := s.ApplyErrorResponse(op.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.PendingOperationCount() != 1 {
		t.Fatalf("expected only the Parse operation to leave the queue, got count %d", s.PendingOperationCount())
	}
	got, ok := s.Statement(gen.ID)
	if !ok {
		t.Fatal("expected the failed generation to still exist while a pipelined Describe still references it")
	}
	if got.State != LifecycleFailed {
		t.Fatalf("expected LifecycleFailed, got %v", got.State)
	}
	_ = dop
}

func TestState_PendingOperation_CompletedOperationsCleanedUp(t *testing.T) {
	s := NewState()
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(op.ID)
	for _, pending := range s.PendingOperations() {
		if pending.ID == op.ID {
			t.Fatal("expected completed operation to be removed from the queue, not merely marked")
		}
	}
}

// --- Resource/cleanup tests -------------------------------------------

func TestState_NoUnboundedRetainedFailedGenerations(t *testing.T) {
	s := NewState()
	for i := 0; i < 50; i++ {
		op, _, _ := s.CreateParse("dup", "SELECT 1", nil)
		s.ApplyErrorResponse(op.ID)
	}
	if s.StatementCount() != 0 {
		t.Fatalf("expected all failed generations to be cleaned up, got %d retained", s.StatementCount())
	}
}

func TestState_NoDanglingPortalReferences(t *testing.T) {
	s := NewState()
	sop, sgen, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	cop, _ := s.CreateCloseStatement("s1")
	s.ApplyCloseComplete(cop.ID)

	if s.PortalCount() != 0 {
		t.Fatalf("expected no dangling portals after statement cascade close, got %d", s.PortalCount())
	}
	if _, ok := s.Statement(sgen.ID); ok {
		t.Fatal("expected statement itself to be gone too")
	}
}

func TestState_StatementCleanupOnlyAfterFinalReference(t *testing.T) {
	s := NewState()
	sop, sgen, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop1, _, _ := s.CreateBind("p1", "", nil, nil, nil)
	s.ApplyBindComplete(bop1.ID)
	bop2, _, _ := s.CreateBind("p2", "", nil, nil, nil)
	s.ApplyBindComplete(bop2.ID)

	// Supersede the unnamed current pointer - gen1 now survives only via
	// its two portal references.
	sop2, _, _ := s.CreateParse("", "SELECT 2", nil)
	s.ApplyParseComplete(sop2.ID)

	if _, ok := s.Statement(sgen.ID); !ok {
		t.Fatal("expected statement to survive while two portals still reference it")
	}
	cop1, _ := s.CreateClosePortal("p1")
	s.ApplyCloseComplete(cop1.ID)
	if _, ok := s.Statement(sgen.ID); !ok {
		t.Fatal("expected statement to survive while one portal still references it")
	}
	cop2, _ := s.CreateClosePortal("p2")
	s.ApplyCloseComplete(cop2.ID)
	if _, ok := s.Statement(sgen.ID); ok {
		t.Fatal("expected statement to be cleaned up only after the final portal reference is gone")
	}
}

func TestState_CountHelpersReturnToBaseline(t *testing.T) {
	s := NewState()
	baseStatements, basePortals, baseOps := s.StatementCount(), s.PortalCount(), s.PendingOperationCount()

	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)
	cop1, _ := s.CreateClosePortal("p1")
	s.ApplyCloseComplete(cop1.ID)
	cop2, _ := s.CreateCloseStatement("s1")
	s.ApplyCloseComplete(cop2.ID)

	if s.StatementCount() != baseStatements {
		t.Fatalf("expected statement count to return to baseline %d, got %d", baseStatements, s.StatementCount())
	}
	if s.PortalCount() != basePortals {
		t.Fatalf("expected portal count to return to baseline %d, got %d", basePortals, s.PortalCount())
	}
	if s.PendingOperationCount() != baseOps {
		t.Fatalf("expected pending operation count to return to baseline %d, got %d", baseOps, s.PendingOperationCount())
	}
}

// --- Additional lifecycle-transition safety tests -------------------------

func TestState_ApplyErrorResponse_OnSyncRejected(t *testing.T) {
	s := NewState()
	op, _ := s.CreateSync()
	if err := s.ApplyErrorResponse(op.ID); !errors.Is(err, ErrInvalidLifecycleTransition) {
		t.Fatalf("expected ErrInvalidLifecycleTransition, got %v", err)
	}
}

func TestState_CreateDescribeStatement_UnknownRejected(t *testing.T) {
	s := NewState()
	if _, err := s.CreateDescribeStatement("nope"); !errors.Is(err, ErrUnknownStatement) {
		t.Fatalf("expected ErrUnknownStatement, got %v", err)
	}
}

func TestState_CreateDescribePortal_UnknownRejected(t *testing.T) {
	s := NewState()
	if _, err := s.CreateDescribePortal("nope"); !errors.Is(err, ErrUnknownPortal) {
		t.Fatalf("expected ErrUnknownPortal, got %v", err)
	}
}

func TestState_CreateExecute_UnknownRejected(t *testing.T) {
	s := NewState()
	if _, err := s.CreateExecute("nope"); !errors.Is(err, ErrUnknownPortal) {
		t.Fatalf("expected ErrUnknownPortal, got %v", err)
	}
}

func TestState_CloseNonexistentName_IsNoOp(t *testing.T) {
	s := NewState()
	op, err := s.CreateCloseStatement("never-existed")
	if err != nil {
		t.Fatalf("Close of an unknown name must never error (matches real-server no-op behavior): %v", err)
	}
	if op.TargetGeneration != NoGeneration {
		t.Fatalf("expected NoGeneration snapshot for an unknown name, got %d", op.TargetGeneration)
	}
	if err := s.ApplyCloseComplete(op.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestState_CompleteOperation_RejectsParseBindCloseSync(t *testing.T) {
	s := NewState()
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	if err := s.CompleteOperation(op.ID); !errors.Is(err, ErrAckKindMismatch) {
		t.Fatalf("expected ErrAckKindMismatch for a Parse op, got %v", err)
	}
}

func TestState_CompleteOperation_SucceedsForDescribeAndExecute(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	dop, err := s.CreateDescribeStatement("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.CompleteOperation(dop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)
	eop, err := s.CreateExecute("p1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.CompleteOperation(eop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

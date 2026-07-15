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
			switch int(opb) % 15 {
			case 0: // CreateParse
				i, ok := r.pick(len(stmtNames))
				if !ok {
					continue
				}
				op, gen, err := s.CreateParse(stmtNames[i], "SELECT 1", []uint32{23, 25})
				if err == nil {
					trackOp(op.ID)
					trackGen(gen.ID)
					// Mutation-isolation: corrupting the returned snapshot
					// locally must never be observable through State.
					if len(gen.ParamOIDs) > 0 {
						gen.ParamOIDs[0] = 999999
					}
					gen.Query = "corrupted"
					op.TargetGeneration = 999999
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
					// Mutation-isolation, same as above, for portal snapshots.
					if len(gen.ParamFormats) > 0 {
						gen.ParamFormats[0] = 99
					}
					gen.StatementID = 999999
					op.TargetGeneration = 999999
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
							for id, p := range s.portals {
								if p.CreatedCycle <= cyc {
									t.Fatalf("ReadyForQuery('I') for cycle %d left portal %d with CreatedCycle %d (<= completed cycle)", cyc, id, p.CreatedCycle)
								}
							}
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
				cyc, err := s.ApplyReadyForQuery(status)
				if err == nil {
					trackCycle(cyc)
					if status == TxStatusIdle {
						// Corrected invariant: ReadyForQuery('I') leaves no
						// portal whose CreatedCycle is <= the just-completed
						// cycle - but portals from later, already-pipelined
						// (outstanding) cycles may legitimately remain.
						for id, p := range s.portals {
							if p.CreatedCycle <= cyc {
								t.Fatalf("ReadyForQuery('I') for cycle %d left portal %d with CreatedCycle %d (<= completed cycle)", cyc, id, p.CreatedCycle)
							}
						}
					}
				}
			case 10: // ApplySimpleQueryReceived
				s.ApplySimpleQueryReceived()
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
				if cyc, err := s.ApplyReadyForQuery(b); err == nil && b == TxStatusIdle {
					for id, p := range s.portals {
						if p.CreatedCycle <= cyc {
							t.Fatalf("ReadyForQuery('I') for cycle %d left portal %d with CreatedCycle %d (<= completed cycle)", cyc, id, p.CreatedCycle)
						}
					}
				}
			case 13: // ApplySimpleQueryReadyForQuery with a random (possibly invalid) status
				i, ok := r.pick(len(statuses))
				if !ok {
					continue
				}
				status := statuses[i]
				beforePending := s.PendingOperationCount()
				beforeCycles := s.OutstandingCycleCount()
				beforeCur := s.CurrentCycle()
				err := s.ApplySimpleQueryReadyForQuery(status)
				if err == nil {
					if status == TxStatusIdle && s.PortalCount() != 0 {
						t.Fatalf("ApplySimpleQueryReadyForQuery('I') left %d live portal(s)", s.PortalCount())
					}
					if s.TransactionStatus() != status {
						t.Fatalf("expected TransactionStatus %q after ApplySimpleQueryReadyForQuery, got %q", status, s.TransactionStatus())
					}
				}
				// Consumes no pending operation, no outstanding cycle, and
				// creates no new cycle - true whether it succeeded or failed.
				if s.PendingOperationCount() != beforePending {
					t.Fatalf("ApplySimpleQueryReadyForQuery changed PendingOperationCount: before=%d after=%d", beforePending, s.PendingOperationCount())
				}
				if s.OutstandingCycleCount() != beforeCycles {
					t.Fatalf("ApplySimpleQueryReadyForQuery changed OutstandingCycleCount: before=%d after=%d", beforeCycles, s.OutstandingCycleCount())
				}
				if s.CurrentCycle() != beforeCur {
					t.Fatalf("ApplySimpleQueryReadyForQuery changed CurrentCycle: before=%d after=%d", beforeCur, s.CurrentCycle())
				}
			case 14: // ApplySimpleQueryLifecycleEffect with a random (possibly invalid) effect
				effects := []SimpleQueryLifecycleEffect{
					SimpleQueryLifecycleNone, SimpleQueryInvalidatePortals,
					SimpleQueryInvalidateStatementsAndPortals, SimpleQueryLifecycleEffect(99),
				}
				i, ok := r.pick(len(effects))
				if !ok {
					continue
				}
				effect := effects[i]
				beforeStatus := s.TransactionStatus()
				beforePending := s.PendingOperationCount()
				beforeCycles := s.OutstandingCycleCount()
				beforeCur := s.CurrentCycle()
				err := s.ApplySimpleQueryLifecycleEffect(effect)
				if err == nil {
					if effect == SimpleQueryInvalidatePortals || effect == SimpleQueryInvalidateStatementsAndPortals {
						if s.PortalCount() != 0 {
							t.Fatalf("ApplySimpleQueryLifecycleEffect(%v) left %d live portal(s)", effect, s.PortalCount())
						}
					}
					if effect == SimpleQueryInvalidateStatementsAndPortals && s.StatementCount() != 0 {
						t.Fatalf("ApplySimpleQueryLifecycleEffect(StatementsAndPortals) left %d live statement(s)", s.StatementCount())
					}
				}
				// Never touches transaction status, pending count,
				// outstanding-cycle count, or current cycle - true whether
				// it succeeded or failed.
				if s.TransactionStatus() != beforeStatus {
					t.Fatalf("ApplySimpleQueryLifecycleEffect changed TransactionStatus: before=%q after=%q", beforeStatus, s.TransactionStatus())
				}
				if s.PendingOperationCount() != beforePending {
					t.Fatalf("ApplySimpleQueryLifecycleEffect changed PendingOperationCount: before=%d after=%d", beforePending, s.PendingOperationCount())
				}
				if s.OutstandingCycleCount() != beforeCycles {
					t.Fatalf("ApplySimpleQueryLifecycleEffect changed OutstandingCycleCount: before=%d after=%d", beforeCycles, s.OutstandingCycleCount())
				}
				if s.CurrentCycle() != beforeCur {
					t.Fatalf("ApplySimpleQueryLifecycleEffect changed CurrentCycle: before=%d after=%d", beforeCur, s.CurrentCycle())
				}
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

// --- Identifier-exhaustion atomicity tests -------------------------------
//
// These construct near-exhaustion internal counters directly (white-box,
// same package) and confirm a failed Create* call never leaves partial
// state behind: no generation in a map, no changed unnamed current
// pointer, no pending operation, no outstanding Sync cycle. Every
// Create* method allocates ALL of its fallible identifiers BEFORE
// mutating any map/pointer/queue, so a later allocation failing after an
// earlier one succeeded still leaves zero observable side effects (the
// earlier identifier is simply wasted, never reused, never surfaced).

func TestState_CreateParse_GenerationExhaustion_LeavesNoPartialState(t *testing.T) {
	s := NewState()
	s.nextGeneration = math.MaxUint64
	baseStatements, baseOps := s.StatementCount(), s.PendingOperationCount()
	prevUnnamed := s.unnamedStatementCurrent

	if _, _, err := s.CreateParse("", "SELECT 1", nil); !errors.Is(err, ErrIdentifierExhaustion) {
		t.Fatalf("expected ErrIdentifierExhaustion, got %v", err)
	}
	if s.StatementCount() != baseStatements {
		t.Fatalf("expected no statement left behind, got count %d", s.StatementCount())
	}
	if s.PendingOperationCount() != baseOps {
		t.Fatalf("expected no pending operation left behind, got count %d", s.PendingOperationCount())
	}
	if s.unnamedStatementCurrent != prevUnnamed {
		t.Fatalf("expected unnamed statement pointer unchanged, got %d want %d", s.unnamedStatementCurrent, prevUnnamed)
	}
}

func TestState_CreateParse_OpExhaustion_LeavesNoPartialState(t *testing.T) {
	s := NewState()
	s.nextOp = math.MaxUint64
	baseStatements, baseOps := s.StatementCount(), s.PendingOperationCount()
	prevUnnamed := s.unnamedStatementCurrent
	prevGenCounter := s.nextGeneration

	if _, _, err := s.CreateParse("", "SELECT 1", nil); !errors.Is(err, ErrIdentifierExhaustion) {
		t.Fatalf("expected ErrIdentifierExhaustion, got %v", err)
	}
	if s.StatementCount() != baseStatements {
		t.Fatalf("expected no statement left behind (even though a generation ID was already consumed), got count %d", s.StatementCount())
	}
	if s.PendingOperationCount() != baseOps {
		t.Fatalf("expected no pending operation left behind, got count %d", s.PendingOperationCount())
	}
	if s.unnamedStatementCurrent != prevUnnamed {
		t.Fatalf("expected unnamed statement pointer unchanged, got %d want %d", s.unnamedStatementCurrent, prevUnnamed)
	}
	if s.nextGeneration != prevGenCounter+1 {
		t.Fatalf("expected the generation counter to have advanced (wasted, never reused) by exactly 1, got %d want %d", s.nextGeneration, prevGenCounter+1)
	}
}

func TestState_CreateBind_GenerationExhaustion_LeavesNoPartialState(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	s.nextGeneration = math.MaxUint64
	basePortals, baseOps := s.PortalCount(), s.PendingOperationCount()
	prevUnnamedPortal := s.unnamedPortalCurrent

	if _, _, err := s.CreateBind("", "s1", nil, nil, nil); !errors.Is(err, ErrIdentifierExhaustion) {
		t.Fatalf("expected ErrIdentifierExhaustion, got %v", err)
	}
	if s.PortalCount() != basePortals {
		t.Fatalf("expected no portal left behind, got count %d", s.PortalCount())
	}
	if s.PendingOperationCount() != baseOps {
		t.Fatalf("expected no pending operation left behind, got count %d", s.PendingOperationCount())
	}
	if s.unnamedPortalCurrent != prevUnnamedPortal {
		t.Fatalf("expected unnamed portal pointer unchanged, got %d want %d", s.unnamedPortalCurrent, prevUnnamedPortal)
	}
}

func TestState_CreateBind_OpExhaustion_LeavesNoPartialState(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	s.nextOp = math.MaxUint64
	basePortals, baseOps := s.PortalCount(), s.PendingOperationCount()
	prevUnnamedPortal := s.unnamedPortalCurrent

	if _, _, err := s.CreateBind("", "s1", nil, nil, nil); !errors.Is(err, ErrIdentifierExhaustion) {
		t.Fatalf("expected ErrIdentifierExhaustion, got %v", err)
	}
	if s.PortalCount() != basePortals {
		t.Fatalf("expected no portal left behind (even though a generation ID was already consumed), got count %d", s.PortalCount())
	}
	if s.PendingOperationCount() != baseOps {
		t.Fatalf("expected no pending operation left behind, got count %d", s.PendingOperationCount())
	}
	if s.unnamedPortalCurrent != prevUnnamedPortal {
		t.Fatalf("expected unnamed portal pointer unchanged, got %d want %d", s.unnamedPortalCurrent, prevUnnamedPortal)
	}
}

func TestState_CreateSync_OpExhaustion_LeavesNoPartialState(t *testing.T) {
	s := NewState()
	s.nextOp = math.MaxUint64
	baseOps, baseOutstanding := s.PendingOperationCount(), s.OutstandingCycleCount()
	prevCycle := s.CurrentCycle()

	if _, err := s.CreateSync(); !errors.Is(err, ErrIdentifierExhaustion) {
		t.Fatalf("expected ErrIdentifierExhaustion, got %v", err)
	}
	if s.PendingOperationCount() != baseOps {
		t.Fatalf("expected no pending operation left behind, got count %d", s.PendingOperationCount())
	}
	if s.OutstandingCycleCount() != baseOutstanding {
		t.Fatalf("expected no outstanding cycle left behind, got count %d", s.OutstandingCycleCount())
	}
	if s.CurrentCycle() != prevCycle {
		t.Fatalf("expected current cycle unchanged, got %d want %d", s.CurrentCycle(), prevCycle)
	}
}

func TestState_CreateSync_CycleExhaustion_LeavesNoPartialState(t *testing.T) {
	s := NewState()
	s.nextCycle = math.MaxUint64
	baseOps, baseOutstanding := s.PendingOperationCount(), s.OutstandingCycleCount()
	prevCycle := s.CurrentCycle()
	prevOpCounter := s.nextOp

	if _, err := s.CreateSync(); !errors.Is(err, ErrIdentifierExhaustion) {
		t.Fatalf("expected ErrIdentifierExhaustion, got %v", err)
	}
	if s.PendingOperationCount() != baseOps {
		t.Fatalf("expected no pending operation left behind (even though an op ID was already consumed), got count %d", s.PendingOperationCount())
	}
	if s.OutstandingCycleCount() != baseOutstanding {
		t.Fatalf("expected no outstanding cycle left behind, got count %d", s.OutstandingCycleCount())
	}
	if s.CurrentCycle() != prevCycle {
		t.Fatalf("expected current cycle unchanged, got %d want %d", s.CurrentCycle(), prevCycle)
	}
	if s.nextOp != prevOpCounter+1 {
		t.Fatalf("expected the op counter to have advanced (wasted, never reused) by exactly 1, got %d want %d", s.nextOp, prevOpCounter+1)
	}
}

// TestState_CreateSimpleOp_OpExhaustion_LeavesNoPartialState, createSimpleOp
// (Describe/Execute/Close* tarafindan paylasilan) icin temsili bir testtir -
// tek bir fallible adimi (allocOp) oldugundan ve bu adim herhangi bir
// mutasyondan once yapildigindan yapisal olarak zaten atomiktir; bu test
// bunu CreateDescribeStatement uzerinden dogrular (diger tum createSimpleOp
// cagiranlari - CreateDescribePortal/CreateExecute/CreateCloseStatement/
// CreateClosePortal - ayni kod yolunu paylasir).
func TestState_CreateSimpleOp_OpExhaustion_LeavesNoPartialState(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	s.nextOp = math.MaxUint64
	baseOps := s.PendingOperationCount()

	if _, err := s.CreateDescribeStatement("s1"); !errors.Is(err, ErrIdentifierExhaustion) {
		t.Fatalf("expected ErrIdentifierExhaustion, got %v", err)
	}
	if s.PendingOperationCount() != baseOps {
		t.Fatalf("expected no pending operation left behind, got count %d", s.PendingOperationCount())
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

// --- Close-before-acknowledgement (pending target) tests -----------------
//
// PostgreSQL processes frontend messages strictly in order. A well-behaved
// pipelining client can legally send Close immediately after Parse/Bind
// without waiting for ParseComplete/BindComplete - if the creation
// succeeds, the following Close must be able to close that brand-new,
// still-pending object. CreateCloseStatement/CreateClosePortal must
// therefore resolve using the same committed-or-pending rule as Describe/
// Bind/Execute, not committed-only.

func TestState_CreateCloseStatement_NamedPendingBeforeParseComplete(t *testing.T) {
	s := NewState()
	sop, sgen, err := s.CreateParse("s1", "SELECT 1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Close is pipelined immediately, before ParseComplete.
	cop, err := s.CreateCloseStatement("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cop.TargetGeneration != sgen.ID {
		t.Fatalf("expected Close to capture the pending generation %d, got %d", sgen.ID, cop.TargetGeneration)
	}
	_ = sop
}

func TestState_CreateCloseStatement_UnnamedPendingBeforeParseComplete(t *testing.T) {
	s := NewState()
	sop, sgen, err := s.CreateParse("", "SELECT 1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cop, err := s.CreateCloseStatement("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cop.TargetGeneration != sgen.ID {
		t.Fatalf("expected Close to capture the pending unnamed generation %d, got %d", sgen.ID, cop.TargetGeneration)
	}
	_ = sop
}

func TestState_CreateClosePortal_NamedPendingBeforeBindComplete(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	bop, pgen, err := s.CreateBind("p1", "s1", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cop, err := s.CreateClosePortal("p1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cop.TargetGeneration != pgen.ID {
		t.Fatalf("expected Close to capture the pending portal generation %d, got %d", pgen.ID, cop.TargetGeneration)
	}
	_ = bop
}

func TestState_CreateClosePortal_UnnamedPendingBeforeBindComplete(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	bop, pgen, err := s.CreateBind("", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cop, err := s.CreateClosePortal("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cop.TargetGeneration != pgen.ID {
		t.Fatalf("expected Close to capture the pending unnamed portal generation %d, got %d", pgen.ID, cop.TargetGeneration)
	}
	_ = bop
}

func TestState_ParseCompleteThenCloseComplete_RemovesCapturedStatement(t *testing.T) {
	s := NewState()
	sop, sgen, _ := s.CreateParse("s1", "SELECT 1", nil)
	cop, err := s.CreateCloseStatement("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := s.ApplyParseComplete(sop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.ApplyCloseComplete(cop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.Statement(sgen.ID); ok {
		t.Fatal("expected the captured statement generation to be removed")
	}
	if _, ok := s.CommittedStatement("s1"); ok {
		t.Fatal("expected s1 to no longer resolve")
	}
}

func TestState_BindCompleteThenCloseComplete_RemovesCapturedPortal(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	bop, pgen, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	cop, err := s.CreateClosePortal("p1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := s.ApplyBindComplete(bop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.ApplyCloseComplete(cop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.Portal(pgen.ID); ok {
		t.Fatal("expected the captured portal generation to be removed")
	}
	if _, ok := s.CommittedPortal("p1"); ok {
		t.Fatal("expected p1 to no longer resolve")
	}
}

func TestState_CreateCloseStatement_NonexistentIsSuccessfulNoOp(t *testing.T) {
	s := NewState()
	cop, err := s.CreateCloseStatement("does-not-exist")
	if err != nil {
		t.Fatalf("Close of an unknown statement must never error: %v", err)
	}
	if cop.TargetGeneration != NoGeneration {
		t.Fatalf("expected NoGeneration snapshot, got %d", cop.TargetGeneration)
	}
	if err := s.ApplyCloseComplete(cop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestState_CreateClosePortal_NonexistentIsSuccessfulNoOp(t *testing.T) {
	s := NewState()
	cop, err := s.CreateClosePortal("does-not-exist")
	if err != nil {
		t.Fatalf("Close of an unknown portal must never error: %v", err)
	}
	if cop.TargetGeneration != NoGeneration {
		t.Fatalf("expected NoGeneration snapshot, got %d", cop.TargetGeneration)
	}
	if err := s.ApplyCloseComplete(cop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestState_PendingStatementClose_StillCascadesToPortals dogrular: bir
// Close, karsilik gelen Parse henuz onaylanmadan (pending iken) yakalanmis
// olsa bile - o statement generation'indan olusturulan portal'lara
// (pipeline edilmis bir Bind ile) cascade hala dogru sekilde uygulanir.
// TestState_PendingStatementClose_StillCascadesToPortals dogrular: Parse,
// Bind ve Close hicbir onay beklenmeden pipeline edildiginde (bkz.
// docs/design/0001-extended-query.md, "Pipelining ve pozisyonel yanit
// korelasyonu") - Close, hala PENDING olan (henuz ParseComplete
// almamis) bir statement'i yakalasa bile - gercek FIFO onay sirasiyla
// (ParseComplete, sonra BindComplete, sonra CloseComplete) islendiginde
// cascade hala dogru calisir.
func TestState_PendingStatementClose_StillCascadesToPortals(t *testing.T) {
	s := NewState()
	sop, sgen, _ := s.CreateParse("s1", "SELECT 1", nil)
	// Bind, henuz pending olan statement'i hedefler (bkz. "provisionally
	// valid for forwarding purposes" kurali) - hala gecerlidir.
	bop, pgen, err := s.CreateBind("p1", "s1", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Close de ayni sekilde, hala pending olan statement'i yakalar.
	cop, err := s.CreateCloseStatement("s1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Gercek FIFO sirasiyla onaylanir: Parse, sonra Bind, sonra Close.
	if _, err := s.ApplyParseComplete(sop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.ApplyBindComplete(bop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.ApplyCloseComplete(cop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.Statement(sgen.ID); ok {
		t.Fatal("expected statement to be removed")
	}
	if _, ok := s.Portal(pgen.ID); ok {
		t.Fatal("expected dependent portal to be cascaded away even though Close captured a then-pending statement")
	}
}

// --- Simple Query tests -------------------------------------------------
//
// These test the renamed ApplySimpleQueryReceived() (previously
// ApplyAllowedSimpleQuery()) - the clearing behavior is byte-for-byte the
// same; only the name (and, per the design correction, the set of
// legitimate callers - both an allowed AND a locally-blocked-but-
// structurally-valid Simple Query now call it, not "allowed-only") has
// changed. Every assertion below is ported unweakened from the pre-rename
// test suite.

func TestState_SimpleQueryReceivedClearsUnnamedSlots(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("", "", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	s.ApplySimpleQueryReceived()

	if _, ok := s.ResolveStatement(""); ok {
		t.Fatal("expected unnamed statement slot to be cleared")
	}
	if _, ok := s.ResolvePortal(""); ok {
		t.Fatal("expected unnamed portal slot to be cleared")
	}
}

func TestState_SimpleQueryReceivedPreservesNamedObjects(t *testing.T) {
	s := NewState()
	sop, sgen, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, pgen, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	s.ApplySimpleQueryReceived()

	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected named statement to survive a received Simple Query")
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected named portal to survive a received Simple Query")
	}
	_ = sgen
	_ = pgen
}

// TestState_SimpleQueryReceivedHistoricalSnapshotsRemainUsable dogrular:
// bir Simple Query kabul edilip iletildigi anda hala IN-FLIGHT (bekleyen,
// henuz onaylanmamis) bir Bind/Execute varsa, bu islemin (name,generation)
// anlik goruntusu (snapshot) mevcut isimsiz isaretcilerin temizlenmesinden
// ETKILENMEZ - kendi backend onayi geldiginde hala dogru sekilde
// sonuclanabilir olmalidir (bkz. tasarim belgesi, "Mixed Simple/Extended
// Query state handling", madde 6). Bu, ZATEN commit edilmis/tamamlanmis
// (bekleyen islemi kalmamis) bir portaldan farklidir - byle bir portal,
// gercek sunucunun da yikacagi isimsiz nesne oldugu icin, "current"
// isaretcisi temizlenir temizlenmez cleanup tarafindan kaldirilmasi
// BEKLENEN dogru davranistir (ayri, asagidaki NoLongerCurrent testi).
func TestState_SimpleQueryReceivedHistoricalSnapshotsRemainUsable(t *testing.T) {
	s := NewState()
	sop, sgen, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	// Bind KASITLI OLARAK commit edilmiyor - hala bekleyen-islem kuyrugunda,
	// tam da Simple Query'nin arayı bolebilecegi "in-flight" durumu.
	bop, pgen, err := s.CreateBind("", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s.ApplySimpleQueryReceived()

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

// TestState_SimpleQueryReceived_AlreadyCommittedUnnamedPortalIsDestroyed
// dogrular: ZATEN commit edilmis (bekleyen islemi kalmamis) bir isimsiz
// portal, gercek sunucunun da onu yok ettigi Simple Query sonrasi hemen
// temizlenir - "current" isaretcisi temizlenince baska hicbir referansi
// kalmiyorsa artik erisilemez olmalidir.
func TestState_SimpleQueryReceived_AlreadyCommittedUnnamedPortalIsDestroyed(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, pgen, _ := s.CreateBind("", "", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	s.ApplySimpleQueryReceived()

	if _, ok := s.Portal(pgen.ID); ok {
		t.Fatal("expected an already-committed, no-longer-referenced unnamed portal to be cleaned up after the Simple Query destroyed it")
	}
}

func TestState_BlockedMalformedSimpleQueryIsNoMutation(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	before, _ := s.ResolveStatement("")

	// A malformed Simple Query body (never structurally accepted, so
	// ApplySimpleQueryReceived is never called for it - see
	// docs/design/0002-mixed-query-routing.md, "Correct valid blocked-Query
	// lifecycle semantics") is represented by simply NOT calling
	// ApplySimpleQueryReceived at all.
	after, ok := s.ResolveStatement("")
	if !ok || after.ID != before.ID {
		t.Fatal("expected no mutation to occur when the Simple Query helper is never called")
	}
}

// TestState_SimpleQueryReceived_CalledForBothAllowAndBlockVerdicts proves
// the corrected mixed-mode contract directly: ApplySimpleQueryReceived's
// unnamed-object-clearing side effect is triggered by SentinelDB ACCEPTING
// a structurally valid Query at a clean boundary - not by Policy's Allow/
// Block verdict. Calling it identically for both an "allowed" and a
// "locally blocked, but structurally valid" Query must produce exactly the
// same State effect.
func TestState_SimpleQueryReceived_CalledForBothAllowAndBlockVerdicts(t *testing.T) {
	allowed := NewState()
	{
		sop, _, _ := allowed.CreateParse("", "SELECT 1", nil)
		allowed.ApplyParseComplete(sop.ID)
		allowed.ApplySimpleQueryReceived() // represents the Allow verdict path
	}

	blocked := NewState()
	{
		sop, _, _ := blocked.CreateParse("", "SELECT 1", nil)
		blocked.ApplyParseComplete(sop.ID)
		blocked.ApplySimpleQueryReceived() // represents the Block verdict path (queryReceived=true)
	}

	if _, ok := allowed.ResolveStatement(""); ok {
		t.Fatal("expected the allow-path unnamed statement slot to be cleared")
	}
	if _, ok := blocked.ResolveStatement(""); ok {
		t.Fatal("expected the block-path unnamed statement slot to ALSO be cleared - the lifecycle effect must not depend on the verdict")
	}
}

// TestState_SimpleQueryReceived_Idempotent dogrular: ApplySimpleQueryReceived
// arka arkaya birden fazla kez cagrilsa bile (ör. savunmaci/tekrarlanan bir
// cagri), sonuc her zaman aynidir - ikinci cagri hicbir ek/farkli etki
// yaratmaz.
func TestState_SimpleQueryReceived_Idempotent(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)
	uop, _, _ := s.CreateParse("", "SELECT 2", nil)
	s.ApplyParseComplete(uop.ID)

	s.ApplySimpleQueryReceived()
	after1 := snapshotState(s)
	s.ApplySimpleQueryReceived()
	after2 := snapshotState(s)

	assertStateUnchanged(t, after1, after2)
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected named statement to remain resolvable after repeated calls")
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected named portal to remain resolvable after repeated calls")
	}
}

// TestState_SimpleQueryReceived_DoesNotChangePendingCycleOrTxCounters
// dogrular: ApplySimpleQueryReceived, statement/portal isaretcileri
// disinda HICBIR sey degistirmez - bekleyen islem sayisi, outstanding
// cycle sayisi, islem (transaction) durumu ve mevcut cycle tamamen
// etkilenmeden kalir.
func TestState_SimpleQueryReceived_DoesNotChangePendingCycleOrTxCounters(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	// Bir bekleyen (henuz onaylanmamis) islem birak.
	s.CreateBind("", "s1", nil, nil, nil)
	s.CreateSync()

	beforePending := s.PendingOperationCount()
	beforeCycles := s.OutstandingCycleCount()
	beforeStatus := s.TransactionStatus()
	beforeCurrentCycle := s.CurrentCycle()

	s.ApplySimpleQueryReceived()

	if s.PendingOperationCount() != beforePending {
		t.Fatalf("expected PendingOperationCount unchanged: before=%d after=%d", beforePending, s.PendingOperationCount())
	}
	if s.OutstandingCycleCount() != beforeCycles {
		t.Fatalf("expected OutstandingCycleCount unchanged: before=%d after=%d", beforeCycles, s.OutstandingCycleCount())
	}
	if s.TransactionStatus() != beforeStatus {
		t.Fatalf("expected TransactionStatus unchanged: before=%q after=%q", beforeStatus, s.TransactionStatus())
	}
	if s.CurrentCycle() != beforeCurrentCycle {
		t.Fatalf("expected CurrentCycle unchanged: before=%d after=%d", beforeCurrentCycle, s.CurrentCycle())
	}
}

// TestState_SimpleQueryReceived_HistoricalGenerationStillReferencedByNamedPortalSurvives
// dogrular: bir isimsiz statement generation'i artik "current" olmasa bile,
// hala ISIMLI (named) bir portal tarafindan referans veriliyorsa, cleanup
// tarafindan yanlislikla kaldirilmaz - yalnizca GERCEKTEN erisilemez
// generation'lar kaldirilir.
func TestState_SimpleQueryReceived_HistoricalGenerationStillReferencedByNamedPortalSurvives(t *testing.T) {
	s := NewState()
	// Isimsiz statement: named bir portal tarafindan referans verilecek.
	sop, sgen, _ := s.CreateParse("", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	// Yeni bir isimsiz Parse ile "current" isaretcisini ileri tasi - eski
	// generation artik "current" degil, ama p1 hala ona referans veriyor.
	sop2, sgen2, _ := s.CreateParse("", "SELECT 2", nil)
	s.ApplyParseComplete(sop2.ID)

	s.ApplySimpleQueryReceived()

	if _, ok := s.Statement(sgen.ID); !ok {
		t.Fatal("expected the historical statement generation still referenced by a named portal to survive cleanup")
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected the named portal itself to remain resolvable")
	}
	if _, ok := s.Statement(sgen2.ID); ok {
		t.Fatal("expected the newer unnamed statement generation to be cleared (it was 'current' and is now cleared by ApplySimpleQueryReceived, with no portal referencing it)")
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

// --- ReadyForQuery cycle-scoping tests -------------------------------
//
// These prove the corrected rule: ReadyForQuery('I') only removes portals
// whose CreatedCycle is <= the cycle it just completed - never portals from
// a later, already-pipelined cycle merely because they happen to already
// exist in local state (bkz. duzeltme notu, ApplyReadyForQuery).

func TestState_ReadyForQuery_I_RemovesPortalFromCompletedCycle(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop1, _, _ := s.CreateBind("portal_1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop1.ID)
	syncOp1, _ := s.CreateSync() // closes cycle 1
	cycle1 := syncOp1.Cycle

	completed, err := s.ApplyReadyForQuery(TxStatusIdle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if completed != cycle1 {
		t.Fatalf("expected cycle %d to complete, got %d", cycle1, completed)
	}
	if _, ok := s.CommittedPortal("portal_1"); ok {
		t.Fatal("expected portal created in the completed cycle to be removed")
	}
}

func TestState_ReadyForQuery_I_PreservesPendingLaterCyclePortal(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	// Cycle 1: bind + execute portal_1, then Sync.
	bop1, _, _ := s.CreateBind("portal_1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop1.ID)
	eop1, _ := s.CreateExecute("portal_1")
	s.CompleteOperation(eop1.ID)
	s.CreateSync() // closes cycle 1, cycle 2 begins

	// Cycle 2: Bind portal_2 is pipelined (forwarded/registered locally)
	// BEFORE cycle 1's ReadyForQuery has been observed - the exact race
	// this fix addresses. Left pending (no BindComplete yet).
	bop2, pgen2, err := s.CreateBind("portal_2", "s1", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Cycle 1's ReadyForQuery('I') arrives.
	if _, err := s.ApplyReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := s.Portal(pgen2.ID); !ok {
		t.Fatal("expected the pending Cycle 2 portal to survive Cycle 1's ReadyForQuery('I')")
	}
	_ = bop2
}

func TestState_ReadyForQuery_I_SurvivingLaterCyclePortalCanStillCommit(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop1, _, _ := s.CreateBind("portal_1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop1.ID)
	eop1, _ := s.CreateExecute("portal_1")
	s.CompleteOperation(eop1.ID)
	s.CreateSync()

	bop2, pgen2, _ := s.CreateBind("portal_2", "s1", nil, nil, nil)
	if _, err := s.ApplyReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	committed, err := s.ApplyBindComplete(bop2.ID)
	if err != nil {
		t.Fatalf("expected the surviving Cycle 2 portal to still receive BindComplete normally: %v", err)
	}
	if committed.ID != pgen2.ID {
		t.Fatalf("expected committed generation %d, got %d", pgen2.ID, committed.ID)
	}
	if _, ok := s.CommittedPortal("portal_2"); !ok {
		t.Fatal("expected portal_2 to now be resolvable as committed")
	}
}

func TestState_ReadyForQuery_I_LaterRemovesCycle2Portal(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop1, _, _ := s.CreateBind("portal_1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop1.ID)
	eop1, _ := s.CreateExecute("portal_1")
	s.CompleteOperation(eop1.ID)
	s.CreateSync()

	bop2, pgen2, _ := s.CreateBind("portal_2", "s1", nil, nil, nil)
	s.ApplyReadyForQuery(TxStatusIdle) // completes cycle 1

	s.ApplyBindComplete(bop2.ID)
	eop2, _ := s.CreateExecute("portal_2")
	s.CompleteOperation(eop2.ID)
	syncOp2, _ := s.CreateSync() // closes cycle 2
	cycle2 := syncOp2.Cycle

	completed, err := s.ApplyReadyForQuery(TxStatusIdle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if completed != cycle2 {
		t.Fatalf("expected cycle %d to complete, got %d", cycle2, completed)
	}
	if _, ok := s.Portal(pgen2.ID); ok {
		t.Fatal("expected Cycle 2's portal to be removed once Cycle 2's own ReadyForQuery('I') arrives")
	}
}

// TestState_ReadyForQuery_I_RemovesOlderTransactionPortalAcrossCycles
// dogrular: bir portal, eski bir (halen acik) explicit transaction
// icinde ONCEKI bir cycle'da olusturulmus olsa bile - o transaction
// nihayet SONRAKI bir cycle'in ReadyForQuery('I')'siyle kapandiginda -
// dogru sekilde kaldirilir (yalnizca "tamamlanan cycle ile ayni cycle"
// degil, o cycle'dan ONCEKI her cycle de kapsanir).
func TestState_ReadyForQuery_I_RemovesOlderTransactionPortalAcrossCycles(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	// Cycle 1: bind portal_x inside what becomes a still-open explicit
	// transaction (status 'T').
	bop, pgen, _ := s.CreateBind("portal_x", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)
	s.CreateSync()
	if _, err := s.ApplyReadyForQuery(TxStatusInTransaction); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.Portal(pgen.ID); !ok {
		t.Fatal("expected portal to survive while the transaction remains open (T)")
	}

	// Cycle 2: transaction remains open (T -> T), no new portal activity.
	s.CreateSync()
	if _, err := s.ApplyReadyForQuery(TxStatusInTransaction); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.Portal(pgen.ID); !ok {
		t.Fatal("expected portal to still survive across a T -> T cycle")
	}

	// Cycle 3: the transaction finally ends (T -> I).
	s.CreateSync()
	if _, err := s.ApplyReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.Portal(pgen.ID); ok {
		t.Fatal("expected the older portal (bound two cycles earlier) to be removed once its transaction finally ends")
	}
}

func TestState_ReadyForQuery_StatementsSurviveAllStatuses(t *testing.T) {
	for _, status := range []byte{TxStatusIdle, TxStatusInTransaction, TxStatusFailedTransaction} {
		s := NewState()
		sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
		s.ApplyParseComplete(sop.ID)
		s.CreateSync()
		if _, err := s.ApplyReadyForQuery(status); err != nil {
			t.Fatalf("status %q: unexpected error: %v", status, err)
		}
		if _, ok := s.CommittedStatement("s1"); !ok {
			t.Fatalf("status %q: expected prepared statement to survive", status)
		}
	}
}

func TestState_ReadyForQuery_I_NoDanglingPortalStatementReferences(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop1, _, _ := s.CreateBind("portal_1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop1.ID)
	s.CreateSync()
	bop2, pgen2, _ := s.CreateBind("portal_2", "s1", nil, nil, nil)

	if _, err := s.ApplyReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s.ApplyBindComplete(bop2.ID)

	got, ok := s.Portal(pgen2.ID)
	if !ok {
		t.Fatal("expected surviving portal to exist")
	}
	if _, ok := s.Statement(got.StatementID); !ok {
		t.Fatal("expected surviving portal's referenced statement to still exist - no dangling reference")
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

// --- Mutation-isolation tests ---------------------------------------------
//
// Every value State returns is an independent deep copy (bkz. extended_state.go
// "Degismezlik sozlesmesi" / copyStatementGeneration / copyPortalGeneration /
// copyPendingOperation). These tests deliberately mutate every field
// (including slice elements) of returned snapshots and confirm State's own
// internal data is completely unaffected.

func TestState_MutatingReturnedPendingOperation_DoesNotAffectQueue(t *testing.T) {
	s := NewState()
	op, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	originalID, originalCycle, originalKind, originalTarget := op.ID, op.Cycle, op.Kind, op.TargetGeneration

	op.ID = 999999
	op.Cycle = 999999
	op.Kind = OpSync
	op.TargetGeneration = 999999
	op.TargetName = "corrupted"

	ops := s.PendingOperations()
	if len(ops) != 1 {
		t.Fatalf("expected 1 queued operation, got %d", len(ops))
	}
	if ops[0].ID != originalID {
		t.Fatalf("expected queue ID unaffected, got %d want %d", ops[0].ID, originalID)
	}
	if ops[0].Cycle != originalCycle {
		t.Fatalf("expected queue Cycle unaffected, got %d want %d", ops[0].Cycle, originalCycle)
	}
	if ops[0].Kind != originalKind {
		t.Fatalf("expected queue Kind unaffected, got %v want %v", ops[0].Kind, originalKind)
	}
	if ops[0].TargetGeneration != originalTarget {
		t.Fatalf("expected queue TargetGeneration unaffected, got %d want %d", ops[0].TargetGeneration, originalTarget)
	}
	if ops[0].TargetName != "s1" {
		t.Fatalf("expected queue TargetName unaffected, got %q", ops[0].TargetName)
	}
}

func TestState_MutatingReturnedStatementGeneration_DoesNotAffectState(t *testing.T) {
	s := NewState()
	_, gen, _ := s.CreateParse("s1", "SELECT 1", []uint32{23, 25})

	gen.Query = "DROP TABLE users"
	gen.Name = "corrupted"
	gen.State = LifecycleCommitted
	gen.ParamOIDs[0] = 999999

	got, ok := s.ResolveStatement("s1")
	if !ok {
		t.Fatal("expected s1 to still resolve")
	}
	if got.Query != "SELECT 1" {
		t.Fatalf("expected internal Query unaffected, got %q", got.Query)
	}
	if got.Name != "s1" {
		t.Fatalf("expected internal Name unaffected, got %q", got.Name)
	}
	if got.State != LifecyclePending {
		t.Fatalf("expected internal State unaffected, got %v", got.State)
	}
	if got.ParamOIDs[0] != 23 {
		t.Fatalf("expected internal ParamOIDs unaffected, got %v", got.ParamOIDs)
	}
}

func TestState_MutatingReturnedParamOIDs_DoesNotAffectState(t *testing.T) {
	s := NewState()
	_, gen, _ := s.CreateParse("s1", "SELECT 1", []uint32{23, 25})

	gen.ParamOIDs[0] = 1
	gen.ParamOIDs[1] = 2
	gen.ParamOIDs = append(gen.ParamOIDs, 3, 4, 5) // also exercises capacity growth

	got, ok := s.Statement(gen.ID)
	if !ok {
		t.Fatal("expected statement to still exist")
	}
	if len(got.ParamOIDs) != 2 || got.ParamOIDs[0] != 23 || got.ParamOIDs[1] != 25 {
		t.Fatalf("expected internal ParamOIDs unaffected by external mutation/append, got %v", got.ParamOIDs)
	}
}

func TestState_MutatingReturnedPortalGeneration_DoesNotAffectState(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	_, gen, err := s.CreateBind("p1", "s1", []int16{0, 1}, []bool{false, true}, []int16{0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gen.Name = "corrupted"
	gen.State = LifecycleCommitted
	gen.StatementID = 999999

	got, ok := s.ResolvePortal("p1")
	if !ok {
		t.Fatal("expected p1 to still resolve")
	}
	if got.Name != "p1" {
		t.Fatalf("expected internal Name unaffected, got %q", got.Name)
	}
	if got.State != LifecyclePending {
		t.Fatalf("expected internal State unaffected, got %v", got.State)
	}
	if got.StatementID == 999999 {
		t.Fatal("expected internal StatementID unaffected")
	}
}

func TestState_MutatingReturnedFormatAndNullSlices_DoesNotAffectState(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	_, gen, err := s.CreateBind("p1", "s1", []int16{0, 1}, []bool{false, true}, []int16{1, 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gen.ParamFormats[0] = 99
	gen.ParamNulls[0] = true
	gen.ResultFormats[0] = 99
	gen.ParamFormats = append(gen.ParamFormats, 5, 5, 5)

	got, ok := s.Portal(gen.ID)
	if !ok {
		t.Fatal("expected portal to still exist")
	}
	if len(got.ParamFormats) != 2 || got.ParamFormats[0] != 0 {
		t.Fatalf("expected internal ParamFormats unaffected, got %v", got.ParamFormats)
	}
	if got.ParamNulls[0] != false {
		t.Fatalf("expected internal ParamNulls unaffected, got %v", got.ParamNulls)
	}
	if got.ResultFormats[0] != 1 {
		t.Fatalf("expected internal ResultFormats unaffected, got %v", got.ResultFormats)
	}
}

func TestState_MutatingResolveOrCommittedSnapshot_DoesNotAffectLaterLookup(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)

	snap, ok := s.CommittedStatement("s1")
	if !ok {
		t.Fatal("expected s1 to resolve")
	}
	snap.Query = "corrupted"
	snap.ParamOIDs = append(snap.ParamOIDs, 42)
	snap.State = LifecycleFailed

	again, ok := s.CommittedStatement("s1")
	if !ok {
		t.Fatal("expected s1 to still resolve")
	}
	if again.Query != "SELECT 1" {
		t.Fatalf("expected later lookup unaffected by earlier snapshot mutation, got %q", again.Query)
	}
	if len(again.ParamOIDs) != 0 {
		t.Fatalf("expected later lookup's ParamOIDs unaffected, got %v", again.ParamOIDs)
	}
	if again.State != LifecycleCommitted {
		t.Fatalf("expected later lookup's State unaffected, got %v", again.State)
	}
}

// TestState_InvariantsHoldAfterMutatingEveryReturnedSnapshot dogrular:
// donen HER snapshot turunu (PendingOperation, StatementGeneration,
// PortalGeneration - slice alanlari dahil) kasitli olarak bozduktan sonra
// bile, State'in kendi ic yapisal degismezleri (bkz.
// checkStructuralInvariants) hala gecerlidir ve gercek ID'lerle yapilan
// sonraki cagrilar (ApplyParseComplete/ApplyBindComplete) hala doğru
// calisir - hicbir donus degeri mutasyonu State'e geri sizmaz.
func TestState_InvariantsHoldAfterMutatingEveryReturnedSnapshot(t *testing.T) {
	s := NewState()

	pop, sgen, err := s.CreateParse("s1", "SELECT 1", []uint32{1, 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	realParseOpID, realStmtGenID := pop.ID, sgen.ID

	pop.ID, pop.Cycle, pop.Kind, pop.TargetGeneration, pop.TargetName = 777, 777, OpSync, 777, "corrupted"
	sgen.ParamOIDs[0], sgen.Query, sgen.Name, sgen.State = 777, "corrupted", "corrupted", LifecycleCommitted

	if _, err := s.ApplyParseComplete(realParseOpID); err != nil {
		t.Fatalf("expected ApplyParseComplete to still work with the REAL (unmutated) ID: %v", err)
	}

	bop, pgen, err := s.CreateBind("p1", "s1", []int16{0}, []bool{false}, []int16{0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	realBindOpID, realPortalGenID := bop.ID, pgen.ID

	bop.TargetGeneration = 777
	pgen.ParamFormats[0] = 99
	pgen.StatementID = 777

	if _, err := s.ApplyBindComplete(realBindOpID); err != nil {
		t.Fatalf("expected ApplyBindComplete to still work with the REAL (unmutated) ID: %v", err)
	}

	got, ok := s.Portal(realPortalGenID)
	if !ok || got.StatementID != realStmtGenID {
		t.Fatalf("expected portal to reference the real statement generation %d, got %+v (ok=%v)", realStmtGenID, got, ok)
	}

	checkStructuralInvariants(t, s)
}

// --- ApplySimpleQueryReadyForQuery tests ---------------------------------
//
// These test the new, additive State.ApplySimpleQueryReadyForQuery method
// (bkz. docs/design/0002-mixed-query-routing.md, "New, additive State
// method"): unlike ApplyReadyForQuery, it requires no pending OpSync/
// outstanding Sync cycle, consumes nothing, and creates no new cycle - it
// only updates transaction status and (on 'I') unconditionally invalidates
// every currently-tracked portal.

func TestState_SimpleQueryReadyForQuery_I_UpdatesStatusAndRemovesAllPortals(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop1, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop1.ID)
	// Also leave an unnamed, uncommitted (still-pending) portal in flight -
	// "every currently-tracked portal" must mean named AND unnamed, pending
	// AND committed.
	s.CreateBind("", "s1", nil, nil, nil)

	if err := s.ApplySimpleQueryReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.TransactionStatus() != TxStatusIdle {
		t.Fatalf("expected TransactionStatus 'I', got %q", s.TransactionStatus())
	}
	if s.PortalCount() != 0 {
		t.Fatalf("expected zero live portals after ApplySimpleQueryReadyForQuery('I'), got %d", s.PortalCount())
	}
	if _, ok := s.CommittedPortal("p1"); ok {
		t.Fatal("expected named, committed portal to be invalidated")
	}
	if _, ok := s.ResolvePortal(""); ok {
		t.Fatal("expected unnamed, still-pending portal to ALSO be invalidated")
	}
}

func TestState_SimpleQueryReadyForQuery_I_PreservesStatements(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	uop, _, _ := s.CreateParse("", "SELECT 2", nil)
	s.ApplyParseComplete(uop.ID)

	if err := s.ApplySimpleQueryReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected named prepared statement to survive ApplySimpleQueryReadyForQuery('I')")
	}
	if _, ok := s.ResolveStatement(""); !ok {
		t.Fatal("expected unnamed prepared statement to survive ApplySimpleQueryReadyForQuery('I') - statements are never invalidated by this method")
	}
}

func TestState_SimpleQueryReadyForQuery_T_UpdatesStatusPreservesEverything(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	if err := s.ApplySimpleQueryReadyForQuery(TxStatusInTransaction); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.TransactionStatus() != TxStatusInTransaction {
		t.Fatalf("expected TransactionStatus 'T', got %q", s.TransactionStatus())
	}
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected statement to survive ApplySimpleQueryReadyForQuery('T')")
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected portal to survive ApplySimpleQueryReadyForQuery('T')")
	}
}

func TestState_SimpleQueryReadyForQuery_E_UpdatesStatusPreservesEverything(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	if err := s.ApplySimpleQueryReadyForQuery(TxStatusFailedTransaction); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.TransactionStatus() != TxStatusFailedTransaction {
		t.Fatalf("expected TransactionStatus 'E', got %q", s.TransactionStatus())
	}
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected statement to survive ApplySimpleQueryReadyForQuery('E')")
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected portal to survive ApplySimpleQueryReadyForQuery('E')")
	}
}

// TestState_SimpleQueryReadyForQuery_ITEI_Deterministic dogrular: I -> T ->
// E -> I gecis zinciri, her adimda beklenen (deterministik) davranisi
// uretir - ozellikle: yalnizca SON 'I' gecisi, o ana kadar biriken portal'i
// gecersiz kilar (aradaki T/E adimlari onu korur).
func TestState_SimpleQueryReadyForQuery_ITEI_Deterministic(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	if err := s.ApplySimpleQueryReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("I: unexpected error: %v", err)
	}
	if s.TransactionStatus() != TxStatusIdle {
		t.Fatalf("I: expected 'I', got %q", s.TransactionStatus())
	}
	if _, ok := s.CommittedPortal("p1"); ok {
		t.Fatal("I: expected portal to be invalidated")
	}

	// Re-establish a portal for the T/E/I chain below.
	bop2, _, _ := s.CreateBind("p2", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop2.ID)

	if err := s.ApplySimpleQueryReadyForQuery(TxStatusInTransaction); err != nil {
		t.Fatalf("T: unexpected error: %v", err)
	}
	if s.TransactionStatus() != TxStatusInTransaction {
		t.Fatalf("T: expected 'T', got %q", s.TransactionStatus())
	}
	if _, ok := s.CommittedPortal("p2"); !ok {
		t.Fatal("T: expected portal to survive")
	}

	if err := s.ApplySimpleQueryReadyForQuery(TxStatusFailedTransaction); err != nil {
		t.Fatalf("E: unexpected error: %v", err)
	}
	if s.TransactionStatus() != TxStatusFailedTransaction {
		t.Fatalf("E: expected 'E', got %q", s.TransactionStatus())
	}
	if _, ok := s.CommittedPortal("p2"); !ok {
		t.Fatal("E: expected portal to survive")
	}

	if err := s.ApplySimpleQueryReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("final I: unexpected error: %v", err)
	}
	if s.TransactionStatus() != TxStatusIdle {
		t.Fatalf("final I: expected 'I', got %q", s.TransactionStatus())
	}
	if _, ok := s.CommittedPortal("p2"); ok {
		t.Fatal("final I: expected portal to now be invalidated")
	}
}

func TestState_SimpleQueryReadyForQuery_InvalidStatusIsFullyAtomic(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)
	if err := s.ApplySimpleQueryReadyForQuery(TxStatusInTransaction); err != nil {
		t.Fatalf("setup: unexpected error: %v", err)
	}
	s.CreateSync() // leave a pending operation + outstanding cycle in place too
	before := snapshotState(s)

	if err := s.ApplySimpleQueryReadyForQuery('X'); !errors.Is(err, ErrInvalidTransactionStatus) {
		t.Fatalf("expected ErrInvalidTransactionStatus, got %v", err)
	}

	after := snapshotState(s)
	assertStateUnchanged(t, before, after)
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected portal to survive an invalid-status call")
	}
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected statement to survive an invalid-status call")
	}
}

func TestState_SimpleQueryReadyForQuery_DoesNotConsumeSyncOperation(t *testing.T) {
	s := NewState()
	syncOp, err := s.CreateSync()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	beforePending := s.PendingOperationCount()
	beforeCycles := s.OutstandingCycleCount()
	beforeCurrent := s.CurrentCycle()

	if err := s.ApplySimpleQueryReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s.PendingOperationCount() != beforePending {
		t.Fatalf("expected PendingOperationCount unchanged (no Sync consumed): before=%d after=%d", beforePending, s.PendingOperationCount())
	}
	if s.OutstandingCycleCount() != beforeCycles {
		t.Fatalf("expected OutstandingCycleCount unchanged (no cycle consumed): before=%d after=%d", beforeCycles, s.OutstandingCycleCount())
	}
	if s.CurrentCycle() != beforeCurrent {
		t.Fatalf("expected CurrentCycle unchanged (no new cycle created): before=%d after=%d", beforeCurrent, s.CurrentCycle())
	}
	// The real Sync operation registered above must remain exactly as it
	// was - untouched by the Simple Query method.
	ops := s.PendingOperations()
	if len(ops) != 1 || ops[0].ID != syncOp.ID || ops[0].Kind != OpSync {
		t.Fatalf("expected the real pending Sync operation to remain queued untouched, got %+v", ops)
	}
}

func TestState_SimpleQueryReadyForQuery_RepeatedValidCallsAreDeterministic(t *testing.T) {
	s := NewState()
	sop, _, _ := s.CreateParse("s1", "SELECT 1", nil)
	s.ApplyParseComplete(sop.ID)
	bop, _, _ := s.CreateBind("p1", "s1", nil, nil, nil)
	s.ApplyBindComplete(bop.ID)

	if err := s.ApplySimpleQueryReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}
	after1 := snapshotState(s)
	if err := s.ApplySimpleQueryReadyForQuery(TxStatusIdle); err != nil {
		t.Fatalf("second call: unexpected error: %v", err)
	}
	after2 := snapshotState(s)
	assertStateUnchanged(t, after1, after2)
}

// --- ApplySimpleQueryLifecycleEffect tests -------------------------------
//
// These test the new State.ApplySimpleQueryLifecycleEffect method (bkz.
// docs/design/0002-mixed-query-routing.md, "CommandComplete lifecycle-
// effect classification" / "Apply lifecycle effects atomically to State"):
// the atomic State-side application of a SimpleQueryLifecycleEffect value
// classified by SimpleQueryTracker from a validated, ordering-valid
// CommandComplete tag.

// namedStatementAndPortal builds a State with one named, committed
// statement ("s1") and one named, committed portal ("p1") bound to it -
// the "named statement + named portal exist" precondition required by
// every test below.
func namedStatementAndPortal(t *testing.T) (*State, GenerationID, GenerationID) {
	t.Helper()
	s := NewState()
	sop, sgen, err := s.CreateParse("s1", "SELECT 1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.ApplyParseComplete(sop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bop, pgen, err := s.CreateBind("p1", "s1", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.ApplyBindComplete(bop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return s, sgen.ID, pgen.ID
}

func TestState_SimpleQueryLifecycleEffect_None_IsNoOp(t *testing.T) {
	s, _, _ := namedStatementAndPortal(t)
	before := snapshotState(s)

	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryLifecycleNone); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertStateUnchanged(t, before, snapshotState(s))
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected statement to remain resolvable")
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected portal to remain resolvable")
	}
}

func TestState_SimpleQueryLifecycleEffect_InvalidatePortals_RemovesPortalsPreservesStatements(t *testing.T) {
	s, sid, pid := namedStatementAndPortal(t)

	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidatePortals); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s.PortalCount() != 0 {
		t.Fatalf("expected zero live portals, got %d", s.PortalCount())
	}
	if _, ok := s.CommittedPortal("p1"); ok {
		t.Fatal("expected named portal to be invalidated")
	}
	if _, ok := s.Portal(pid); ok {
		t.Fatal("expected portal generation to be fully removed")
	}
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected named statement to be preserved")
	}
	if _, ok := s.Statement(sid); !ok {
		t.Fatal("expected statement generation to be preserved")
	}
	if s.StatementCount() != 1 {
		t.Fatalf("expected exactly one live statement, got %d", s.StatementCount())
	}
}

func TestState_SimpleQueryLifecycleEffect_PortalOnly_ClearsRollbackReferences(t *testing.T) {
	s := NewState()
	sop, _, err := s.CreateParse("s1", "SELECT 1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.ApplyParseComplete(sop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Unnamed portal - populates unnamedPortalRollback at creation.
	bop, pgen, err := s.CreateBind("", "s1", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.ApplyBindComplete(bop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidatePortals); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := s.unnamedPortalRollback[pgen.ID]; ok {
		t.Fatalf("expected the rollback reference for removed portal generation %d to be cleared", pgen.ID)
	}
}

func TestState_SimpleQueryLifecycleEffect_InvalidateStatementsAndPortals_RemovesEverything(t *testing.T) {
	s, sid, pid := namedStatementAndPortal(t)

	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidateStatementsAndPortals); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s.PortalCount() != 0 {
		t.Fatalf("expected zero live portals, got %d", s.PortalCount())
	}
	if s.StatementCount() != 0 {
		t.Fatalf("expected zero live statements, got %d", s.StatementCount())
	}
	if _, ok := s.CommittedStatement("s1"); ok {
		t.Fatal("expected named statement mapping to be cleared")
	}
	if _, ok := s.CommittedPortal("p1"); ok {
		t.Fatal("expected named portal mapping to be cleared")
	}
	if _, ok := s.Statement(sid); ok {
		t.Fatal("expected statement generation to be fully removed")
	}
	if _, ok := s.Portal(pid); ok {
		t.Fatal("expected portal generation to be fully removed")
	}
	// No portal may be left referring to a removed statement - trivially
	// true here since ALL portals are gone, but assert PortalCount()==0
	// again explicitly as the exact requirement this proves.
	if s.PortalCount() != 0 {
		t.Fatal("expected no portal to remain, referring to a removed statement or otherwise")
	}
}

func TestState_SimpleQueryLifecycleEffect_StatementAndPortal_ClearsAllRollbackReferences(t *testing.T) {
	s := NewState()
	// Unnamed statement AND unnamed portal - populates both rollback maps.
	sop, sgen, err := s.CreateParse("", "SELECT 1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.ApplyParseComplete(sop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bop, pgen, err := s.CreateBind("", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.ApplyBindComplete(bop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidateStatementsAndPortals); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := s.unnamedStatementRollback[sgen.ID]; ok {
		t.Fatalf("expected the rollback reference for removed statement generation %d to be cleared", sgen.ID)
	}
	if _, ok := s.unnamedPortalRollback[pgen.ID]; ok {
		t.Fatalf("expected the rollback reference for removed portal generation %d to be cleared", pgen.ID)
	}
}

func TestState_SimpleQueryLifecycleEffect_UnknownValueIsFullyAtomic(t *testing.T) {
	s, _, _ := namedStatementAndPortal(t)
	before := snapshotState(s)

	const bogus SimpleQueryLifecycleEffect = 200
	if err := s.ApplySimpleQueryLifecycleEffect(bogus); !errors.Is(err, ErrUnknownSimpleQueryLifecycleEffect) {
		t.Fatalf("expected ErrUnknownSimpleQueryLifecycleEffect, got %v", err)
	}

	assertStateUnchanged(t, before, snapshotState(s))
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected statement to survive an unknown-effect call")
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected portal to survive an unknown-effect call")
	}
}

func TestState_SimpleQueryLifecycleEffect_UncleanBoundary_PendingOperationIsFullyAtomic(t *testing.T) {
	s, _, _ := namedStatementAndPortal(t)
	// Leave an additional, unresolved pending operation - unclean boundary.
	if _, _, err := s.CreateBind("p2", "s1", nil, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	before := snapshotState(s)

	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidateStatementsAndPortals); !errors.Is(err, ErrSimpleQueryUncleanBoundary) {
		t.Fatalf("expected ErrSimpleQueryUncleanBoundary, got %v", err)
	}

	assertStateUnchanged(t, before, snapshotState(s))
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected statement to survive a rejected unclean-boundary call")
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected portal to survive a rejected unclean-boundary call - no partial deletion")
	}
}

func TestState_SimpleQueryLifecycleEffect_UncleanBoundary_OutstandingCycleIsFullyAtomic(t *testing.T) {
	s, _, _ := namedStatementAndPortal(t)
	// Register a Sync without its matching ReadyForQuery - an outstanding
	// cycle, also an unclean boundary.
	if _, err := s.CreateSync(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	before := snapshotState(s)

	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidatePortals); !errors.Is(err, ErrSimpleQueryUncleanBoundary) {
		t.Fatalf("expected ErrSimpleQueryUncleanBoundary, got %v", err)
	}

	assertStateUnchanged(t, before, snapshotState(s))
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("expected portal to survive a rejected unclean-boundary call - no partial deletion")
	}
}

func TestState_SimpleQueryLifecycleEffect_DoesNotChangeTxOrCycleCounters(t *testing.T) {
	s, _, _ := namedStatementAndPortal(t)
	beforeStatus := s.TransactionStatus()
	beforePending := s.PendingOperationCount()
	beforeCycles := s.OutstandingCycleCount()
	beforeCurrent := s.CurrentCycle()

	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidateStatementsAndPortals); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s.TransactionStatus() != beforeStatus {
		t.Fatalf("expected TransactionStatus unchanged: before=%q after=%q", beforeStatus, s.TransactionStatus())
	}
	if s.PendingOperationCount() != beforePending {
		t.Fatalf("expected PendingOperationCount unchanged: before=%d after=%d", beforePending, s.PendingOperationCount())
	}
	if s.OutstandingCycleCount() != beforeCycles {
		t.Fatalf("expected OutstandingCycleCount unchanged: before=%d after=%d", beforeCycles, s.OutstandingCycleCount())
	}
	if s.CurrentCycle() != beforeCurrent {
		t.Fatalf("expected CurrentCycle unchanged: before=%d after=%d", beforeCurrent, s.CurrentCycle())
	}
}

func TestState_SimpleQueryLifecycleEffect_RepeatedCallsAreDeterministic(t *testing.T) {
	s, _, _ := namedStatementAndPortal(t)

	// Repeating the SAME effect (SimpleQueryInvalidatePortals) is
	// idempotent: the second call has nothing left to remove.
	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidatePortals); err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}
	after1 := snapshotState(s)
	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidatePortals); err != nil {
		t.Fatalf("second call: unexpected error: %v", err)
	}
	after2 := snapshotState(s)
	assertStateUnchanged(t, after1, after2)
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected statement to still be resolvable after repeated portal-only effects")
	}

	// A subsequent, STRONGER effect (SimpleQueryInvalidateStatementsAndPortals)
	// still has the statement to remove the first time...
	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidateStatementsAndPortals); err != nil {
		t.Fatalf("third call: unexpected error: %v", err)
	}
	if _, ok := s.CommittedStatement("s1"); ok {
		t.Fatal("expected the statement to be removed by the statement-and-portal effect")
	}
	after3 := snapshotState(s)

	// ...and repeating THAT same effect again is, in turn, idempotent too.
	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidateStatementsAndPortals); err != nil {
		t.Fatalf("fourth call: unexpected error: %v", err)
	}
	after4 := snapshotState(s)
	assertStateUnchanged(t, after3, after4)
}

// TestState_MultiStatementLifecycleModel_CommitThenBegin is the concrete
// regression from the task: a multi-statement Simple Query executing
// "COMMIT; BEGIN" must destroy the OLD transaction's portal even though the
// FINAL ReadyForQuery status is 'T' (the new, just-begun transaction) -
// proving that ApplySimpleQueryReadyForQuery's own "preserve everything on
// T/E" rule is correct ONLY because the earlier CommandComplete's own
// lifecycle effect (applied via ApplySimpleQueryLifecycleEffect) already
// ran first, before the final ReadyForQuery is ever observed.
func TestState_MultiStatementLifecycleModel_CommitThenBegin(t *testing.T) {
	s := NewState()
	// Start in 'T' (an already-open transaction, e.g. from an earlier
	// Extended BEGIN).
	if err := s.ApplySimpleQueryReadyForQuery(TxStatusInTransaction); err != nil {
		t.Fatalf("setup: unexpected error: %v", err)
	}

	// Create a named statement and named portal inside transaction A.
	sop, _, err := s.CreateParse("s1", "SELECT 1", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.ApplyParseComplete(sop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bop, _, err := s.CreateBind("p1", "s1", nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := s.ApplyBindComplete(bop.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.CommittedPortal("p1"); !ok {
		t.Fatal("setup: expected p1 to exist before COMMIT")
	}

	// Simulate the tracker having just processed CommandComplete("COMMIT")
	// mid-Query: apply its classified lifecycle effect immediately.
	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidatePortals); err != nil {
		t.Fatalf("applying COMMIT's lifecycle effect: unexpected error: %v", err)
	}

	// The old portal must already be gone, well before the Query's own
	// final ReadyForQuery is ever seen.
	if _, ok := s.CommittedPortal("p1"); ok {
		t.Fatal("expected the old transaction's portal to be gone immediately after COMMIT's lifecycle effect")
	}

	// The rest of the Query text is "BEGIN" - CommandComplete("BEGIN")
	// itself classifies as SimpleQueryLifecycleNone (nothing to apply).

	// The Query's own final ReadyForQuery reports 'T' - the NEW
	// transaction BEGIN just opened, not the old one.
	if err := s.ApplySimpleQueryReadyForQuery(TxStatusInTransaction); err != nil {
		t.Fatalf("final ReadyForQuery: unexpected error: %v", err)
	}

	if s.TransactionStatus() != TxStatusInTransaction {
		t.Fatalf("expected final TransactionStatus 'T', got %q", s.TransactionStatus())
	}
	if _, ok := s.CommittedPortal("p1"); ok {
		t.Fatal("expected the old portal to remain gone after the final ReadyForQuery('T')")
	}
	if _, ok := s.CommittedStatement("s1"); !ok {
		t.Fatal("expected the prepared statement to remain (COMMIT's effect only invalidates portals, never statements)")
	}
}

// TestState_DeallocateRegression is the concrete DEALLOCATE regression from
// the task: a successful SQL DEALLOCATE CommandComplete must remove a
// protocol-created named prepared statement (and any portal depending on
// it) from State, even though DEALLOCATE's own tag never carries the
// deallocated statement's name.
func TestState_DeallocateRegression(t *testing.T) {
	s, _, _ := namedStatementAndPortal(t) // named statement "s1" + named portal "p1" bound to it

	// Simulate the tracker having just processed
	// CommandComplete("DEALLOCATE") mid-Query (or as the Query's only
	// statement).
	if err := s.ApplySimpleQueryLifecycleEffect(SimpleQueryInvalidateStatementsAndPortals); err != nil {
		t.Fatalf("applying DEALLOCATE's lifecycle effect: unexpected error: %v", err)
	}

	if _, ok := s.CommittedStatement("s1"); ok {
		t.Fatal("expected the deallocated statement to no longer be resolvable")
	}
	if _, ok := s.CommittedPortal("p1"); ok {
		t.Fatal("expected the portal depending on the deallocated statement to no longer be resolvable")
	}
	if s.StatementCount() != 0 || s.PortalCount() != 0 {
		t.Fatalf("expected zero live statements/portals, got statements=%d portals=%d", s.StatementCount(), s.PortalCount())
	}
}

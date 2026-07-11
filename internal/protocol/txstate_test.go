package protocol

import (
	"sync"
	"testing"
)

func TestTxState_DefaultsToIdle(t *testing.T) {
	s := NewTxState()
	if got := s.Get(); got != TxStatusIdle {
		t.Fatalf("expected default status %q, got %q", TxStatusIdle, got)
	}
}

func TestTxState_SetAndGet(t *testing.T) {
	s := NewTxState()
	s.Set(TxStatusInTransaction)
	if got := s.Get(); got != TxStatusInTransaction {
		t.Fatalf("expected %q, got %q", TxStatusInTransaction, got)
	}
	s.Set(TxStatusFailedTransaction)
	if got := s.Get(); got != TxStatusFailedTransaction {
		t.Fatalf("expected %q, got %q", TxStatusFailedTransaction, got)
	}
	s.Set(TxStatusIdle)
	if got := s.Get(); got != TxStatusIdle {
		t.Fatalf("expected %q, got %q", TxStatusIdle, got)
	}
}

func TestTxState_ConcurrentAccessIsSafe(t *testing.T) {
	s := NewTxState()
	var wg sync.WaitGroup
	statuses := []byte{TxStatusIdle, TxStatusInTransaction, TxStatusFailedTransaction}

	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			s.Set(statuses[i%len(statuses)])
		}(i)
		go func() {
			defer wg.Done()
			_ = s.Get()
		}()
	}
	wg.Wait()

	got := s.Get()
	valid := got == TxStatusIdle || got == TxStatusInTransaction || got == TxStatusFailedTransaction
	if !valid {
		t.Fatalf("expected a valid status byte after concurrent access, got %q", got)
	}
}

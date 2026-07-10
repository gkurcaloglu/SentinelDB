package wasm

import (
	"context"
	"errors"
	"testing"

	"github.com/gkurcaloglu/sentineldb/internal/firewall"
	"github.com/gkurcaloglu/sentineldb/internal/protocol"
	"github.com/gkurcaloglu/sentineldb/internal/wasmproto"
)

// fakeEvaluator, gerçek bir Wasm eklentisi derlemeden Policy'nin
// evaluator ile nasıl etkileşime girdiğini (parametreler, hata durumu)
// izole şekilde test etmeyi sağlar. Gerçek Runtime'a karşı uçtan uca
// testler runtime_test.go'dadır.
type fakeEvaluator struct {
	verdict, reason string
	err             error

	calls      int
	gotQuery   string
	gotPhrases []string
}

func (f *fakeEvaluator) Evaluate(ctx context.Context, query string, blockedPhrases []string) (string, string, error) {
	f.calls++
	f.gotQuery = query
	f.gotPhrases = blockedPhrases
	return f.verdict, f.reason, f.err
}

func TestPolicy_IgnoresNonQueryMessages(t *testing.T) {
	fe := &fakeEvaluator{}
	p := &Policy{rt: fe, blockedPhrases: []string{"DROP TABLE"}}

	v, reason := p.Evaluate(protocol.Message{Type: protocol.MsgParse, Query: "DROP TABLE users;"})

	if v != firewall.Allow || reason != "" {
		t.Fatalf("expected (Allow, \"\"), got (%v, %q)", v, reason)
	}
	if fe.calls != 0 {
		t.Fatalf("expected evaluator to never be called for non-Query messages, got %d calls", fe.calls)
	}
}

func TestPolicy_ForwardsQueryAndPhrasesToEvaluator(t *testing.T) {
	fe := &fakeEvaluator{verdict: wasmproto.VerdictAllow}
	phrases := []string{"DROP TABLE", "DELETE FROM"}
	p := &Policy{rt: fe, blockedPhrases: phrases}

	v, _ := p.Evaluate(protocol.Message{Type: protocol.MsgQuery, Query: "SELECT 1;"})

	if v != firewall.Allow {
		t.Fatalf("expected Allow, got %v", v)
	}
	if fe.calls != 1 {
		t.Fatalf("expected exactly 1 evaluator call, got %d", fe.calls)
	}
	if fe.gotQuery != "SELECT 1;" {
		t.Errorf("expected query %q forwarded, got %q", "SELECT 1;", fe.gotQuery)
	}
	if len(fe.gotPhrases) != 2 || fe.gotPhrases[0] != "DROP TABLE" {
		t.Errorf("expected blocked phrases forwarded unchanged, got %v", fe.gotPhrases)
	}
}

func TestPolicy_TranslatesBlockVerdict(t *testing.T) {
	fe := &fakeEvaluator{verdict: wasmproto.VerdictBlock, reason: "wasm dedi ki hayir"}
	p := &Policy{rt: fe, blockedPhrases: nil}

	v, reason := p.Evaluate(protocol.Message{Type: protocol.MsgQuery, Query: "DROP TABLE users;"})

	if v != firewall.Block {
		t.Fatalf("expected Block, got %v", v)
	}
	if reason != "wasm dedi ki hayir" {
		t.Errorf("expected the plugin's reason to be forwarded verbatim, got %q", reason)
	}
}

func TestPolicy_FailsClosedOnEvaluatorError(t *testing.T) {
	fe := &fakeEvaluator{err: errors.New("wasm cöktü")}
	var loggedErr error
	p := &Policy{
		rt:             fe,
		blockedPhrases: nil,
		onError:        func(err error) { loggedErr = err },
	}

	v, reason := p.Evaluate(protocol.Message{Type: protocol.MsgQuery, Query: "SELECT 1;"})

	if v != firewall.Block {
		t.Fatalf("expected fail-closed Block on evaluator error, got %v", v)
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason when failing closed")
	}
	if loggedErr == nil {
		t.Fatal("expected onError to be called with the underlying error")
	}
}

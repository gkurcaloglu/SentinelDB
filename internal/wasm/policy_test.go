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

func TestPolicy_IgnoresNonQueryNonParseMessages(t *testing.T) {
	fe := &fakeEvaluator{}
	p := &Policy{rt: fe, blockedPhrases: []string{"DROP TABLE"}}

	for _, typ := range []protocol.MessageType{protocol.MsgBind, protocol.MsgDescribe, protocol.MsgExecute, protocol.MsgClose, protocol.MsgFlush, protocol.MsgSync} {
		v, reason := p.Evaluate(protocol.Message{Type: typ, Query: "DROP TABLE users;"})
		if v != firewall.Allow || reason != "" {
			t.Fatalf("type %v: expected (Allow, \"\"), got (%v, %q)", typ, v, reason)
		}
	}
	if fe.calls != 0 {
		t.Fatalf("expected evaluator to never be called for non-Query/non-Parse messages, got %d calls", fe.calls)
	}
}

func TestPolicy_TreatsExtendedParseLikeSimpleQuery(t *testing.T) {
	// bkz. gorev 8: MsgParse SQL sablonunu tasir - Wasm ABI'sine yalnizca
	// m.Query gectigi icin (m.Type asla sinir gecmez), bu davranis
	// eklenti tarafinda HICBIR degisiklik gerektirmez.
	fe := &fakeEvaluator{verdict: wasmproto.VerdictBlock, reason: "blocked"}
	p := &Policy{rt: fe, blockedPhrases: []string{"DROP TABLE"}}

	v, reason := p.Evaluate(protocol.Message{Type: protocol.MsgParse, Name: "Parse", Query: "DROP TABLE users;"})

	if v != firewall.Block || reason != "blocked" {
		t.Fatalf("expected (Block, \"blocked\"), got (%v, %q)", v, reason)
	}
	if fe.calls != 1 {
		t.Fatalf("expected evaluator to be called exactly once for a Parse message, got %d calls", fe.calls)
	}
	if fe.gotQuery != "DROP TABLE users;" {
		t.Fatalf("expected the Parse query text forwarded to the evaluator, got %q", fe.gotQuery)
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

// TestPolicy_FailsClosedOnUnknownVerdict gorev F'yi dogrular: eklenti tam
// olarak "ALLOW" ya da "BLOCK" disinda bir sey dondurdugunde (ör. yazim
// hatasi "BLOKC", yanlis buyuk/kucuk harf, ya da bos deger), bu bir
// eklenti protokolu hatasi sayilmali ve guvenli tarafta kalinip sorgu
// engellenmelidir (fail-closed) - sessizce Allow'a dusmemelidir.
func TestPolicy_FailsClosedOnUnknownVerdict(t *testing.T) {
	cases := []string{"BLOKC", "allow", "block", "", "ALLOWED", "TRUE"}

	for _, verdict := range cases {
		t.Run(verdict, func(t *testing.T) {
			fe := &fakeEvaluator{verdict: verdict, reason: "eklentiden gelen sebep"}
			var loggedErr error
			p := &Policy{
				rt:             fe,
				blockedPhrases: nil,
				onError:        func(err error) { loggedErr = err },
			}

			v, reason := p.Evaluate(protocol.Message{Type: protocol.MsgQuery, Query: "SELECT 1;"})

			if v != firewall.Block {
				t.Fatalf("verdict %q: expected fail-closed Block for an invalid verdict, got %v", verdict, v)
			}
			if reason == "" {
				t.Fatalf("verdict %q: expected a non-empty reason when failing closed", verdict)
			}
			if loggedErr == nil {
				t.Fatalf("verdict %q: expected onError to be called for the invalid verdict", verdict)
			}
		})
	}
}

func TestPolicy_ExactAllowVerdictIsAllowed(t *testing.T) {
	fe := &fakeEvaluator{verdict: "ALLOW"}
	p := &Policy{rt: fe, blockedPhrases: nil}

	v, reason := p.Evaluate(protocol.Message{Type: protocol.MsgQuery, Query: "SELECT 1;"})

	if v != firewall.Allow {
		t.Fatalf("expected exact 'ALLOW' verdict to be allowed, got %v (reason=%q)", v, reason)
	}
}

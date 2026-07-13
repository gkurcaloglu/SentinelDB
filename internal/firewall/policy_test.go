package firewall

import (
	"testing"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

func TestDenyKeywords_BlocksDangerousQueries(t *testing.T) {
	policy := DenyKeywords("DROP TABLE", "DELETE FROM")

	cases := []struct {
		query   string
		wantBlk bool
	}{
		{"DROP TABLE users;", true},
		{"drop   table\tusers;", true}, // buyuk/kucuk harf ve bosluk duyarsiz
		{"DELETE FROM users WHERE id = 1;", true},
		{"SELECT * FROM users;", false},
		{"UPDATE users SET name = 'x' WHERE id = 1;", false},
	}

	for _, tc := range cases {
		v, reason := policy.Evaluate(protocol.Message{Type: protocol.MsgQuery, Query: tc.query})
		blocked := v == Block
		if blocked != tc.wantBlk {
			t.Errorf("query %q: got blocked=%v (reason=%q), want %v", tc.query, blocked, reason, tc.wantBlk)
		}
		if blocked && reason == "" {
			t.Errorf("query %q: blocked but reason is empty", tc.query)
		}
	}
}

func TestDenyKeywords_IgnoresNonQueryNonParseMessages(t *testing.T) {
	policy := DenyKeywords("DROP TABLE")

	// Bind/Describe/Execute/Close/Flush/Sync hicbir yeni SQL sablonu
	// tasimaz (m.Query bos) - DenyKeywords bunlari denetlemez.
	for _, typ := range []protocol.MessageType{protocol.MsgBind, protocol.MsgDescribe, protocol.MsgExecute, protocol.MsgClose, protocol.MsgFlush, protocol.MsgSync} {
		v, _ := policy.Evaluate(protocol.Message{Type: typ, Query: "DROP TABLE users;"})
		if v != Allow {
			t.Fatalf("type %v: expected non-Query/non-Parse messages to be allowed regardless of content, got %v", typ, v)
		}
	}
}

func TestDenyKeywords_TreatsExtendedParseLikeSimpleQuery(t *testing.T) {
	// bkz. gorev 8 "Parse-time policy evaluation": Extended Query Parse
	// (MsgParse) SQL sablonunu tasir - DenyKeywords bunu MsgQuery ile
	// AYNI kurallarla denetlemelidir (SQL matching bypass edilemez).
	policy := DenyKeywords("DROP TABLE", "DELETE FROM")

	cases := []struct {
		query   string
		wantBlk bool
	}{
		{"DROP TABLE users;", true},
		{"drop   table\tusers;", true},
		{"DELETE FROM users WHERE id = 1;", true},
		{"SELECT * FROM users;", false},
	}
	for _, tc := range cases {
		v, reason := policy.Evaluate(protocol.Message{Type: protocol.MsgParse, Name: "Parse", Query: tc.query})
		blocked := v == Block
		if blocked != tc.wantBlk {
			t.Errorf("Parse query %q: got blocked=%v (reason=%q), want %v", tc.query, blocked, reason, tc.wantBlk)
		}
		if blocked && reason == "" {
			t.Errorf("Parse query %q: blocked but reason is empty", tc.query)
		}
	}
}

func TestDenyKeywords_NaiveTextMatchCatchesLiterals(t *testing.T) {
	// DenyKeywords gercek bir SQL ayristirici degil; string literal icindeki
	// eslesmeleri de yakalar. Bu bilinen bir sinirlamadir, hata degil.
	policy := DenyKeywords("DROP TABLE")
	v, _ := policy.Evaluate(protocol.Message{
		Type:  protocol.MsgQuery,
		Query: "INSERT INTO logs (msg) VALUES ('someone tried DROP TABLE');",
	})
	if v != Block {
		t.Fatalf("expected naive text match to flag the literal too, got %v", v)
	}
}

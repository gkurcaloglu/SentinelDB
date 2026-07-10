package protocol

import "testing"

func TestBuildErrorResponse_DecodesAsErrorResponse(t *testing.T) {
	pkt := BuildErrorResponse("ERROR", "42501", "test mesaji")

	var got []Message
	dec := NewServerDecoder(func(m Message) { got = append(got, m) }, func(err error) {
		t.Fatalf("unexpected decode error: %v", err)
	})
	dec.Write(pkt)

	if len(got) != 1 || got[0].Name != "ErrorResponse" {
		t.Fatalf("expected ErrorResponse message, got %+v", got)
	}
	if got[0].Type != MsgErrorResponse {
		t.Fatalf("expected type %q, got %q", byte(MsgErrorResponse), byte(got[0].Type))
	}
}

func TestBuildReadyForQuery_DecodesAsReadyForQuery(t *testing.T) {
	pkt := BuildReadyForQuery('I')

	var got []Message
	dec := NewServerDecoder(func(m Message) { got = append(got, m) }, func(err error) {
		t.Fatalf("unexpected decode error: %v", err)
	})
	dec.Write(pkt)

	if len(got) != 1 || got[0].Name != "ReadyForQuery" || got[0].Length != 5 {
		t.Fatalf("expected ReadyForQuery(length=5), got %+v", got)
	}
}

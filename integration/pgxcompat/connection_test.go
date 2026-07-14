package pgxcompat

import (
	"context"
	"testing"
	"time"
)

// TestConnectionStartupAuthAndProtocolNegotiation proves that an ordinary,
// unmodified pgx v5 connection can complete plaintext startup and
// PostgreSQL SCRAM authentication through SentinelDB's opt-in Extended
// Query gateway (internal/gateway.RunStartupHandoff), negotiate the latest
// protocol version pgx requests (3.0 or 3.2, depending on the PostgreSQL
// major version behind the gateway), and run a real Extended Query while
// SentinelDB relays a correctly-shaped BackendKeyData secret key.
//
// PostgreSQL 16 must retain legacy-compatible (fixed 4-byte) key behavior;
// PostgreSQL 18 must expose a key longer than that legacy form (currently
// 32 bytes, but this test only asserts ">4 and <=256" per the documented
// protocol range - see docs/postgresql-protocol.md - to avoid pinning an
// undocumented exact length). The PID and secret key bytes themselves are
// never read into a log line or failure message - only their length.
//
// (*pgx.Conn).Ping is deliberately exercised last, and expected to fail
// *and* terminate the connection: in pinned pgx v5.10.0, pgconn.PgConn.Ping
// delegates to `Exec(ctx, "-- ping")`, which issues a raw Simple Query
// message - there is no Extended Query option at that layer in this pgx
// version, and no pgx configuration available today changes it.
// SentinelDB's Extended-only gateway correctly rejects that Simple Query
// fail-closed and terminates the connection, exactly like the documented
// mixed-protocol boundary (see TestSimpleQueryRejectedOnExtendedOnlyGateway).
// This is a genuine, *current* compatibility limitation between pinned
// pgx v5.10.0's Ping and SentinelDB's current Extended-only mode that
// this suite discovered and documents here - not a SentinelDB bug to
// work around (SentinelDB does not start accepting Simple Query on an
// Extended-only connection to accommodate it), and not a claim that this
// can never change in a future pgx release or a future SentinelDB stage;
// every other test in this package proves connectivity via Extended
// Query instead (see helpers_test.go's assertAlive).
func TestConnectionStartupAuthAndProtocolNegotiation(t *testing.T) {
	env := requireIntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := connectGateway(ctx, env, nil)
	if err != nil {
		t.Fatalf("connect through gateway: %v", err)
	}
	defer conn.Close(context.Background())

	secretKey := conn.PgConn().SecretKey()
	length := len(secretKey)
	if length < 4 || length > 256 {
		t.Fatalf("relayed backend secret key length is outside the documented [4,256] byte range: got %d bytes", length)
	}
	if env.expectLongCancelKey {
		if length <= 4 {
			t.Fatalf("expected a PostgreSQL 18 protocol 3.2 secret key longer than the legacy 4-byte form, got %d bytes", length)
		}
	} else if length != 4 {
		t.Fatalf("expected PostgreSQL 16's legacy-compatible fixed 4-byte secret key, got %d bytes", length)
	}

	// Real connectivity, proven via Extended Query - the gateway is a real
	// Extended Query participant, not merely completing the handshake.
	assertAlive(ctx, t, conn)

	// See the doc comment above: Ping cannot succeed here by design, and
	// the rejection terminates the connection.
	if err := conn.Ping(ctx); err == nil {
		t.Fatalf("expected (*pgx.Conn).Ping to fail against the Extended-only gateway (it always issues a Simple Query at the pgconn layer), but it succeeded")
	}
}

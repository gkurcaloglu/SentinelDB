package pgxcompat

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestParseTimePolicyRejectionAndRecovery proves real-driver compatibility
// with SentinelDB's discard-until-Sync recovery: a single pgx connection
// sends a statement whose Parse SQL matches the configured blocked phrase
// (the driver-compat stack configures "DROP TABLE"), observes a policy
// rejection with SQLSTATE 42501, and then - on the very same connection,
// no reconnect - runs a safe parameterized query successfully. The blocked
// table's continued existence and unchanged row count is itself proof the
// blocked statement never reached PostgreSQL.
func TestParseTimePolicyRejectionAndRecovery(t *testing.T) {
	env := requireIntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := connectGateway(ctx, env, nil)
	if err != nil {
		t.Fatalf("connect through gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })

	table := uniqueName("pgxcompat_policy")
	if err := execExtended(ctx, conn, fmt.Sprintf("CREATE TABLE %s (id integer PRIMARY KEY)", table)); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(dropTableCleanup(t, env, table))
	if err := execExtended(ctx, conn, fmt.Sprintf("INSERT INTO %s (id) VALUES ($1)", table), 1); err != nil {
		t.Fatalf("seed row: %v", err)
	}

	// This Parse SQL matches the configured blocked phrase ("DROP TABLE")
	// and must never reach the real PostgreSQL server.
	blockedSQL := fmt.Sprintf("DROP TABLE %s", table)
	err = execExtended(ctx, conn, blockedSQL)
	if err == nil {
		t.Fatalf("expected the policy-blocked DROP TABLE statement to be rejected")
	}
	code, ok := pgErrorCode(err)
	if !ok {
		t.Fatalf("expected a PostgreSQL wire-level error for the policy-blocked statement, got: %v", err)
	}
	if code != "42501" {
		t.Fatalf("expected SQLSTATE 42501 (insufficient_privilege) for the policy-blocked Parse, got %q", code)
	}

	// The same connection, without reconnecting, must still work.
	var count int
	if err := conn.QueryRow(ctx, fmt.Sprintf("SELECT count(*) FROM %s WHERE id = $1", table), 1).Scan(&count); err != nil {
		t.Fatalf("safe query after blocked statement (same connection): %v", err)
	}
	if count != 1 {
		t.Fatalf("expected the table to still exist with its seeded row (the blocked DROP TABLE must never reach PostgreSQL), got count=%d", count)
	}
}

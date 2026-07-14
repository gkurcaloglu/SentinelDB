package pgxcompat

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestTransactions proves transaction support over the Extended Query
// gateway: a committed transaction with parameterized statements, then a
// second transaction that is rolled back, verifying the connection's
// reported transaction status (idle/in-transaction, via
// (*pgconn.PgConn).TxStatus) at each step and that the connection returns
// to idle and remains usable throughout.
//
// This deliberately does NOT use pgx's convenience Tx API
// ((*pgx.Conn).Begin / (pgx.Tx).Commit / (pgx.Tx).Rollback): this suite
// discovered that pinned pgx v5.10.0's Tx implementation issues
// "begin"/"commit"/"rollback" via (*pgx.Conn).Exec with zero bind
// arguments, which - like (*pgx.Conn).Ping (see helpers_test.go's
// assertAlive doc comment) - forces the Simple Query Protocol in this
// pgx version. SentinelDB's Extended-only gateway correctly rejects that
// fail-closed and terminates the connection, so pgx's Tx API is
// currently incompatible with Extended-only mode - a *current*
// driver/gateway-mode combination limitation of pinned pgx v5.10.0 with
// SentinelDB's current implementation, not a SentinelDB bug and not a
// claim that this can never change (mixed Simple/Extended routing is
// explicitly out of scope for this branch; SentinelDB does not start
// accepting Simple Query on an Extended-only connection to accommodate
// it). Ordinary parameterized/prepared Extended Query operations are
// unaffected.
//
// BEGIN/COMMIT/ROLLBACK are, however, ordinary SQL statements from the
// wire protocol's point of view - this test sends them explicitly through
// execExtended (still entirely pgx's public Query/Exec API, just not the
// higher-level Tx wrapper), which never uses Simple Query, proving
// SentinelDB's Extended Query path itself handles transaction control
// correctly.
func TestTransactions(t *testing.T) {
	env := requireIntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := connectGateway(ctx, env, nil)
	if err != nil {
		t.Fatalf("connect through gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })

	table := uniqueName("pgxcompat_tx")
	if err := execExtended(ctx, conn, fmt.Sprintf("CREATE TABLE %s (id integer PRIMARY KEY, name text)", table)); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(dropTableCleanup(t, env, table))

	const txStatusIdle = 'I'
	const txStatusInTransaction = 'T'

	if got := conn.PgConn().TxStatus(); got != txStatusIdle {
		t.Fatalf("expected idle transaction status before BEGIN, got %q", string(got))
	}

	if err := execExtended(ctx, conn, "BEGIN"); err != nil {
		t.Fatalf("BEGIN: %v", err)
	}
	if got := conn.PgConn().TxStatus(); got != txStatusInTransaction {
		t.Fatalf("expected in-transaction status after BEGIN, got %q", string(got))
	}

	insertSQL := fmt.Sprintf("INSERT INTO %s (id, name) VALUES ($1, $2)", table)
	if err := execExtended(ctx, conn, insertSQL, 1, "frank"); err != nil {
		t.Fatalf("insert within transaction: %v", err)
	}
	if err := execExtended(ctx, conn, insertSQL, 2, "grace"); err != nil {
		t.Fatalf("insert within transaction: %v", err)
	}
	if err := execExtended(ctx, conn, "COMMIT"); err != nil {
		t.Fatalf("COMMIT: %v", err)
	}
	if got := conn.PgConn().TxStatus(); got != txStatusIdle {
		t.Fatalf("expected idle transaction status after COMMIT, got %q", string(got))
	}

	var count int
	if err := conn.QueryRow(ctx, fmt.Sprintf("SELECT count(*) FROM %s", table)).Scan(&count); err != nil {
		t.Fatalf("count after commit: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 committed rows, got %d", count)
	}

	if err := execExtended(ctx, conn, "BEGIN"); err != nil {
		t.Fatalf("BEGIN (second transaction): %v", err)
	}
	if err := execExtended(ctx, conn, insertSQL, 3, "henry"); err != nil {
		t.Fatalf("insert within second transaction: %v", err)
	}
	if err := execExtended(ctx, conn, "ROLLBACK"); err != nil {
		t.Fatalf("ROLLBACK: %v", err)
	}
	if got := conn.PgConn().TxStatus(); got != txStatusIdle {
		t.Fatalf("expected idle transaction status after ROLLBACK, got %q", string(got))
	}

	// The connection returns to idle and remains usable: the rolled-back
	// row must not be present.
	if err := conn.QueryRow(ctx, fmt.Sprintf("SELECT count(*) FROM %s", table)).Scan(&count); err != nil {
		t.Fatalf("count after rollback: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected the rolled-back insert to be undone (count should remain 2), got %d", count)
	}
}

package pgxcompat

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestNamedPreparedStatement uses pgx's public named-prepared-statement API
// end-to-end: Prepare (Parse+Describe), multiple Execute-equivalent
// QueryRow calls with different parameters, and Deallocate - which sends a
// protocol-level Close message (not a textual SQL `DEALLOCATE`) - followed
// by a safe query on the same connection to prove it still works
// afterwards.
func TestNamedPreparedStatement(t *testing.T) {
	env := requireIntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := connectGateway(ctx, env, nil)
	if err != nil {
		t.Fatalf("connect through gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })

	table := uniqueName("pgxcompat_prepared")
	if err := execExtended(ctx, conn, fmt.Sprintf("CREATE TABLE %s (id integer PRIMARY KEY, name text)", table)); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(dropTableCleanup(t, env, table))

	insertSQL := fmt.Sprintf("INSERT INTO %s (id, name) VALUES ($1, $2)", table)
	rows := map[int]string{1: "dave", 2: "erin", 3: "frank"}
	for id, name := range rows {
		if err := execExtended(ctx, conn, insertSQL, id, name); err != nil {
			t.Fatalf("insert id=%d: %v", id, err)
		}
	}

	stmtName := uniqueName("pgxcompat_select_by_id")
	selectSQL := fmt.Sprintf("SELECT name FROM %s WHERE id = $1", table)
	if _, err := conn.Prepare(ctx, stmtName, selectSQL); err != nil {
		t.Fatalf("prepare named statement: %v", err)
	}

	// Execute the named prepared statement multiple times with different
	// parameters via pgx's public API (referencing it by name routes
	// through pgx's execPrepared path - Bind+Execute against the
	// already-parsed/described statement, no re-Parse).
	for id, want := range rows {
		var got string
		if err := conn.QueryRow(ctx, stmtName, id).Scan(&got); err != nil {
			t.Fatalf("execute prepared statement id=%d: %v", id, err)
		}
		if got != want {
			t.Fatalf("execute prepared statement id=%d: got %q, want %q", id, got, want)
		}
	}
	// A second round of executions against the same prepared statement.
	for id, want := range rows {
		var got string
		if err := conn.QueryRow(ctx, stmtName, id).Scan(&got); err != nil {
			t.Fatalf("re-execute prepared statement id=%d: %v", id, err)
		}
		if got != want {
			t.Fatalf("re-execute prepared statement id=%d: got %q, want %q", id, got, want)
		}
	}

	// Close/deallocate through the protocol-level driver API.
	if err := conn.Deallocate(ctx, stmtName); err != nil {
		t.Fatalf("deallocate prepared statement: %v", err)
	}

	// A subsequent safe query on the same connection must still succeed.
	var one int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("query after deallocating prepared statement: %v", err)
	}
	if one != 1 {
		t.Fatalf("SELECT 1 returned %d, want 1", one)
	}
}

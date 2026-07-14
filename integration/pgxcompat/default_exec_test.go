package pgxcompat

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestDefaultExtendedQueryExecution leaves pgx's default Extended Query
// execution mode (QueryExecModeCacheStatement) completely unchanged and
// runs the same parameterized SELECT repeatedly, so pgx exercises its
// normal automatic server-side statement preparation/cache behavior
// against the gateway - the first execution of a given SQL text triggers
// Parse+Describe, later executions of the identical text reuse the cached
// prepared statement (Bind+Execute only).
func TestDefaultExtendedQueryExecution(t *testing.T) {
	env := requireIntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := connectGateway(ctx, env, nil)
	if err != nil {
		t.Fatalf("connect through gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })

	table := uniqueName("pgxcompat_default_exec")
	if err := execExtended(ctx, conn, fmt.Sprintf("CREATE TABLE %s (id integer PRIMARY KEY, name text)", table)); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(dropTableCleanup(t, env, table))

	insertSQL := fmt.Sprintf("INSERT INTO %s (id, name) VALUES ($1, $2)", table)
	want := map[int]string{1: "alice", 2: "bob", 3: "carol"}
	for id, name := range want {
		if err := execExtended(ctx, conn, insertSQL, id, name); err != nil {
			t.Fatalf("insert id=%d: %v", id, err)
		}
	}

	selectSQL := fmt.Sprintf("SELECT name FROM %s WHERE id = $1", table)

	// Run the identical parameterized statement repeatedly (more than one
	// execution on the same connection), proving pgx's default statement
	// cache/auto-prepare behavior works end-to-end through the gateway.
	const iterations = 5
	for i := 0; i < iterations; i++ {
		for id, name := range want {
			var got string
			if err := conn.QueryRow(ctx, selectSQL, id).Scan(&got); err != nil {
				t.Fatalf("select id=%d (iteration %d): %v", id, i, err)
			}
			if got != name {
				t.Fatalf("select id=%d (iteration %d): got %q, want %q", id, i, got, name)
			}
		}
	}

	// The connection must remain usable afterwards - not silently switched
	// to simple protocol, not left in a broken state. (Not checked via
	// (*pgx.Conn).Ping - see helpers_test.go's assertAlive doc comment for
	// why Ping is incompatible with the Extended-only gateway by design.)
	assertAlive(ctx, t, conn)
}

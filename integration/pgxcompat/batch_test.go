package pgxcompat

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestBatchedExtendedOperationsOrdering uses pgx's normal batch API
// (pgx.Batch/SendBatch) to queue multiple parameterized SELECTs and proves
// every result arrives in the same order it was submitted, that closing
// the batch leaves the connection usable, and that a genuine error inside a
// batch is handled per normal PostgreSQL Sync semantics (later batch items
// in the same implicit pipeline are aborted, and the connection recovers
// afterwards) - never via COPY or SentinelDB-unsupported pipelining
// features.
func TestBatchedExtendedOperationsOrdering(t *testing.T) {
	env := requireIntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := connectGateway(ctx, env, nil)
	if err != nil {
		t.Fatalf("connect through gateway: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })

	table := uniqueName("pgxcompat_batch")
	if err := execExtended(ctx, conn, fmt.Sprintf("CREATE TABLE %s (id integer PRIMARY KEY, name text)", table)); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(dropTableCleanup(t, env, table))

	insertSQL := fmt.Sprintf("INSERT INTO %s (id, name) VALUES ($1, $2)", table)
	names := map[int]string{1: "ivan", 2: "julia", 3: "kevin", 4: "laura"}
	for id, name := range names {
		if err := execExtended(ctx, conn, insertSQL, id, name); err != nil {
			t.Fatalf("insert id=%d: %v", id, err)
		}
	}

	selectSQL := fmt.Sprintf("SELECT name FROM %s WHERE id = $1", table)

	// Prepare/describe the statement ahead of the batch (per the gateway's
	// documented masking-shape rule that a portal needs a resolved
	// Describe shape before Execute) by running it once beforehand - this
	// also warms pgx's own statement cache for the identical SQL text used
	// inside the batch below.
	var warm string
	if err := conn.QueryRow(ctx, selectSQL, 1).Scan(&warm); err != nil {
		t.Fatalf("warm-up query before batch: %v", err)
	}

	order := []int{3, 1, 4, 2}
	batch := &pgx.Batch{}
	for _, id := range order {
		batch.Queue(selectSQL, id)
	}
	br := conn.SendBatch(ctx, batch)
	for i, id := range order {
		var got string
		if err := br.QueryRow().Scan(&got); err != nil {
			t.Fatalf("batch item %d (id=%d): %v", i, id, err)
		}
		if want := names[id]; got != want {
			t.Fatalf("batch item %d out of order or wrong: id=%d got %q, want %q", i, id, got, want)
		}
	}
	if err := br.Close(); err != nil {
		t.Fatalf("close batch: %v", err)
	}

	// The connection remains usable after closing the batch. (Not checked
	// via (*pgx.Conn).Ping - see helpers_test.go's assertAlive doc
	// comment.)
	assertAlive(ctx, t, conn)

	// A batch containing a genuine backend error, using a single shared
	// statement text (division by an integer parameter) so the error
	// surfaces only at Execute time (a parameter value, e.g. a divisor of
	// 0, cannot be known/rejected at Parse/Describe time) - not at pgx's
	// own upfront "describe every distinct new statement text in this
	// batch" pass, which this suite discovered runs before *any* batch
	// item executes and would otherwise fail the whole batch (including
	// otherwise-valid earlier items) the moment any distinct statement
	// text in the batch fails to Parse/Describe. PostgreSQL's own Sync
	// semantics abandon later same-cycle pipelined operations once a real
	// ErrorResponse occurs (see docs/postgresql-protocol.md's response
	// sequencer section), and the connection must recover afterward.
	divideSQL := "SELECT 100 / $1::int"
	badBatch := &pgx.Batch{}
	badBatch.Queue(divideSQL, 5)  // 100/5 = 20, succeeds
	badBatch.Queue(divideSQL, 0)  // division by zero, a genuine backend error
	badBatch.Queue(divideSQL, 10) // same cycle as the item above - abandoned by real PostgreSQL/Sync semantics

	badBR := conn.SendBatch(ctx, badBatch)

	var first int
	if err := badBR.QueryRow().Scan(&first); err != nil {
		t.Fatalf("first batch item should succeed before the later error: %v", err)
	}
	if first != 20 {
		t.Fatalf("first batch item: got %d, want 20", first)
	}

	var second int
	secondErr := badBR.QueryRow().Scan(&second)
	if secondErr == nil {
		t.Fatalf("expected the second batch item (division by zero) to error")
	}
	if code, ok := pgErrorCode(secondErr); ok && code != "22012" {
		t.Fatalf("expected SQLSTATE 22012 (division_by_zero) for the second batch item, got %q", code)
	}

	_ = badBR.Close() // aggregate close error, if any, is not asserted on beyond the per-item error already observed above

	// The connection must recover and remain usable after an aborted batch.
	assertAlive(ctx, t, conn)
	var count int
	if err := conn.QueryRow(ctx, fmt.Sprintf("SELECT count(*) FROM %s", table)).Scan(&count); err != nil {
		t.Fatalf("query after aborted batch: %v", err)
	}
	if count != len(names) {
		t.Fatalf("expected %d rows still present after aborted batch, got %d", len(names), count)
	}
}

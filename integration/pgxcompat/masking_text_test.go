package pgxcompat

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestExtendedQueryTextMaskingAndNullHandling proves that, when a client
// (pgx) explicitly requests text result format and runs a real Extended
// Query through the gateway, the configured `email` masking target is
// masked, other columns are returned unmodified, and SQL NULL is preserved
// as NULL - while the real database, verified through a direct connection
// bypassing SentinelDB, still holds the original raw values.
func TestExtendedQueryTextMaskingAndNullHandling(t *testing.T) {
	env := requireIntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	direct, err := connectDirect(ctx, env)
	if err != nil {
		t.Fatalf("connect directly to PostgreSQL: %v", err)
	}
	t.Cleanup(func() { direct.Close(context.Background()) })

	table := uniqueName("pgxcompat_mask_text")
	if _, err := direct.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (id integer PRIMARY KEY, email text, name text)", table)); err != nil {
		t.Fatalf("create table directly: %v", err)
	}
	t.Cleanup(dropTableCleanup(t, env, table))

	const rawEmail = "alice.distinctive@example.com"
	if _, err := direct.Exec(ctx,
		fmt.Sprintf("INSERT INTO %s (id, email, name) VALUES ($1,$2,$3), ($4,$5,$6), ($7,$8,$9)", table),
		1, rawEmail, "Alice A",
		2, "bob.other@example.com", "Bob B",
		3, nil, "Null Email User",
	); err != nil {
		t.Fatalf("insert directly: %v", err)
	}

	gw, err := connectGateway(ctx, env, nil)
	if err != nil {
		t.Fatalf("connect through gateway: %v", err)
	}
	defer gw.Close(context.Background())

	selectSQL := fmt.Sprintf("SELECT id, email, name FROM %s ORDER BY id", table)

	type row struct {
		id    int
		email *string
		name  string
	}

	// Explicitly request TEXT result format for every column (0 = text) -
	// this still uses Extended Query (Parse/Bind/Describe/Execute/Sync),
	// just with an explicit, rather than implicit, result-format choice.
	rows, err := gw.Query(ctx, selectSQL, pgx.QueryResultFormats{0, 0, 0})
	if err != nil {
		t.Fatalf("masked select through gateway: %v", err)
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.email, &r.name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(got))
	}

	want := map[int]struct {
		email *string
		name  string
	}{
		1: {strPtr("al****@example.com"), "Alice A"},
		2: {strPtr("bo****@example.com"), "Bob B"},
		3: {nil, "Null Email User"},
	}
	for _, r := range got {
		w, ok := want[r.id]
		if !ok {
			t.Fatalf("unexpected row id=%d", r.id)
		}
		if r.name != w.name {
			t.Fatalf("id=%d: non-masked column name changed: got %q, want %q", r.id, r.name, w.name)
		}
		switch {
		case w.email == nil:
			if r.email != nil {
				t.Fatalf("id=%d: expected NULL email to remain NULL, got non-NULL value", r.id)
			}
		case r.email == nil:
			t.Fatalf("id=%d: expected a masked email value, got NULL", r.id)
		case *r.email != *w.email:
			t.Fatalf("id=%d: masked email mismatch: got %q, want %q", r.id, *r.email, *w.email)
		}
		if r.email != nil && *r.email == rawEmail {
			t.Fatalf("id=%d: raw email value was returned unmasked through the gateway", r.id)
		}
	}

	// The connection remains usable and was never silently downgraded to
	// simple protocol for these checks. (Not checked via
	// (*pgx.Conn).Ping - see helpers_test.go's assertAlive doc comment.)
	assertAlive(ctx, t, gw)

	// The real database, verified directly (bypassing SentinelDB), must
	// still hold the original raw value - masking only ever rewrites what
	// is returned to the client, never stored data.
	var rawFromDB string
	if err := direct.QueryRow(ctx, fmt.Sprintf("SELECT email FROM %s WHERE id = 1", table)).Scan(&rawFromDB); err != nil {
		t.Fatalf("verify raw value directly: %v", err)
	}
	if rawFromDB != rawEmail {
		t.Fatalf("underlying database no longer holds the raw email: got %q, want %q", rawFromDB, rawEmail)
	}
}

func strPtr(s string) *string { return &s }

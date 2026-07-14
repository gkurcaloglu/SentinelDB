package pgxcompat

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestExtendedQueryBinaryMaskedColumnFailsClosed is an expected-limitation
// test, not a request to add binary masking support. SentinelDB's masking
// only understands text-format cells (see docs/postgresql-protocol.md's
// "Binary format limitation"); on the opt-in Extended Query path, a
// masking-target column requested in binary result format is caught by
// ExtendedRuntime's Execute-time masking preflight
// (internal/masking.ErrExtendedBinaryTarget /
// gateway.ErrExtendedMaskingPreflightRejected) and rejected before the
// statement ever executes - this test proves that fail-closed behavior
// holds for a real driver, that the raw value is never returned, and that
// the test does not go on to reuse the affected connection for anything
// else.
func TestExtendedQueryBinaryMaskedColumnFailsClosed(t *testing.T) {
	env := requireIntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	direct, err := connectDirect(ctx, env)
	if err != nil {
		t.Fatalf("connect directly to PostgreSQL: %v", err)
	}
	t.Cleanup(func() { direct.Close(context.Background()) })

	table := uniqueName("pgxcompat_mask_binary")
	if _, err := direct.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (id integer PRIMARY KEY, email text)", table)); err != nil {
		t.Fatalf("create table directly: %v", err)
	}
	t.Cleanup(dropTableCleanup(t, env, table))

	const rawEmail = "binary.target@example.com"
	if _, err := direct.Exec(ctx, fmt.Sprintf("INSERT INTO %s (id, email) VALUES ($1,$2)", table), 1, rawEmail); err != nil {
		t.Fatalf("insert directly: %v", err)
	}

	// A separate gateway connection, used only for this rejection.
	gw, err := connectGateway(ctx, env, nil)
	if err != nil {
		t.Fatalf("connect through gateway: %v", err)
	}
	defer gw.Close(context.Background())

	selectSQL := fmt.Sprintf("SELECT email FROM %s WHERE id = $1", table)

	// Explicitly request BINARY (1) result format for the masked email
	// column.
	rows, err := gw.Query(ctx, selectSQL, pgx.QueryResultFormats{1}, 1)
	var gotValue string
	var scanErr error
	if err == nil {
		for rows.Next() {
			scanErr = rows.Scan(&gotValue)
		}
		if err == nil {
			err = rows.Err()
		}
	}

	if err == nil && scanErr == nil {
		t.Fatalf("expected the binary-format request against a masked column to fail closed, but it succeeded")
	}
	if gotValue == rawEmail {
		t.Fatalf("raw email value was returned for a binary-format masked column request")
	}

	firstErr := err
	if firstErr == nil {
		firstErr = scanErr
	}
	if code, ok := pgErrorCode(firstErr); ok {
		t.Logf("binary masked-column request rejected with SQLSTATE %s (expected)", code)
	} else {
		t.Fatalf("expected a PostgreSQL wire-level error rejecting the binary-format masked column, got: %v", firstErr)
	}

	// This connection observed a rejected request; per the test plan, it
	// must not be reused for anything else - close it here rather than
	// continuing to issue requests on it, even though SentinelDB's current
	// Execute-time masking preflight is a recoverable, connection-local
	// rejection (SQLSTATE 42501) rather than a hard connection-terminating
	// failure (see internal/firewall/extended_frontend.go's
	// handleRegistrationOutcome). Asserting a hard disconnect here would
	// test behavior SentinelDB does not currently implement for this
	// specific preflight category; asserting success would contradict
	// "verify the failed connection is not reused" and the fail-closed
	// requirement that the raw/binary value is never returned - both of
	// which are already proven above.
	gw.Close(context.Background())
}

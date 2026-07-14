// Package pgxcompat contains SentinelDB's first dedicated real-driver
// compatibility suite: it runs the unmodified, stable jackc/pgx/v5 driver
// against a real PostgreSQL server through SentinelDB's opt-in Extended
// Query gateway (protocol.extended_query_enabled: true).
//
// This package never implements PostgreSQL wire messages itself - every
// test drives a real *pgx.Conn through its public API. It is hermetic by
// default: every test calls requireIntegrationEnv first, which skips (with
// a clear reason) whenever the required environment variables are absent,
// so `go test ./...` run from this directory never requires Docker or a
// live PostgreSQL server to pass. scripts/driver-compat.ps1 (and the CI
// driver-compat job) set the environment variables and provide the real
// stack.
package pgxcompat

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	// envDriverDSN names the environment variable carrying the DSN pgx
	// uses to connect *through* the SentinelDB gateway.
	envDriverDSN = "SENTINELDB_DRIVER_DSN"
	// envDirectDSN names the environment variable carrying the DSN used to
	// connect directly to the real PostgreSQL server, bypassing SentinelDB -
	// used only to seed/verify raw data and to observe pg_stat_activity for
	// the cancellation test. Never used to run the statements under test.
	envDirectDSN = "SENTINELDB_DIRECT_DSN"
	// envExpectLongCancelKey names the environment variable that tells the
	// suite whether the PostgreSQL server behind SentinelDB is expected to
	// use PostgreSQL 18's protocol 3.2 variable-length (>4 byte) cancel
	// key, as opposed to PostgreSQL 16's legacy fixed 4-byte key.
	envExpectLongCancelKey = "SENTINELDB_EXPECT_LONG_CANCEL_KEY"
)

// integrationEnv holds the environment-provided configuration for one run
// of the suite.
type integrationEnv struct {
	driverDSN           string
	directDSN           string
	expectLongCancelKey bool
}

// requireIntegrationEnv skips the calling test, with a clear reason, unless
// both DSN environment variables are set. It never hard-codes a host,
// port, or credential - every value is environment-provided (see
// scripts/driver-compat.ps1 and deploy/driver-compat).
func requireIntegrationEnv(t *testing.T) integrationEnv {
	t.Helper()

	driverDSN := os.Getenv(envDriverDSN)
	directDSN := os.Getenv(envDirectDSN)
	if driverDSN == "" || directDSN == "" {
		t.Skipf("skipping real pgx driver-compatibility test: %s and %s must both be set (run scripts/driver-compat.ps1, or see deploy/driver-compat)", envDriverDSN, envDirectDSN)
	}

	expectLong, _ := strconv.ParseBool(os.Getenv(envExpectLongCancelKey))
	return integrationEnv{
		driverDSN:           driverDSN,
		directDSN:           directDSN,
		expectLongCancelKey: expectLong,
	}
}

// connectGateway parses env.driverDSN into a *pgx.ConnConfig, requests the
// latest supported PostgreSQL wire protocol version while still accepting
// 3.0 as the minimum (see docs/postgresql-protocol.md's "Protocol 3.0 and
// 3.2 compatibility"), applies an optional caller mutation (e.g. a unique
// application_name for a specific test), and connects through the gateway.
func connectGateway(ctx context.Context, env integrationEnv, mutate func(*pgx.ConnConfig)) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(env.driverDSN)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", envDriverDSN, err)
	}
	cfg.MinProtocolVersion = "3.0"
	cfg.MaxProtocolVersion = "latest"
	if mutate != nil {
		mutate(cfg)
	}
	return pgx.ConnectConfig(ctx, cfg)
}

// connectDirect connects straight to the real PostgreSQL server, bypassing
// SentinelDB entirely - used only to seed/verify raw data and to observe
// pg_stat_activity; never to run the statements under test.
func connectDirect(ctx context.Context, env integrationEnv) (*pgx.Conn, error) {
	conn, err := pgx.Connect(ctx, env.directDSN)
	if err != nil {
		return nil, fmt.Errorf("parse/connect %s: %w", envDirectDSN, err)
	}
	return conn, nil
}

// uniqueName returns a name derived from prefix that is unique within this
// process, suitable for a table, prepared-statement, or application_name
// that must not collide with a previous or concurrent test run.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

// execExtended runs sql (with optional bind parameters) through conn using
// pgx's normal Extended Query execution path (Parse/Bind/Describe/Execute/
// Sync).
//
// This deliberately does NOT use (*pgx.Conn).Exec: pgx's own Exec silently
// downgrades to the Simple Query Protocol whenever it is called with zero
// bind arguments (see pgx's conn.go, "Always use simple protocol when there
// are no arguments"). SentinelDB's opt-in Extended-only gateway
// (protocol.extended_query_enabled: true) always rejects a Simple Query
// message fail-closed and terminates the connection (see test J), so any
// zero-argument statement (most DDL) run via Exec against the gateway would
// break the connection instead of exercising the Extended Query path this
// suite is meant to prove out. Query never makes that downgrade, so it is
// used here for every statement regardless of argument count.
func execExtended(ctx context.Context, conn *pgx.Conn, sql string, args ...any) error {
	rows, err := conn.Query(ctx, sql, args...)
	if err != nil {
		return err
	}
	rows.Close()
	return rows.Err()
}

// dropTableCleanup returns a t.Cleanup function that drops table using a
// short-lived, direct (non-gateway) connection and a bounded, independent
// context (the test's own context may already be canceled/expired, and
// any gateway connection created by the test may already be closed, by
// the time cleanup runs).
//
// Cleanup deliberately never reuses the test's own gateway connection to
// run this DROP TABLE: the driver-compat stack's configured blocked
// phrase is literally "DROP TABLE" (see deploy/driver-compat/config.yaml
// and TestParseTimePolicyRejectionAndRecovery), so a gateway-routed
// cleanup statement would always be policy-blocked. This has nothing to
// do with SentinelDB's Extended-only mode - a direct connection is simply
// the correct, uninvolved path for test teardown.
func dropTableCleanup(t *testing.T, env integrationEnv, table string) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := connectDirect(ctx, env)
		if err != nil {
			t.Logf("cleanup: failed to connect directly to drop table %s: %v", table, err)
			return
		}
		defer conn.Close(context.Background())
		if _, err := conn.Exec(ctx, "DROP TABLE IF EXISTS "+table); err != nil {
			t.Logf("cleanup: failed to drop table %s: %v", table, err)
		}
	}
}

// pollUntilTrue calls check repeatedly (spaced by interval) until it
// reports true, returns an error, or ctx is done - never relying on a
// single fixed sleep. It is used to deterministically observe
// pg_stat_activity state instead of guessing a sleep duration.
func pollUntilTrue(ctx context.Context, interval time.Duration, check func(context.Context) (bool, error)) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ok, err := check(ctx)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// assertAlive proves conn remains usable by running a trivial SELECT
// through Extended Query (Query never downgrades to Simple Query
// regardless of argument count - see execExtended's doc comment).
//
// It deliberately does NOT call (*pgx.Conn).Ping: pgconn.PgConn.Ping is
// hard-wired to `pgConn.Exec(ctx, "-- ping")`, which always issues a raw
// PostgreSQL Simple Query ('Q') message - there is no Extended Query
// option at that layer, and no pgx configuration changes it. Against
// SentinelDB's opt-in Extended-only gateway that unconditionally rejects
// Simple Query fail-closed, Ping can never succeed; this is a genuine,
// permanent incompatibility this suite discovered and documents (see
// TestConnectionStartupAuthAndProtocolNegotiation and
// docs/postgresql-protocol.md's driver-compatibility notes) rather than a
// SentinelDB bug to work around - SentinelDB must not start accepting
// Simple Query on an Extended-only connection to accommodate it.
func assertAlive(ctx context.Context, t *testing.T, conn *pgx.Conn) {
	t.Helper()
	var one int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("connection unusable (Extended Query SELECT 1 failed): %v", err)
	}
	if one != 1 {
		t.Fatalf("SELECT 1 returned %d, want 1", one)
	}
}

// pgErrorCode returns the SQLSTATE of err if it is (or wraps) a
// *pgconn.PgError, and ok=true. It never returns the error's Message,
// Detail, Hint, or any other server-supplied text - only the fixed
// five-character SQLSTATE code, which is safe to assert on and print in a
// test failure.
func pgErrorCode(err error) (code string, ok bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code, true
	}
	return "", false
}

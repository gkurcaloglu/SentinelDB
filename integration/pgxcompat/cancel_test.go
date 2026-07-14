package pgxcompat

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestCancelRequest uses pgx's public cancellation API
// ((*pgconn.PgConn).CancelRequest) and the BackendKeyData credentials
// SentinelDB relayed during startup to cancel a real, deliberately
// long-running query. It connects through the gateway with a unique
// application_name, deterministically observes (via bounded polling of
// pg_stat_activity through a direct, non-gateway connection - never a
// fixed sleep) that the exact session is actively running the long query,
// sends the cancellation through the gateway, verifies the running query
// returns SQLSTATE 57014 (query_canceled), and verifies the original
// connection remains open and usable afterwards.
//
// This test runs identically against PostgreSQL 16 (legacy fixed 4-byte
// cancellation key) and PostgreSQL 18 (protocol 3.2 variable-length
// cancellation key) - see scripts/driver-compat.ps1's -PostgresVersion
// parameter. It never inspects, compares, or logs the key's contents,
// only pgx's own transparent use of it via CancelRequest.
func TestCancelRequest(t *testing.T) {
	env := requireIntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	appName := uniqueName("pgxcompat_cancel")
	gw, err := connectGateway(ctx, env, func(cfg *pgx.ConnConfig) {
		cfg.RuntimeParams["application_name"] = appName
	})
	if err != nil {
		t.Fatalf("connect through gateway: %v", err)
	}
	defer gw.Close(context.Background())

	direct, err := connectDirect(ctx, env)
	if err != nil {
		t.Fatalf("connect directly to PostgreSQL: %v", err)
	}
	defer direct.Close(context.Background())

	queryErrCh := make(chan error, 1)
	go func() {
		rows, qerr := gw.Query(ctx, "SELECT pg_sleep(30)")
		if qerr == nil {
			rows.Close()
			qerr = rows.Err()
		}
		queryErrCh <- qerr
	}()

	pollCtx, pollCancel := context.WithTimeout(ctx, 15*time.Second)
	defer pollCancel()
	pollErr := pollUntilTrue(pollCtx, 150*time.Millisecond, func(pctx context.Context) (bool, error) {
		var active bool
		err := direct.QueryRow(pctx,
			`SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = $1 AND state = 'active' AND query ILIKE '%pg_sleep%')`,
			appName,
		).Scan(&active)
		return active, err
	})
	if pollErr != nil {
		t.Fatalf("timed out waiting to deterministically observe the long-running query as active in pg_stat_activity: %v", pollErr)
	}

	cancelCtx, cancelCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCancel()
	if err := gw.PgConn().CancelRequest(cancelCtx); err != nil {
		t.Fatalf("send CancelRequest through the gateway: %v", err)
	}

	select {
	case qerr := <-queryErrCh:
		var pgErr *pgconn.PgError
		if !errors.As(qerr, &pgErr) {
			t.Fatalf("expected a PostgreSQL error after CancelRequest, got: %v", qerr)
		}
		if pgErr.Code != "57014" {
			t.Fatalf("expected SQLSTATE 57014 (query_canceled), got %q", pgErr.Code)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("long-running query did not return after CancelRequest within the bounded deadline")
	}

	// The original connection must remain open and usable.
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pingCancel()
	var one int
	if err := gw.QueryRow(pingCtx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("gateway connection unusable after cancellation: %v", err)
	}
	if one != 1 {
		t.Fatalf("SELECT 1 returned %d, want 1", one)
	}
}

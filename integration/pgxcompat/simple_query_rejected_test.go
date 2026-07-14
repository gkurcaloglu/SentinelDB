package pgxcompat

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestSimpleQueryRejectedOnExtendedOnlyGateway documents the current
// connection-wide mode boundary: a pgx connection explicitly configured for
// Simple Query Protocol (DefaultQueryExecMode = QueryExecModeSimpleProtocol)
// completes plaintext startup/authentication normally (that phase never
// distinguishes Simple from Extended), but the very first Simple Query
// ('Q') message sent afterwards is rejected fail-closed by the
// Extended-only gateway (internal/firewall/extended_frontend.go's
// ExtendedFrontend, which fails closed on any MsgQuery/unsupported
// steady-state message type - see ErrExtendedFrontendUnsupportedMessage),
// and the connection is terminated. This test does not change - and is not
// a request to change - SentinelDB's unsupported mixed Simple/Extended
// routing in this branch.
//
// Because ExtendedFrontend.handle rejects Query (and every other
// unsupported message type) before any State/ResponseSequencer
// registration or upstream forwarding call is ever made (see that file's
// dispatch switch), the safe query used here structurally cannot reach the
// real PostgreSQL server - there is no forwarding code path for it to take.
func TestSimpleQueryRejectedOnExtendedOnlyGateway(t *testing.T) {
	env := requireIntegrationEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cfg, err := pgx.ParseConfig(env.driverDSN)
	if err != nil {
		t.Fatalf("parse driver DSN: %v", err)
	}
	cfg.MinProtocolVersion = "3.0"
	cfg.MaxProtocolVersion = "latest"
	cfg.RuntimeParams["application_name"] = uniqueName("pgxcompat_simple")
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect through gateway with simple-protocol mode: %v", err)
	}
	defer conn.Close(context.Background())

	_, err = conn.Exec(ctx, "SELECT 1")
	if err == nil {
		t.Fatalf("expected the Extended-only gateway to reject a Simple Query message")
	}

	// The connection must be terminated - not merely have returned one
	// query error while otherwise remaining usable.
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pingCancel()
	if pingErr := conn.Ping(pingCtx); pingErr == nil {
		t.Fatalf("expected the connection to be terminated after the rejected Simple Query, but Ping succeeded")
	}
}

# Mixed Simple Query / Extended Query Routing

## Status

**Proposed — not implemented.** This document specifies the design for
allowing one authenticated PostgreSQL connection to alternate between the
Simple Query Protocol and the Extended Query Protocol. No production Go
code changes accompany this document. `protocol.query_mode` does not exist
in `internal/config` yet; `cmd/gateway/main.go` still dispatches only
between `runSimpleConnection` and `runExtendedConnection`. Nothing in this
document should be read as a claim that pgx's `Ping`, zero-argument `Exec`,
or convenience transaction methods (`Begin`/`Commit`/`Rollback`) work
against SentinelDB today — see
[docs/postgresql-protocol.md](../postgresql-protocol.md#pgxs-ping-and-tx-api-are-currently-incompatible-with-extended-only-mode)
for the current, verified state, which this design intends to change in a
later, separately reviewed and committed implementation.

This document follows the review discipline established by
[docs/design/0001-extended-query.md](0001-extended-query.md) and its
[review checklist](0001-extended-query-review-checklist.md): every claim
about current behavior cites a real file/type/method; every claim about
PostgreSQL protocol behavior cites the official documentation
(`https://www.postgresql.org/docs/current/protocol-*.html`); every claim
about pgx behavior cites the pinned `github.com/jackc/pgx/v5 v5.10.0`
source used by `integration/pgxcompat` (see
`integration/pgxcompat/go.mod`). Design decisions are made explicitly, not
deferred with "TBD."

## Terminology

- **Sub-protocol**: either the PostgreSQL Simple Query Protocol (a single
  `Query` message per request) or the Extended Query Protocol
  (`Parse`/`Bind`/`Describe`/`Execute`/`Close`/`Flush`/`Sync`).
- **Cycle**: an Extended Query pipeline unit delimited by `Sync`, as
  modeled by `protocol.CycleID`/`protocol.State.CurrentCycle()` (see
  [Current architecture](#current-architecture)).
- **Simple Query response**: the full backend message sequence produced
  for one `Query` message, ending in exactly one `ReadyForQuery` (see
  [Simple Query response grammar](#simple-query-response-grammar)).
- **Clean boundary**: the connection-wide condition under which a
  sub-protocol transition is permitted in this design — defined precisely
  in [Chosen architecture](#chosen-architecture).
- **Mixed mode**: the new, opt-in `protocol.query_mode: mixed`
  configuration this document proposes.
- **Legacy modes**: `simple_only` (today's default,
  `runSimpleConnection`) and `extended_only` (today's opt-in,
  `runExtendedConnection`) — both preserved unchanged.

## Current architecture

This section states only verifiable, current behavior. Every symbol below
exists in the repository as of commit `0d9505c` (branch
`feature/mixed-query-routing`, merge of PR #12).

### Connection dispatch (`cmd/gateway/main.go`)

`handleConn` (`cmd/gateway/main.go:271`) dials the upstream once, registers
both `net.Conn`s in `activeConns`, then dispatches on
`cfg.Protocol.ExtendedQueryEnabled`: `runExtendedConnection` or
`runSimpleConnection`. There is no third path today.

- `runSimpleConnection` (`cmd/gateway/main.go:303`) constructs a
  `protocol.SerializedWriter` client writer, a `protocol.TxState`, a
  `firewall.Gate` (client → server), and a `masking.Transformer` (server →
  client), and runs `gate.Run(client)` and `transformer.Run(target)` in two
  goroutines joined by a `sync.WaitGroup`.
- `runExtendedConnection` (`cmd/gateway/main.go:438`) calls
  `gateway.RunStartupHandoff`, then constructs one fresh `protocol.State`,
  one `gateway.ExtendedRuntime` (via `NewExtendedRuntimeWithMasking` when
  masking is enabled, else `NewExtendedRuntime`), one
  `firewall.ExtendedFrontend`, starts `rt.Run(ctx)` in a goroutine, waits
  on `rt.WaitStarted(ctx)`, and only then calls
  `(&firewall.Gate{}).RunExtended(ctx, client, frontend)`.

Both paths share `gateway.RunStartupHandoff` conceptually (only
`runExtendedConnection` currently calls it — `runSimpleConnection` relays
startup/authentication inline via `firewall.Gate.Run`'s own
`protocol.NewClientDecoder`, which begins in `phaseStartup`). This is
addressed in [Configuration and migration behavior](#configuration-and-migration-behavior).

### Simple-only path

- `internal/firewall/gate.go`'s `Gate` owns one `protocol.Decoder`
  (`protocol.NewClientDecoder`), evaluates `MsgQuery` (and rejects every
  Extended Query message type via `isExtendedProtocolMessage` +
  `rejectExtendedProtocol`, fail-closed, `ErrUnsupportedProtocol`), and
  writes either the allowed raw bytes to `target` or a synthetic
  `ErrorResponse` + `ReadyForQuery` (via `protocol.BuildErrorResponse` /
  `protocol.BuildReadyForQuery`) to `respond` on `Block`.
  `Gate.readyForQueryStatus()` reads `*protocol.TxState` (default `'I'` if
  unset).
- `internal/masking/transformer.go`'s `Transformer` owns one
  `protocol.Decoder` (`protocol.NewServerDecoder`), tracks exactly one
  active `RowMaskPlan` (`t.plan`, cleared on `MsgCommandComplete` /
  `MsgErrorResponse` / `MsgReadyForQuery` — see `clearResultSet`,
  `transformer.go:178`), updates the shared `*protocol.TxState` from every
  real `ReadyForQuery`'s status byte, and fails closed on COPY responses
  (`MsgCopyInResponse`/`MsgCopyOutResponse`/`MsgCopyBothResponse`).
- `internal/masking/row_mask.go`'s `MaskDataRow(ctx, masker, plan, frame,
  hooks) ([]byte, bool, error)` is a pure, I/O-free function: validates a
  complete `DataRow` frame, skips `NULL` cells, fails closed
  (`ErrRowMaskBinaryTarget`) on a binary-format target cell, calls
  `Masker.Mask` only for configured target columns, and rebuilds the frame
  via `protocol.DataRow.WithCell`/`Build` only if changed. `Transformer`
  and `gateway.ExtendedRuntime` (see below) both already call this same
  function — it is already the shared masking core this design reuses for
  Simple Query.

### Extended-only path

- `internal/protocol/extended_state.go`'s `State` is a connection-local,
  single-goroutine, I/O-free model of prepared statements, portals, a FIFO
  pending-operation queue, and Sync-delimited cycles. Every query/create/
  apply method returns an independent deep copy (never an internal
  pointer or aliased slice — see the file's own "Değişmezlik" contract).
  Relevant to this design specifically:
  - `ApplyAllowedSimpleQuery()` **already exists and is currently
    unused by any live code path**. Its documented effect: immediately
    clears `unnamedStatementCurrent`/`unnamedPortalCurrent` to
    `NoGeneration` (named objects untouched), then runs internal cleanup.
    This is exactly the PostgreSQL rule quoted in
    [Protocol requirements](#protocol-requirements) below. This design
    reuses it as-is.
  - `TransactionStatus() byte` returns the last status byte applied via
    `ApplyReadyForQuery`. `ApplyReadyForQuery(status byte) (CycleID,
    error)` requires a pending `OpSync` head and a non-empty
    `outstandingSyncCycles` queue — it is Extended-cycle-specific and is
    **not** reusable as-is for a Simple Query's `ReadyForQuery`, which has
    no `Sync`/pending-operation identity. [State lifecycle across
    sub-protocols](#transaction-state-behavior) proposes a new,
    additive method for this.
  - `OperationKind` has exactly 8 values today (`OpParse` through
    `OpSync`, `iota+1`-based) — no Simple-Query-specific kind exists.
- `internal/protocol/extended_correlation.go`'s `BackendCorrelator` and
  `internal/protocol/extended_sequence.go`'s `ResponseSequencer` are both
  pure, I/O-free, single-goroutine components with no Simple-Query
  awareness — every validated backend message type is one of the 8
  `OperationKind`-correlated types or the three async types
  (`NoticeResponse`/`ParameterStatus`/`NotificationResponse`).
- `internal/gateway/extended_runtime.go`'s `ExtendedRuntime` is the single
  event-driven owner of `protocol.State`, the `ResponseSequencer`, the
  backend transport, and the client transport, for one connection.
  `Run(ctx)` starts exactly two goroutines (a backend reader,
  `runBackendReader`, and a shutdown watcher) and runs its own event loop
  (`loop`) directly in the calling goroutine. The **only** function that
  ever writes client-bound bytes is `processActions`
  (`extended_runtime.go:1709`) — every frontend-event handler and the
  backend-message path funnel through it. The registration-before-
  forwarding atomic operation is `RegisterAndForwardFrontendOperation`
  (`extended_runtime.go:1114`): validate frame → (masking preflight, if
  `OpExecute`) → `createStateOperation` (`State.Create*`) →
  `seq.AddForwardedOperation` → (masking plan commit, if applicable) →
  `processActions` → `writeAll(r.backend, frame)` → ack. A failure after
  `State.Create*` succeeds is always fail-closed permanent termination
  (`ErrFrontendRegistrationDiverged` or `ErrBackendWriteFailed`) — no
  rollback is ever attempted.
- `internal/masking/extended.go`'s `ExtendedTracker` is a second,
  independent, I/O-free, single-goroutine-owned component (generation-ID-
  keyed, never name-keyed) that caches per-generation `RowDescription`
  shape and per-portal committed `RowMaskPlan`s. `ExtendedRuntime`'s event
  loop calls it from exactly three points: preflight (before
  `State.CreateExecute`, only for `OpExecute`), plan commit (after
  `AddForwardedOperation` succeeds), and `applyMasking`
  (`extended_runtime.go:1744`, dispatched from `processActions` for
  `ActionEmitBackendFrame` actions).
- `internal/firewall/extended_frontend.go`'s `ExtendedFrontend` runs in
  `Gate.RunExtended`'s **own goroutine** — a different goroutine from
  `ExtendedRuntime`'s event loop, connected only through
  `ExtendedRuntime`'s public, channel-backed API
  (`RegisterAndForwardFrontendOperation`, `SubmitSyntheticErrorForCurrentCycle`,
  `ForwardFlush`, `ForwardTerminate`, `NotifyFrontendClosed`). It owns
  `discardCycle` (client-facing discard-until-`Sync`) as **frontend-local**
  state — explicitly documented as owned exclusively by this one goroutine,
  never inferred by `ExtendedRuntime`. Discard begins the instant a local
  rejection's synthetic error is *submitted* (accepted by the runtime),
  not when its bytes become client-visible. `Sync` and `Terminate` are
  always processed regardless of discard state; every other Extended
  message type is silently dropped, before its typed body parser is ever
  invoked, while discarding.
- `internal/protocol/decoder.go`'s
  `NewSteadyStateFrontendFrameDecoder` validates **only** tag+length
  framing for the client → server direction post-authentication — it
  never invokes the typed Extended body parsers (that is
  `ExtendedFrontend`'s job, deliberately, so a malformed body while
  discarding never becomes a decoder-level fatal error). This decoder is
  reused unchanged by this design (see
  [Mixed frontend state machine](#frontend-state-machine)).

### Startup and cancellation

`internal/gateway/startup_handoff.go`'s `RunStartupHandoff(ctx, client,
backend, limits) (StartupResult, error)` exclusively owns both transports
until authentication's first real `ReadyForQuery` (or a `CancelRequest`,
returned as `StartupResult{CancelOnly: true}`, forwarded once with no
runtime constructed). It performs no policy evaluation, no masking,
constructs no `protocol.State`/runtime, and transparently relays both
protocol 3.0's fixed 4-byte and protocol 3.2's variable-length (4–256
byte) `BackendKeyData`/`CancelRequest` secret keys without branching on
version. This is unconditionally reused, unchanged, by mixed mode — see
[Configuration and migration behavior](#configuration-and-migration-behavior).

### Configuration (`internal/config/config.go`)

```go
type ProtocolConfig struct {
    ExtendedQueryEnabled bool `yaml:"extended_query_enabled"`
}
```

`Config.Load` uses a `yaml.Decoder` with `KnownFields(true)` — any
unrecognized YAML key at any level fails loading with an explicit error
(confirmed by `TestLoad_UnknownTopLevelFieldIsRejected`,
`TestLoad_UnknownNestedFieldIsRejected`,
`TestLoad_ProtocolUnknownFieldIsRejected` in
`internal/config/config_test.go`). The zero value (`false`) is the
default and is indistinguishable, by a plain `bool`, from an explicit
`extended_query_enabled: false` — this distinction matters for the new
field's ambiguity detection (see
[Configuration and migration behavior](#configuration-and-migration-behavior)).

### pgx v5.10.0: `Ping`, zero-argument `Exec`, and `Tx`

Verified against the pinned `github.com/jackc/pgx/v5 v5.10.0` source
(`integration/pgxcompat/go.mod`), and already documented in
[docs/postgresql-protocol.md](../postgresql-protocol.md#pgxs-ping-and-tx-api-are-currently-incompatible-with-extended-only-mode):

- `(*pgconn.PgConn).Ping` (`pgconn/pgconn.go`) is
  `func (pgConn *PgConn) Ping(ctx context.Context) error { return
  pgConn.Exec(ctx, "-- ping").Close() }` — `pgconn.PgConn.Exec` always
  issues a raw Simple Query (`'Q'`) message; there is no Extended option
  at that layer.
- `(*pgx.Conn).exec` (`conn.go`) contains: `// Always use simple protocol
  when there are no arguments. if len(arguments) == 0 { mode =
  QueryExecModeSimpleProtocol }` — this overrides any explicitly-requested
  `QueryExecMode` when the call has zero bind arguments. `(*pgx.Conn).Query`
  has no equivalent override (`QueryExecModeCacheStatement`, the default,
  is used regardless of argument count) — this asymmetry is why
  `integration/pgxcompat`'s existing suite already uses `Query`, never
  `Exec`, for zero-argument statements against the Extended-only gateway
  (see `execExtended` in `integration/pgxcompat/helpers_test.go`).
- `(*pgx.Conn).BeginTx` (`tx.go`) calls `c.Exec(ctx, txOptions.beginSQL())`
  — `beginSQL()` returns the literal string `"begin"` with **zero**
  arguments, so this always triggers the same Simple-Query override.
  `(*dbTx).Commit`/`Rollback` similarly call `tx.conn.Exec(ctx,
  "commit")`/`"rollback"` with zero arguments.

Given these three facts, `simple_only` and `mixed` modes are the **only**
modes under which pgx's `Ping`, zero-argument `Exec`, and convenience `Tx`
API can succeed, because all three unconditionally emit a Simple Query
message that `extended_only` mode's `ExtendedFrontend` rejects fail-closed
by design (see [Alternatives considered](#alternatives-considered),
"treating Query as an ordinary Extended operation" — not chosen; the
Extended-only rejection is retained unchanged).

## Problem statement

`extended_only` mode proves the Extended Query Protocol works end to end,
but real drivers do not use Extended Query exclusively — pgx v5.10.0
issues plain Simple Query messages for `Ping` and any zero-argument
`Exec`/`Tx`-control statement, unconditionally, with no configuration
available to change this. An application using pgx against
`extended_only` SentinelDB today must avoid `Ping` entirely and hand-roll
transaction control as explicit `Query`/`Exec` statements — see
`integration/pgxcompat/transaction_test.go`'s and `connection_test.go`'s
existing workarounds. This is a real, current limitation, not a
hypothetical one: it was discovered, not assumed, by the pgx compatibility
suite in the previous branch.

SentinelDB needs a connection-wide operating mode in which an ordinary,
unmodified driver's normal mixture of Simple Query (health checks,
transaction control) and Extended Query (parameterized/prepared
statements) calls both work, on the same authenticated connection,
without:

- running two independent, transport-owning components concurrently
  (`firewall.Gate.Run`+`masking.Transformer.Run` and `ExtendedRuntime`)
  on the same `net.Conn` pair;
- silently downgrading Extended-only's policy/masking/state guarantees;
  or
- introducing response-ordering ambiguity between the two sub-protocols'
  independently-designed response grammars.

## Goals

1. One connection completes `RunStartupHandoff` exactly once, shared
   identically across all three modes.
2. After authentication, in `mixed` mode, the same connection may send
   Simple Query messages and Extended Query messages, one sub-protocol
   fully resolved before the other begins (see
   [Chosen architecture](#chosen-architecture) for the exact boundary
   rule).
3. pgx v5.10.0's `Ping`, zero-argument `Exec`, and convenience `Begin`/
   `Commit`/`Rollback` succeed against `mixed` mode, proven by real,
   updated `integration/pgxcompat` tests against PostgreSQL 16 and 18
   (design only in this document; implementation in a later stage).
4. Existing parameterized/prepared-statement/masking/policy/cancellation
   behavior is provably unchanged in `simple_only` and `extended_only`
   modes, and semantically equivalent (same policy contract, same masking
   guarantees, same fail-closed categories) in `mixed` mode.
5. Exactly one goroutine owns `protocol.State`, exactly one owns response
   sequencing/ordering, exactly one writes to the client, exactly one
   writes to the backend, at all times, in all three modes.
6. Every locally-rejected or protocol-violating case has a precisely
   defined, fixed, safe error category, a defined connection-fatal-or-
   recoverable classification with justification, and a defined effect
   (or non-effect) on `protocol.State`.

## Non-goals

Explicitly out of scope for this design and for its first implementation:

- **Arbitrary cross-sub-protocol pipelining.** A client may not send a
  Simple `Query` while earlier Extended work (any pending operation or
  outstanding cycle) is still unresolved, nor send Extended messages
  while a Simple Query response is outstanding. See
  [Chosen architecture](#chosen-architecture) and
  [The supported mixed-routing boundary](#the-supported-mixed-routing-boundary-model-b-chosen).
- **SQL AST parsing.** Policy evaluation remains `sqlmatch`-based text
  matching (`firewall.DenyKeywords`) or the equivalent Wasm plugin
  contract — unchanged, including its documented false-positive/false-
  negative limitations.
- **Automatic protocol-mode detection** from the first steady-state
  message. The mode is selected once, at connection-handling time, from
  configuration — never inferred from traffic.
- **TLS, `COPY`, and reconnection-based sub-protocol switching.** All
  three remain unimplemented/unsupported, exactly as in the two existing
  modes.
- **Splitting a multi-statement Simple `Query` message into independent
  policy decisions.** One `Query` message receives exactly one policy
  evaluation, exactly as `firewall.DenyKeywords` already implements for
  both `MsgQuery` and `MsgParse` today.
- **Claiming compatibility with any driver other than pgx v5.10.0.**
  psycopg, JDBC, Npgsql, Prisma, and other drivers/ORMs remain untested by
  this design.
- **New production Prometheus metrics.** See
  [Metrics behavior](#metrics-behavior).
- **Finalizing exact numeric resource limits.** See
  [Resource limits](#resource-limits) — defaults are proposed, but, as in
  0001, are not treated as final tuning until implementation.

## Protocol requirements

Authoritative source: `https://www.postgresql.org/docs/current/protocol-flow.html`
and `https://www.postgresql.org/docs/current/protocol-message-formats.html`.
Quotations below are verbatim.

- **Simple Query, multiple statements**: "Since a query string could
  contain several queries (separated by semicolons), there might be
  several such response sequences before the backend finishes processing
  the query string." Each statement produces `RowDescription`→`DataRow*`→
  `CommandComplete` (row-returning) or just `CommandComplete`
  (non-row-returning); the whole message ends in exactly one
  `ReadyForQuery`.
- **Simple Query, empty string**: "If a completely empty (no contents
  other than whitespace) query string is received, the response is
  `EmptyQueryResponse` followed by `ReadyForQuery`."
- **Simple Query, error abort**: "In the event of an error, `ErrorResponse`
  is issued followed by `ReadyForQuery`. All further processing of the
  query string is aborted by `ErrorResponse` (even if more queries
  remained in it). Note that this might occur partway through the
  sequence of messages generated by an individual query."
- **Unnamed statement/portal destruction by Simple Query** (the exact
  rule `State.ApplyAllowedSimpleQuery()` already implements): "An
  unnamed prepared statement lasts only until the next Parse statement
  specifying the unnamed statement as destination is issued. (Note that a
  simple Query message also destroys the unnamed statement.)" and "An
  unnamed portal is destroyed at the end of the transaction, or as soon
  as the next Bind statement specifying the unnamed portal as destination
  is issued. (Note that a simple Query message also destroys the unnamed
  portal.)"
- **Named portal lifetime**: "If successfully created, a named portal
  object lasts till the end of the current transaction, unless explicitly
  destroyed." Named prepared statements are not transaction-scoped (only
  `Close` or session end destroys them) — an existing, already-correctly-
  modeled distinction in `State` (statements are never invalidated by
  `ApplyReadyForQuery`, only portals are, per its own doc comment quoted
  in [Current architecture](#current-architecture)).
- **`ReadyForQuery` status byte**
  (`protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS`): "Current
  backend transaction status indicator. Possible values are `'I'` if idle
  (not in a transaction block); `'T'` if in a transaction block; or `'E'`
  if in a failed transaction block (queries will be rejected until block
  is ended)." Identical semantics to `protocol.TxStatusIdle`/
  `InTransaction`/`FailedTransaction` already defined in
  `internal/protocol/txstate.go`.
- **`CancelRequest`**: "the frontend opens a new connection to the server
  and sends a CancelRequest message, rather than the StartupMessage
  message... For security reasons, no direct reply is made to the cancel
  request message." Unchanged by this design — see
  [Error, shutdown and cancellation behavior](#error-and-shutdown-behavior).
- **`PortalSuspended`**: "Note this only appears if an Execute message's
  row-count limit was reached." Simple Query has no `Execute`/row-limit
  concept — `PortalSuspended` observed during a Simple Query response is
  therefore structurally impossible for a genuine backend and is treated
  as a protocol violation (see
  [Simple Query response grammar](#simple-query-response-grammar)).

## Chosen architecture

**One mixed steady-state frontend feeding one unified runtime event
loop**, matching the task's stated likely architecture, because the
alternative (two independently transport-owning components switching
control of the same `net.Conn` pair) cannot satisfy Goal 5 without a
hand-rolled hand-off protocol strictly more complex, and strictly less
tested, than extending the existing single-writer, single-reader
`ExtendedRuntime`.

The unified runtime is `gateway.ExtendedRuntime` itself, **extended in
place** (not replaced, not wrapped by a second competing runtime type),
because:

1. It already owns the single client writer (`processActions`), the
   single backend writer/reader pair, and `protocol.State`, satisfying
   four of the six ownership invariants in
   [Preserve one steady-state transport owner](#ownership-model)
   before any change.
2. `protocol.State.ApplyAllowedSimpleQuery()` already exists,
   already implements the correct PostgreSQL rule, and already lives in
   the same package the runtime already depends on.
3. `masking.MaskDataRow` is already I/O-free and reused, unchanged, by
   both `Transformer` and `ExtendedRuntime` today — a Simple Query masking
   path needs no new masking primitive, only a new call site.

### The supported mixed-routing boundary model: B (chosen)

**Option B — ReadyForQuery-boundary alternation** is chosen over Option A
(full cross-sub-protocol pipelining), because:

- Option A requires a genuinely unified response-plan queue capable of
  interleaving Simple Query's linear, single-active-result-set grammar
  with Extended Query's FIFO, multi-cycle-pipelined, generation-keyed
  grammar, inside the response ordering guarantees `ResponseSequencer`
  already provides for Extended alone. No existing SentinelDB component
  models this; building and proving it correct is a substantially larger,
  higher-risk change than this stage should attempt first ("prioritize
  correctness over arbitrary cross-protocol pipelining" — task
  instruction, [Define the supported mixed-routing boundary](#the-supported-mixed-routing-boundary-model-b-chosen)).
- Option B, in contrast, is provably safe using **only additive**
  changes: because a `Query` is accepted only when
  `protocol.State.PendingOperationCount() == 0 &&
  protocol.State.OutstandingCycleCount() == 0`, and an Extended message
  is accepted only when no Simple Query response is outstanding, the two
  response-tracking subsystems (`ResponseSequencer`/`BackendCorrelator`
  for Extended, a new `SimpleQueryTracker` for Simple) are **never
  concurrently active**. There is exactly one active response-tracking
  subsystem at any instant, selected by one runtime-owned boolean. This
  eliminates, by construction, the response-ordering ambiguity Option A
  would have to solve directly.
- Real, well-behaved drivers (including pgx, and every acceptance
  criterion in [pgx compatibility acceptance criteria](#pgx-compatibility-acceptance-criteria))
  never pipeline a new top-level request ahead of a previous one's
  response on the same connection — Option A's extra generality is not
  needed to satisfy Goal 3.

#### Exact clean-boundary predicate

A **clean boundary** exists, for a given `mixed`-mode connection, at any
instant where **all** of the following hold, evaluated **inside the
runtime's single event-loop goroutine** (never inferred by the frontend
goroutine, which cannot safely read `protocol.State` or the runtime's
internal flags without a data race):

1. `state.PendingOperationCount() == 0` (no Extended operation is
   awaiting a backend acknowledgement).
2. `state.OutstandingCycleCount() == 0` (no `Sync` has been forwarded
   without its matching `ReadyForQuery` yet having been applied).
3. `!runtime.simpleQueryActive` (no Simple Query response is currently
   outstanding — a new, runtime-owned `bool` field; see
   [Runtime state machine](#runtime-state-machine)).
4. The frontend is not in Extended discard-until-`Sync` — this condition
   is checked and enforced **entirely on the frontend side** (see
   [Mixed frontend state machine](#frontend-state-machine)); it
   never reaches the runtime's boundary check because a `Query` arriving
   during discard is absorbed by the frontend before any runtime call is
   made (case 2 below).

Because Simple Query is accepted **only** at a clean boundary (condition
1–3, checked inside `ForwardSimpleQuery`'s single event-loop turn — see
[Unified runtime request model](#runtime-state-machine)), and
because a clean boundary requires `OutstandingCycleCount() == 0`, an
**invariant** follows that this design relies on throughout and that Stage
B's tests must verify directly: *at every clean boundary, the Extended
`ResponseSequencer`'s internal plan queue is also empty* — every
previously-registered plan unit is fully drained (its output action
emitted) by the time its cycle's `ReadyForQuery` reaches the client, and
`OutstandingCycleCount() == 0` is exactly the signal that no cycle
remains undrained. This is why a locally-blocked or locally-allowed
Simple Query's response bytes can be written **directly** through the
runtime's single client-writer path (the same `writeAll(r.client, ...)`
helper `processActions` already uses) without needing to be registered in
the Extended sequencer's plan queue at all: nothing else could possibly be
queued ahead of it.

#### What happens when a message arrives outside the boundary

Two distinct cases, deliberately **not** handled identically:

**Case 1 — a `Query`/Extended message arrives during Extended
discard-until-`Sync`.** This is not a new case: it is the *existing*,
already-safe PostgreSQL discard-until-`Sync` recovery window
(`ExtendedFrontend.discardCycle`, unchanged ownership/semantics). This
design extends the existing frontend dispatch (`ExtendedFrontend.handle`'s
`if f.discarding() { return }` branch, `extended_frontend.go:474`) to
**also** cover `MsgQuery` in `mixed` mode: while discarding, an incoming
`Query` frame is silently dropped, before its body is ever parsed —
identically to how `Parse`/`Bind`/`Describe`/`Execute`/`Close`/`Flush`
are already dropped today. No new synthetic error is produced (one was
already produced for the local rejection that started the discard
window); the connection remains open and fully usable once the real
`Sync` arrives. This is **recoverable**, matching the existing rule
exactly, and is the concrete mechanism that guarantees "a `Query` must
not escape the PostgreSQL Extended Query recovery rule by bypassing
`Sync`": a client cannot use `Query` to jump the discard queue.

**Case 2 — a `Query`/Extended message arrives when the boundary is
unclean but discard is *not* active** (i.e., genuinely pipelined,
not-yet-resolved work from the *other* sub-protocol exists). This is
**connection-fatal**, using a new fixed, safe error category,
`ErrMixedBoundaryViolation` (see
[Error, shutdown and cancellation behavior](#error-and-shutdown-behavior)).
Justification:

- There is no safe way to locally synthesize a complete, correctly-
  ordered response for the out-of-boundary message while genuinely
  pending work from the other sub-protocol still owes the client a
  response: inserting a synthetic response *before* that pending work's
  real response would violate byte-order (the client sent this message
  *after* the still-pending one); inserting it *after* would require
  buffering an unbounded amount of held state for a scenario this design
  does not otherwise need to support.
- This exactly matches the **existing** precedent
  `ExtendedFrontend.handle` already applies to `MsgQuery` arriving in
  `extended_only` mode today (`ErrExtendedFrontendUnsupportedMessage`,
  fail-closed, connection terminated, no forwarding) — mixed mode reuses
  the same *category* of response for the same underlying reason (an
  unsupported message shape for the connection's current mode), merely
  with a boundary-sensitive rather than always-on trigger.
- This path is a defensive backstop against a misbehaving or malicious
  client, not a normal operational path: every driver behavior this
  design is required to support (pgx's `Ping`, `Exec`, `Tx`, and ordinary
  parameterized/prepared use — see
  [pgx compatibility acceptance criteria](#pgx-compatibility-acceptance-criteria))
  naturally waits for each request's response before issuing the next
  request on the same connection, and therefore never reaches this path.

Symmetrically, an Extended message (`Parse`/`Bind`/`Describe`/`Execute`/
`Close`/`Flush`/`Sync`) arriving while `runtime.simpleQueryActive` is
`true` is **also** Case 2 — connection-fatal, same category, same
justification, evaluated by the same runtime-side check (see
[Unified runtime request model](#runtime-state-machine)).
`Terminate` is exempt from both cases (see
[Terminate in every state](#terminate-in-every-frontend-and-runtime-state)).

#### Proof: ordinary sequential pgx flows are unaffected

Every flow in
[pgx compatibility acceptance criteria](#pgx-compatibility-acceptance-criteria)
is a strictly sequential request/response sequence on one connection —
`Ping` (Simple), then wait for its result; `Exec`/`Query` (Extended, via
`QueryExecModeCacheStatement`), then wait; `Begin` (Simple `"begin"`),
then wait; a parameterized statement (Extended), then wait; `Commit`
(Simple `"commit"`), then wait. Because pgx's `pgconn.PgConn` is not used
concurrently by application code across goroutines for a single
connection (this is documented pgx usage: one connection is not safe for
concurrent use), and because every one of these calls blocks until its
own response is fully read, the connection is **always** at a clean
boundary before the next call begins. None of Case 1 or Case 2 above is
ever reached by these flows — they only exist to fail closed against
traffic no supported driver flow produces.

The full, explicit evaluation of rejected alternatives (including
sub-options for the runtime/sequencer question) appears in
[Alternatives considered](#alternatives-considered) near the end of this
document.

## Ownership model

Every mutable component in `mixed` mode, and the single goroutine
permitted to access it. "Runtime event-loop goroutine" refers to the same
goroutine that calls `ExtendedRuntime.loop` today (i.e., the goroutine
that calls `Run`, since `loop` is called directly, not spawned — see
[Current architecture](#current-architecture)). "Frontend goroutine"
refers to the goroutine that calls `Gate.RunMixed` (the new entry point,
[Mixed frontend state machine](#frontend-state-machine)) — a
different goroutine from the runtime event loop, exactly as
`Gate.RunExtended`/`ExtendedFrontend` already are today.

| Component | Owner (single goroutine) | Notes |
|---|---|---|
| `protocol.State` | Runtime event-loop | Unchanged from today — Extended-only already enforces this. |
| `protocol.ResponseSequencer` | Runtime event-loop | Unchanged. Active only when `!runtime.simpleQueryActive`. |
| New `protocol.SimpleQueryTracker` | Runtime event-loop | New (Stage A/B). Active only when `runtime.simpleQueryActive`. |
| `runtime.simpleQueryActive` (new field) | Runtime event-loop | Written only inside `ForwardSimpleQuery`'s and the Simple `ReadyForQuery` handler's event-loop turns. |
| `runtime.simpleMaskPlan` (new field, `masking.RowMaskPlan`) | Runtime event-loop | Mirrors `Transformer.plan` exactly — one active plan, no generation keying needed (Simple Query never has concurrent result sets). |
| Backend `net.Conn` (write) | Runtime event-loop | `writeAll(r.backend, ...)` — unchanged single call site pattern. |
| Backend `net.Conn` (read) | Backend-reader goroutine | Unchanged — `runBackendReader`, decodes only, never writes, never touches `State`/sequencer/tracker directly. |
| Client `net.Conn` (write) | Runtime event-loop | `processActions`/`writeAll(r.client, ...)` — unchanged single choke point, now also the sole writer for Simple Query response bytes. |
| Client `net.Conn` (read, steady-state) | Frontend goroutine | `Gate.RunMixed`'s read loop — unchanged pattern from `Gate.RunExtended`. |
| `ExtendedFrontend`/`MixedFrontend.discardCycle` | Frontend goroutine | Unchanged ownership rule; extended in scope to cover `MsgQuery` (Case 1 above). |
| `protocol.TxState` (legacy, atomic-based) | N/A in mixed mode | **Not used.** Mixed mode uses `protocol.State.TransactionStatus()` exclusively (see [Transaction-state behavior](#transaction-state-behavior)) — `protocol.TxState` remains used only by `simple_only` mode, unchanged. |
| Startup/authentication transports | `RunStartupHandoff`'s calling goroutine | Unchanged — exclusive ownership ends before `ExtendedRuntime`/`MixedFrontend` ever touch the transports, exactly as today. |

Invariants preserved (see
[Preserve one steady-state transport owner](#ownership-model)):
exactly one steady-state client reader (frontend goroutine); exactly one
steady-state backend reader (backend-reader goroutine); exactly one
backend writer (runtime event-loop); exactly one client writer (runtime
event-loop, via `processActions`/its Simple Query direct-write
equivalent, both funneling through the same `writeAll(r.client, ...)`
call site family); exactly one owner of `protocol.State` (runtime
event-loop); exactly one owner of response sequencing at any instant
(runtime event-loop, switching between exactly one of two
mutually-exclusive trackers via `simpleQueryActive`); no simultaneous use
of `Gate.Run`+`Transformer.Run` and `ExtendedRuntime` (mixed mode never
constructs `Gate.Run`/`Transformer` — see
[Configuration and migration behavior](#configuration-and-migration-behavior));
no switching between independent socket-processing pipelines (one
`net.Conn` pair, one runtime, for the connection's entire steady-state
lifetime); no direct client write from the frontend policy layer
(`MixedFrontend` never writes to `client`, exactly like `ExtendedFrontend`
today); no direct backend write from multiple frontend handlers (only the
runtime event-loop calls `writeAll(r.backend, ...)`); startup handoff
ownership ends before steady-state ownership begins (unchanged —
`RunStartupHandoff` returns before `MixedFrontend`/`ExtendedRuntime` are
constructed, for all three modes alike).

## Frontend state machine

`MixedFrontend` (new type, `internal/firewall/mixed_frontend.go`) reuses
`NewSteadyStateFrontendFrameDecoder` unchanged (framing-only; typed body
parsing happens per-handler, after the discard decision, exactly as
`ExtendedFrontend` already does — see
[Current architecture](#current-architecture)). It shares its
`Parse`/`Bind`/`Describe`/`Execute`/`Close`/`Flush`/`Sync` handling with
`ExtendedFrontend` via extracted, shared helper functions (see
[Staged implementation plan](#staged-implementation-plan), Stage C) — not
by duplicating that logic, and not by modifying `ExtendedFrontend`'s own
behavior, which remains byte-for-byte unchanged (verified by its existing,
unmodified test suite continuing to pass).

### Dispatch table

| Frontend message | Handling |
|---|---|
| `Query` | New. See [Query handling](#query-handling) below. |
| `Parse`/`Bind`/`Describe`/`Execute`/`Close`/`Flush` | Reused verbatim from `ExtendedFrontend`'s existing handlers, with one added precondition: if a Simple Query response is outstanding (`Case 2`), reject connection-fatally before any body parsing, exactly like discard drops a message before parsing — the distinction is discard drops **silently** (recoverable), this drops with `ErrMixedBoundaryViolation` (connection-fatal). |
| `Sync` | Reused verbatim, with the same added precondition (Case 2 applies; `Sync` while a Simple response is outstanding is nonsensical and rejected the same way). Still always processed (not silently dropped) if the boundary is otherwise clean, per the existing "Sync/Terminate always processed regardless of discard" rule. |
| `Terminate` | Reused verbatim — always processed in every state, discard or not, Simple-response-outstanding or not. See [Terminate in every state](#terminate-in-every-frontend-and-runtime-state). |
| Unsupported COPY frontend messages (`CopyData`/`CopyDone`/`CopyFail`) | Reused verbatim from `ExtendedFrontend`'s existing unsupported-message fail-closed path (`ErrExtendedFrontendUnsupportedMessage`, generalized name for mixed mode — see below). |
| `FunctionCall` | Same — unsupported, fail-closed, unchanged category. |
| Unknown message types | Same — unsupported, fail-closed, unchanged category. |
| Malformed frames | `NewSteadyStateFrontendFrameDecoder`'s framing-only decode error — unchanged, `ErrExtendedFrontendDecodeFailed`-equivalent (renamed `ErrMixedFrontendDecodeFailed` for mixed mode's own sentinel, same semantics). |
| EOF / read failure | Unchanged pattern from `Gate.RunExtended`/`ExtendedFrontend.closeClean`/`closeTruncated`/`closeReadError`. |
| Global shutdown | Unchanged — parent context cancellation closes both transports via the runtime's existing shutdown watcher; `MixedFrontend`'s read loop observes the resulting read error exactly as `ExtendedFrontend`'s does today. |

### Query handling

```
1. NewSteadyStateFrontendFrameDecoder emits Message{Type: MsgQuery, Raw: <framing-validated bytes>}.
2. If f.discarding(): silently drop (Case 1). Return.
3. Parse the Query body: require exactly one NUL-terminated query string,
   reject a missing terminator, reject any trailing byte after the
   terminator (mirrors protocol.trimNullTerminator's existing framing but
   with an explicit trailing-byte check this design adds — see
   Protocol Requirements below and the frame-size limit already enforced
   by NewSteadyStateFrontendFrameDecoder's shared MaxFrontendFrameBytes
   check). On failure: build a fixed ErrMalformedSimpleQueryFrame
   synthetic response (see Error categories) — SQL is never included,
   the frame is never forwarded, and (per the "recoverable Parse-body-
   malformed" precedent) this is a LOCAL, recoverable rejection: reply
   with a synthetic ErrorResponse+ReadyForQuery pair built exactly like
   case 3b-blocked below, using the runtime's RejectSimpleQuery path (no
   discard follows, since Simple Query has no Sync to recover at) and
   return.
4. Evaluate exactly once: verdict, reason := policy.Evaluate(protocol.Message{
   Type: protocol.MsgQuery, Query: queryText}) — the identical call
   Gate.handle already makes today for Simple-only mode, and the
   identical Policy implementation (firewall.DenyKeywords already
   special-cases both MsgQuery and MsgParse in one code path — no Policy
   change required).
5. queryText is now out of scope for retention: it existed only on this
   goroutine's call stack for step 3-4 and is not passed into any
   long-lived structure — see Privacy and logging guarantees.
6. If Block: call runtime.RejectSimpleQuery(ctx, "42501", reason) — same
   SQLSTATE Gate.handle already uses for a blocked Simple Query today.
   No forwarding. Return.
7. If Allow: call runtime.ForwardSimpleQuery(ctx, m.Raw) — the runtime
   performs its own authoritative boundary re-check (do not let the
   frontend infer boundary state independently) as the first step inside
   this call; if it reports ErrMixedBoundaryViolation, the frontend
   terminates the connection with that fixed category (Case 2 — this is
   the actual enforcement point for "Query outside the permitted
   boundary" when NOT arriving during discard, since the frontend itself
   has no reliable way to know PendingOperationCount()/
   OutstandingCycleCount()/simpleQueryActive without asking the runtime).
   Otherwise, on success, the frontend has nothing further to do — the
   runtime owns delivering the entire response.
```

### Frontend-local vs. runtime-authoritative state

The frontend tracks **only**:

- `discardCycle` (Extended discard-until-`Sync`, unchanged ownership,
  scope extended to cover `MsgQuery` per Case 1).
- `terminated`/`err` (its own terminal state, unchanged pattern from
  `ExtendedFrontend`).

The frontend does **not** track, and must never infer: whether a clean
boundary currently exists, whether a Simple Query response is currently
outstanding, or any `protocol.State` count. Every boundary-sensitive
decision (Case 2) is made by the runtime, inside its own event-loop turn,
and reported back to the frontend as a definitive success/failure — this
satisfies "do not let the frontend infer boundary state independently"
literally: there is no frontend-side boundary predicate to get out of
sync with the runtime's.

### Named frontend states (for documentation purposes only — not a second State machine)

These are the frontend's own possible **local** states, useful for
reasoning about `MixedFrontend.handle`'s behavior, not a duplicate model
of runtime/backend state:

1. **Clean** — not discarding, no local rejection pending. Default state.
2. **Extended-cycle-pipelining** — the frontend has forwarded (or is
   forwarding) Extended messages; it has no local record of *how many*
   cycles are outstanding (that is `State.OutstandingCycleCount()`,
   runtime-owned) — from the frontend's point of view this looks
   identical to "Clean," since the frontend's own dispatch does not
   change behavior based on Extended pipelining depth (this is unchanged
   from `ExtendedFrontend` today).
3. **Discarding** (`discardCycle != protocol.NoCycle`) — absorbing
   `Query`/`Parse`/`Bind`/`Describe`/`Execute`/`Close`/`Flush` until
   `Sync`.
4. **Stopping/Stopped** — `terminated == true`; no further messages are
   dispatched.

### Query behavior while discarding

Specified in [Case 1](#what-happens-when-a-message-arrives-outside-the-boundary)
above: silently dropped, no synthetic error, connection remains alive,
`Sync` still required to clear discard (unchanged mechanism — discard
clears the instant a real `Sync` is successfully registered/forwarded,
exactly as `ExtendedFrontend.handleSync` already implements).

### Terminate in every frontend and runtime state

| State | `Terminate` behavior |
|---|---|
| Clean | Forwarded immediately via `ForwardTerminate` (unchanged). |
| Extended cycle pipelining | Same — unaffected by outstanding cycles. |
| Extended discard-until-`Sync` | Same — explicitly exempted from discard suppression (unchanged existing rule). |
| Simple Query response outstanding | **New, but same treatment**: forwarded immediately. The runtime's `ForwardTerminate` does not consult `simpleQueryActive` — ending the connection takes precedence over waiting for a Simple response to finish, matching the existing "Terminate needs no acknowledgement, ends the connection immediately" rule (`ForwardFlush`/`ForwardTerminate` never touch `State`/sequencer). |
| Stopping/Stopped | No-op — the frontend/runtime are already tearing down. |

## Runtime state machine

`ExtendedRuntime` gains, additively (no existing field/method changes):

```go
// New fields (illustrative; exact names/placement are an implementation
// detail of Stage B, not fixed by this document beyond their semantics).
simpleQueryActive bool                 // event-loop-owned only
simpleMaskPlan    masking.RowMaskPlan  // event-loop-owned only; mirrors Transformer.plan
simpleTracker     *protocol.SimpleQueryTracker // constructed once, reused across Simple Query cycles (reset, not reallocated, at cycle start/end)
```

### New/extended runtime methods

```go
// ForwardSimpleQuery mirrors RegisterAndForwardFrontendOperation's
// validate -> mutate -> forward -> ack sequence, specialized for Simple
// Query (no State.Create*/sequencer registration — see rationale above).
func (r *ExtendedRuntime) ForwardSimpleQuery(ctx context.Context, frame []byte) error

// RejectSimpleQuery synthesizes and writes ErrorResponse+ReadyForQuery
// for a locally blocked or malformed Simple Query, using
// protocol.State.TransactionStatus() for the ReadyForQuery status byte.
// No State mutation occurs (mirrors the existing "a blocked Parse/Query
// never calls a State.Create* method" rule).
func (r *ExtendedRuntime) RejectSimpleQuery(ctx context.Context, sqlState, reason string) error
```

Both follow `submit`'s existing enqueue/ack contract (`extended_runtime.go:1235`)
unchanged: a caller's context is only consulted before the event is
enqueued; once enqueued, the caller is guaranteed either a definitive ack
or `ErrRuntimeStopped` — never an ambiguous `ctx.Err()` for a possibly-
in-flight event. This reuses the existing `frontendEvent`/`submit`
machinery with two new `frontendEventKind` values (illustrative:
`frontendEventForwardSimpleQuery`, `frontendEventRejectSimpleQuery`),
handled by two new, symmetric handler functions inside the same `loop`
dispatch switch that already handles `handleFrontendRegister`,
`handleFrontendSynthetic`, etc.

### `ForwardSimpleQuery`'s exact atomic sequence (event-loop turn)

```
1. Validate frame: tag == MsgQuery, well-formed per
   NewSteadyStateFrontendFrameDecoder's already-applied framing (this is
   a second, defensive structural check mirroring
   validateFrontendOperationFrame's existing pattern — frame size bounded
   by the SAME RuntimeLimits.MaxFrontendFrameBytes already used for
   Extended frames, no new limit type). On failure: ack error, no
   mutation, no forward. (ErrInvalidFrontendFrame-equivalent.)
2. Boundary check (see the exact predicate above): if
   state.PendingOperationCount() != 0 || state.OutstandingCycleCount() != 0
   || r.simpleQueryActive: ack ErrMixedBoundaryViolation, no mutation, no
   forward, and the CALLER (MixedFrontend) is responsible for treating
   this as connection-fatal (Case 2) — the runtime itself does not
   unilaterally terminate here, mirroring how ErrExtendedMaskingPreflightRejected
   is a caller-classified recoverable/fatal decision today, not a
   runtime-classified one, EXCEPT this one is always fatal per the
   frontend's own dispatch rule stated above (no ambiguity is
   introduced — the classification is fixed by this design, only the
   mechanical "who calls Close()" step is the frontend's, exactly as it
   already is for every other ExtendedFrontend-detected fatal condition).
3. state.ApplyAllowedSimpleQuery() — unconditional, matches the official
   rule quoted in Protocol requirements. This call cannot fail (existing
   signature: no return value).
4. r.simpleQueryActive = true; r.simpleMaskPlan = masking.RowMaskPlan{}
   (fresh); r.simpleTracker.Reset() (new cycle).
5. writeAll(r.backend, frame). On failure: wrap as ErrBackendWriteFailed
   (existing sentinel, reused as-is) and permanently fail-close the
   runtime — State already mutated (step 3), no rollback, matching the
   existing, unconditional "no speculative rollback of runtime state"
   rule this design must preserve (task requirement, Unified runtime
   request model).
6. Ack success.
```

### `RejectSimpleQuery`'s exact atomic sequence (event-loop turn)

```
1. No frame validation needed (caller already determined rejection
   locally, before ever calling this — e.g. a Policy Block verdict, or a
   malformed Query frame the frontend itself detected).
2. Build protocol.BuildErrorResponse("ERROR", sqlState, reason) — the
   SAME helper Gate.handle's Block branch already uses today. reason is
   always one of a small set of fixed, safe strings (the Policy block
   reason string itself, which - per DenyKeywords's existing contract -
   is already client-facing/safe, containing at most the matched blocked
   phrase, never arbitrary SQL; and fixed internal strings for malformed-
   frame rejection).
3. status := state.TransactionStatus() — the CURRENT authoritative
   status; PostgreSQL never saw this query (it was never forwarded), so
   the real transaction state is provably unchanged, and reusing the
   last-known status is therefore correct, not an approximation.
4. writeAll(r.client, errorResponseBytes) then
   writeAll(r.client, protocol.BuildReadyForQuery(status)) — both via the
   SAME single-writer path processActions already uses (direct call,
   since — per the clean-boundary invariant proven above — nothing else
   can legitimately be queued ahead of this write at a clean boundary).
5. No State mutation (state.ApplyAllowedSimpleQuery() is NEVER called for
   a blocked Query — mirrors the existing "a blocked Parse never calls
   State.CreateParse" rule exactly).
6. Ack success. The connection remains usable — no Sync is required
   (Simple Query has no Sync concept at all), unlike a blocked Extended
   Parse, which enters discard-until-Sync and does not immediately
   synthesize a complete, independent response cycle. See
   Transaction-state behavior for the full contrast.
7. On a client write failure at step 4: ErrClientWriteFailed (existing
   sentinel, reused), permanent fail-closed termination (no State was
   mutated, but the client transport itself is now unreliable — reusing
   the existing terminal-write-failure precedent uniformly).
```

### Backend-message dispatch (event-loop turn, per decoded backend `Message`)

```
if r.simpleQueryActive {
    result, err := r.simpleTracker.Handle(m)   // new, I/O-free, Stage A
    if err != nil {
        // ErrSimpleResponseOrderingViolation-equivalent (see Error categories);
        // permanent fail-closed termination, mirrors
        // ErrBackendProtocolFailure's existing treatment.
    }
    if result.Async {
        writeAll(r.client, m.Raw)   // relayed unchanged, same as today's async handling
        return
    }
    out := m.Raw
    if maskingEnabled {
        out, err = <Simple masking integration — see Simple Query masking
                     inside the unified runtime>
        // on error: same emitMaskingFailureFatal-equivalent pattern,
        // ErrSimpleMaskingFailed (new sentinel, same shape as
        // ErrExtendedMaskingFailed)
    }
    writeAll(r.client, out)
    if result.CycleCompleted {
        status := <the ReadyForQuery status byte just observed>
        if err := state.ApplySimpleQueryReadyForQuery(status); err != nil {
            // structurally unreachable in correct operation (mirrors
            // existing "impossible ordering" defensive-only errors);
            // still a fixed, safe, fail-closed category if ever hit.
        }
        r.simpleQueryActive = false
        r.simpleMaskPlan = masking.RowMaskPlan{}
    }
} else {
    // UNCHANGED existing path:
    actions, err := r.seq.HandleBackendMessage(m)
    ...
}
```

This `if/else` is the **entire** extent of the change to the runtime's
backend-message dispatch — the `else` branch is the existing code,
untouched.

## Response correlation and sequencing

**Chosen: a runtime-owned dispatch flag selecting between two
mutually-exclusive, independently-scoped tracking subsystems** — not a
literal unified plan queue that interleaves Simple and Extended plan
units (rejected; see [Alternatives considered](#alternatives-considered)),
and not forcing Simple Query into the existing `OperationKind`/
`ResponseSequencer` machinery (also rejected — Simple Query's grammar has
no Parse/Bind identity, no generation, and no FIFO multi-operation
correlation need, since it is always exactly one active response at a
time by construction of the boundary rule; contorting it into
`PendingOperation`/`OutputAction` would add complexity without benefit and
risk destabilizing the extensively-tested existing sequencer).

This is possible, safely, **specifically because** Option B (boundary-only
alternation) was chosen in
[Chosen architecture](#chosen-architecture): the two subsystems are never
concurrently active, so there is no interleaving to arbitrate between
them, and no shared plan-queue data structure is needed. If a future
stage ever adopts full cross-sub-protocol pipelining (Option A, currently
rejected), *that* stage would need to revisit this section and design a
genuinely unified plan queue — this document does not attempt to
future-proof for that, per the instruction to prefer correctness over
speculative generality.

### Preserved invariants

- **Frontend registration before upstream forwarding**: preserved for
  both subsystems — `ForwardSimpleQuery` mutates `State`
  (`ApplyAllowedSimpleQuery`) strictly before `writeAll(r.backend, ...)`,
  mirroring `RegisterAndForwardFrontendOperation`'s existing ordering
  exactly.
- **Exact backend response order**: preserved because exactly one
  subsystem is active at a time, and each individually already
  guarantees in-order delivery (`ResponseSequencer`'s existing plan-queue
  ordering for Extended; `SimpleQueryTracker`'s strictly linear one-
  active-response-at-a-time model for Simple, which cannot reorder
  anything since there is never more than one thing in flight).
- **Asynchronous-message forwarding**: `NoticeResponse`/`ParameterStatus`/
  `NotificationResponse` are relayed unchanged in both branches of the
  dispatch — the `if simpleQueryActive` branch's `result.Async` check
  mirrors `ResponseSequencer`'s existing async handling exactly (checked
  before any "unexpected ordering" validation, matching the existing
  Extended precedent explicitly required by
  [docs/design/0001-extended-query-review-checklist.md](0001-extended-query-review-checklist.md)'s
  "Frontend/backend message completeness" section).
- **Synthetic response ordering**: a locally-blocked Simple Query's
  synthetic response is written directly (no queue) at a clean boundary,
  where nothing else can be queued ahead of it (proven above) — ordering
  is trivially correct.
- **Bounded plan memory**: `SimpleQueryTracker` holds O(1) state (no
  growth regardless of how many statement-result groups one `Query`
  message produces — see [Resource limits](#resource-limits)).
  `ResponseSequencer`'s existing `SequencerLimits` are unchanged and
  continue to bound Extended-only plan memory exactly as today.
- **Deterministic terminal state**: unchanged — both subsystems reuse the
  existing runtime-level terminal-state machinery
  (`lifecycle`/`terminalRequested`/`shutdownCause`), no new termination
  path is introduced beyond the new fixed error categories flowing
  through the same existing `loop()` → `markInternalShutdown()` →
  permanent-termination pipeline.
- **No response belonging to the wrong frontend request**: guaranteed by
  mutual exclusion — while `simpleQueryActive`, every backend message
  belongs to the one active Simple Query; while not, every backend
  message is correlated by the unchanged, already-proven `BackendCorrelator`/
  `ResponseSequencer` FIFO logic.
- **No stale Simple response state when switching back to Extended
  mode**: `simpleMaskPlan` is reset to its zero value and
  `simpleQueryActive` is set `false` in the same event-loop turn that
  processes the Simple Query's `ReadyForQuery` (see the dispatch pseudocode
  above) — there is no window in which stale Simple state could be
  consulted by the (about to resume) Extended path, since both are
  updated atomically within one single-threaded event-loop turn.

### Interaction between Extended `Sync`/`ReadyForQuery` and a following Simple Query

1. Client sends `Parse`/`Bind`/`Execute`/`Sync` (Extended cycle N).
2. Runtime processes them via the **unchanged** `ResponseSequencer` path;
   eventually the real `ReadyForQuery` for cycle N arrives,
   `state.ApplyReadyForQuery(status)` is called (unchanged), and
   `OutstandingCycleCount()` returns to 0 (assuming no other cycles are
   pipelined ahead).
3. The connection is now, by definition, at a clean boundary (conditions
   1–2 of the predicate hold; `simpleQueryActive` was already `false`
   throughout, since Extended and Simple are mutually exclusive by
   construction).
4. Client sends `Query`. `MixedFrontend` is not discarding (Case 1 does
   not apply). `ForwardSimpleQuery`'s boundary check (step 2 of its
   sequence) passes. The Simple Query proceeds normally.

### Interaction between a Simple Query's `ReadyForQuery` and a following Extended cycle

1. Client sends `Query`. `ForwardSimpleQuery` succeeds;
   `simpleQueryActive = true`.
2. Backend responds; `SimpleQueryTracker` validates the sequence; the
   real `ReadyForQuery` arrives, `simpleQueryActive` is set back to
   `false` in the same event-loop turn (see dispatch pseudocode above).
3. Client sends `Parse`. `MixedFrontend` dispatches it to the shared
   Extended handler (reused from `ExtendedFrontend`), which calls
   `RegisterAndForwardFrontendOperation` **unchanged** — no new
   precondition is needed here beyond the existing logic, because by the
   time this `Parse` is processed, `simpleQueryActive` is already
   `false` (step 2 already completed in an earlier event-loop turn) and
   `State`'s own pending-operation/cycle bookkeeping is exactly as
   ordinary Extended-only pipelining already handles.

## Simple Query response grammar

New, pure, I/O-free type: `protocol.SimpleQueryTracker`
(`internal/protocol/simple_query.go`, Stage A). Mirrors
`BackendCorrelator`'s design discipline exactly: connection-local, no
I/O, no goroutines, no logging, single-goroutine sequential access only,
never retains SQL/raw frame bytes beyond structural validation.

### States

```go
type simpleQueryPhase int

const (
    // No message processed yet for the current cycle. Valid inputs:
    // RowDescription, CommandComplete, EmptyQueryResponse, ErrorResponse.
    // ReadyForQuery is INVALID here (see "empty query" grammar rule —
    // a bare ReadyForQuery with zero prior messages is impossible for a
    // genuine backend and is rejected, fail-closed, as a protocol
    // violation).
    simplePhaseAwaitingFirstMessage simpleQueryPhase = iota + 1

    // At least one statement-result group has completed (via
    // CommandComplete) OR this is immediately after RowDescription's own
    // group completed. Valid inputs: RowDescription (next group begins),
    // CommandComplete (next, non-row-returning group), ReadyForQuery
    // (query message fully processed).
    simplePhaseAwaitingGroupOrReady

    // RowDescription seen for the CURRENT group; awaiting its DataRow*
    // then CommandComplete. Valid inputs: DataRow (stay), CommandComplete
    // (group done -> simplePhaseAwaitingGroupOrReady), ErrorResponse
    // (mid-row-streaming error -> simplePhaseAwaitingReadyOnly).
    simplePhaseInRows

    // EmptyQueryResponse or ErrorResponse already seen for this Query
    // message. Per "All further processing of the query string is
    // aborted by ErrorResponse", the ONLY valid remaining input is
    // ReadyForQuery.
    simplePhaseAwaitingReadyOnly
)
```

### Transition table

| Current phase | Backend message | New phase | Notes |
|---|---|---|---|
| AwaitingFirstMessage | `RowDescription` | InRows | Begins the first result-returning group. |
| AwaitingFirstMessage | `CommandComplete` | AwaitingGroupOrReady | First group was non-row-returning. |
| AwaitingFirstMessage | `EmptyQueryResponse` | AwaitingReadyOnly | Only valid as the very first message (empty query string). |
| AwaitingFirstMessage | `ErrorResponse` | AwaitingReadyOnly | First statement failed immediately (e.g. a syntax error). |
| AwaitingFirstMessage | `ReadyForQuery` | *(rejected)* | Impossible per grammar — `ErrSimpleResponseOrderingViolation`. |
| AwaitingGroupOrReady | `RowDescription` | InRows | Next statement in a multi-statement `Query` returns rows. |
| AwaitingGroupOrReady | `CommandComplete` | AwaitingGroupOrReady | Next statement is non-row-returning; more may follow. |
| AwaitingGroupOrReady | `ErrorResponse` | AwaitingReadyOnly | A later statement in the string failed. |
| AwaitingGroupOrReady | `ReadyForQuery` | *(terminal — `CycleCompleted=true`)* | No more statements; ends the response. |
| AwaitingGroupOrReady | `EmptyQueryResponse` | *(rejected)* | Only valid as the very first message — `ErrSimpleResponseOrderingViolation`. |
| InRows | `DataRow` | InRows | Row streamed. |
| InRows | `CommandComplete` | AwaitingGroupOrReady | Result set complete. |
| InRows | `ErrorResponse` | AwaitingReadyOnly | Mid-stream failure. |
| InRows | `RowDescription`/`EmptyQueryResponse`/`ReadyForQuery` | *(rejected)* | `ErrSimpleResponseOrderingViolation` — a second `RowDescription` without an intervening `CommandComplete`, or `ReadyForQuery`/`EmptyQueryResponse` before the open result set closes. |
| AwaitingReadyOnly | `ReadyForQuery` | *(terminal — `CycleCompleted=true`)* | Confirms "all further processing... aborted". |
| AwaitingReadyOnly | anything else | *(rejected)* | `ErrSimpleResponseOrderingViolation` — nothing may follow an error/empty-query response except `ReadyForQuery`. |
| *(any phase)* | `NoticeResponse`/`ParameterStatus`/`NotificationResponse` | *(unchanged)* | Async — checked and relayed **before** the ordering table above, exactly mirroring `BackendCorrelator`'s existing precedence rule. `result.Async = true`, phase unchanged. |
| *(any phase)* | `CopyInResponse`/`CopyOutResponse`/`CopyBothResponse` | *(rejected)* | `ErrSimpleQueryCOPYUnsupported` — fail-closed, mirrors `Transformer.handle`'s existing COPY rejection exactly. |
| *(any phase)* | `PortalSuspended` | *(rejected)* | Structurally impossible for Simple Query (no `Execute` row-limit concept exists) — `ErrSimpleResponseOrderingViolation`. |
| *(any phase)* | `ParseComplete`/`BindComplete`/`CloseComplete`/`ParameterDescription`/`NoData` | *(rejected)* | These are Extended-only backend messages; observing one while `simpleQueryActive` is true is a connection-level desynchronization — `ErrSimpleResponseOrderingViolation`, fail-closed, permanent termination (this can only happen from a genuine bug, since the runtime itself controls which subsystem is active). |
| *(any phase)* | connection-level `ErrorResponse` (no natural place in the grammar — reuses the *existing* `HandleBackendMessage`-level "no pending operation" concept, adapted: for Simple Query, this is instead any `ErrorResponse` seen when `SimpleQueryTracker` itself reports it cannot place the message, e.g. after `ReadyForQuery` was already produced) | *(rejected/terminal)* | Same treatment as `ResponseSequencer.handleConnectionLevelErrorResponse`: relay the frame, terminate the connection. |

### Field-level structural validation (reused, not reimplemented)

Every backend message type `SimpleQueryTracker` accepts is validated
using the **same** structural parsers/validators `BackendCorrelator`
already uses, since the wire format is identical regardless of which
sub-protocol produced it:

- `RowDescription`/`DataRow`: `protocol.ParseRowDescription`/
  `protocol.ParseDataRow` (unchanged, already shared with `Transformer`
  and `ExtendedTracker`).
- `CommandComplete`: the same tag-framing check `BackendCorrelator.
  validateCommandCompleteTag` already performs (exactly one NUL-
  terminated tag, nothing after — the tag's *content* is never read or
  retained, matching the existing rule).
- `ErrorResponse`/`NoticeResponse`: the same `validateFieldFraming`
  `BackendCorrelator` already uses.
- `ParameterStatus`/`NotificationResponse`: the same
  `validateParameterStatusFraming`/`validateNotificationResponseFraming`.
- `ReadyForQuery`: body must be exactly 1 byte, and that byte must be
  exactly `'I'`/`'T'`/`'E'` — the same check `protocol.State.
  ApplyReadyForQuery` already performs for Extended, reused for the new
  `ApplySimpleQueryReadyForQuery` (see
  [State lifecycle across sub-protocols](#transaction-state-behavior)).
- `EmptyQueryResponse`: body must be exactly empty (`Int32(4)` length,
  per the message-format spec — no body bytes).

No cell value, command tag content, or error field content is ever
retained past the single validation call that inspects it — matching the
existing rule `MaskDataRow`/`BackendCorrelator` already follow.

## Extended Query interaction

Extended Query's own internal behavior (Parse-time policy, discard-until-
`Sync`, `State`/`ResponseSequencer`/`ExtendedTracker` mechanics,
pipelining across multiple cycles) is **completely unchanged** by mixed
mode. The only two additions are:

1. The Case 2 boundary check added to the shared Extended message
   handlers (reject if `simpleQueryActive`) — see
   [Mixed frontend state machine](#frontend-state-machine).
2. `MsgQuery` participating in discard-until-`Sync`'s existing absorption
   rule (Case 1) — see
   [What happens when a message arrives outside the boundary](#what-happens-when-a-message-arrives-outside-the-boundary).

No change to `protocol.State`'s Extended-specific methods
(`CreateParse`/`CreateBind`/.../`ApplyReadyForQuery`), no change to
`ResponseSequencer`, no change to `BackendCorrelator`, no change to
`ExtendedTracker`, no change to `ExtendedFrontend` itself (a new,
separate `MixedFrontend` type is introduced instead — see
[Staged implementation plan](#staged-implementation-plan), Stage C).

## Policy behavior

- `internal/firewall/policy.go`'s `Policy` interface and
  `DenyKeywords` are **unchanged** — `DenyKeywords` already evaluates
  both `protocol.MsgQuery` and `protocol.MsgParse` through the identical
  `sqlmatch.MatchAny` call (`policy.go:64`); mixed mode's `Query` handling
  calls `Policy.Evaluate` exactly as `Gate.handle` already does for
  Simple-only mode, and exactly as `ExtendedFrontend.handleParse` already
  does for `Parse`.
- Exactly one evaluation per `Query` frame (no per-statement splitting of
  a multi-statement `Query` string — the existing, unmodified `Policy`
  contract evaluates the complete `m.Query` string as one unit, matching
  today's Simple-only behavior exactly).
- No SQL AST parsing is introduced; `sqlmatch`'s existing documented
  false-positive/false-negative limitations (comment-based and quoted-
  identifier evasion) are unchanged and remain documented in
  `internal/firewall/policy.go`.
- A blocked `Query` never reaches PostgreSQL: `RejectSimpleQuery` (see
  above) performs no `writeAll(r.backend, ...)` call at all — the frame
  never leaves the frontend goroutine's call stack.
- `BlockedQueriesTotal` increments exactly once per `Block` verdict,
  whether for a `Query` or a `Parse` — the mixed mode `onDecide` callback
  (constructed in `cmd/gateway/main.go`'s new `runMixedConnection`,
  Stage E) is the single, unified callback for both message types, mirroring
  `extendedOnDecide`'s existing structure exactly (one callback,
  triggered once per Parse-or-Query evaluation).
- Policy duration is observed identically to today:
  `time.Since(start)` around the `Policy.Evaluate` call, logged via the
  same safe, value-free logging discipline `logGateDecision`/
  `extendedOnDecide` already use (message type, verdict, duration,
  connection ID — never the query text unless `logging.log_full_queries`
  is explicitly `true`, unchanged).
- Policy errors (a `nil` `Policy` interface passed to `MixedFrontend`)
  are treated as `Allow` — the existing `Gate`/`ExtendedFrontend` nil-
  Policy convention, reused unchanged (this is a deliberate existing
  behavior for tests/embedding, not a new fail-open path — production
  wiring in `cmd/gateway/main.go` always supplies a non-nil `wasm.Policy`).
- SQL is not logged unless `logging.log_full_queries` is explicitly
  `true` — unchanged existing gate (`cmd/gateway/main.go`'s
  `logGateDecision`, reused for the mixed `Query` case identically to how
  it already handles Simple-only `Query` logging).
- Production-safe errors (`ErrMalformedSimpleQueryFrame`,
  `ErrMixedBoundaryViolation`, etc.) never contain the query text — every
  new sentinel follows the existing `ExtendedParseError`/`gateway.Err*`
  pattern of fixed, value-free category strings.

## Masking behavior

### Simple Query masking inside the unified runtime

No new masking *primitive* is introduced. `masking.MaskDataRow` and
`masking.RowMaskPlan` (`internal/masking/row_mask.go`) are reused
verbatim — they are already I/O-free, already shared between
`Transformer` and `ExtendedRuntime`, and already implement every rule
this design needs (NULL preservation, binary-target fail-closed,
plugin-error fail-closed, shape validation).

What is new is a single extracted helper, proposed for Stage D:

```go
// BuildRowMaskPlanFromRowDescription builds a RowMaskPlan from a parsed
// RowDescription's fields, using cfg.ShouldMask for target-column
// selection - the exact logic masking.Transformer.handleRowDescription
// already inlines (row_mask.go / transformer.go). Extracting it lets
// both Transformer and the new Simple Query masking integration in
// ExtendedRuntime call the SAME code, so their behavior is provably
// identical rather than independently re-derived.
func BuildRowMaskPlanFromRowDescription(cfg Config, fields []protocol.RowField) RowMaskPlan
```

`Transformer.handleRowDescription` is refactored (Stage D) to call this
helper instead of its current inline loop — a behavior-preserving
refactor verified by `Transformer`'s existing, unmodified test suite
continuing to pass unchanged (byte-for-byte identical output for every
existing test case).

### Runtime integration (single active plan, mirrors `Transformer` exactly)

The runtime holds exactly one `masking.RowMaskPlan` field
(`simpleMaskPlan`) for the currently active Simple Query response — no
generation-keyed cache is needed (unlike `ExtendedTracker`), because
Simple Query, per the PostgreSQL grammar quoted in
[Protocol requirements](#protocol-requirements), never has more than one
active result set at a time (multiple statement-result groups within one
`Query` message are strictly sequential, never concurrent).

| Trigger | Effect |
|---|---|
| `RowDescription` observed (via `SimpleQueryTracker`) | `simpleMaskPlan = BuildRowMaskPlanFromRowDescription(cfg, fields)` (or, if `!cfg.Enabled`, an empty plan — matching `Transformer.handleRowDescription`'s existing `if t.cfg.Enabled` gate). |
| `DataRow` observed | `out, _, err := masking.MaskDataRow(ctx, masker, simpleMaskPlan, m.Raw, hooks)` — the identical call `ExtendedRuntime.transformDataRowAction` already makes for Extended, reused verbatim. |
| `CommandComplete` / `EmptyQueryResponse` / `ErrorResponse` / `ReadyForQuery` observed | `simpleMaskPlan = masking.RowMaskPlan{}` — mirrors `Transformer.clearResultSet()` exactly (same four trigger points: `Transformer.handle`'s `MsgCommandComplete`/`MsgErrorResponse` case calls `clearResultSet`; `MsgReadyForQuery` case calls it too; `EmptyQueryResponse` is the fourth clearing point this design adds explicitly, since `Transformer` today never observes `EmptyQueryResponse` mid-result-set the way a multi-statement Simple Query can produce it between groups — Stage D's tests must confirm this exact parity). |
| Asynchronous message during a result set | No plan change — relayed unchanged, exactly as `Transformer.handle`'s `default` case already does. |
| Binary-format masking target observed | `masking.MaskDataRow` returns `ErrRowMaskBinaryTarget` (existing, reused) — fail-closed, terminal, connection closed with a fixed `FATAL` `ErrorResponse` (mirrors `Transformer.failClosed`/`ExtendedRuntime.emitMaskingFailureFatal`'s existing pattern; the new sentinel is `ErrSimpleMaskingFailed`, wrapping the same SQLSTATE `58030` reason text `Transformer.failClosed` already uses verbatim — no new SQLSTATE is introduced). |
| Plugin (`Masker.Mask`) error | `ErrMaskerInvocationFailed` (existing) → `ErrSimpleMaskingFailed` (new wrapper, same terminal fail-closed treatment). |
| COPY response observed | `ErrSimpleQueryCOPYUnsupported` (new sentinel, same fail-closed shape as `Transformer`'s existing COPY rejection). |
| `MaskedCellsTotal` | Incremented once per changed cell — same `hooks.OnMaskAttempt` callback signature, same increment rule (`changed == true`), reused unchanged; the mixed-mode runtime's hook implementation is structurally identical to `extendedMaskingHooks` (`cmd/gateway/main.go:518`), just invoked from the new Simple Query call site as well as the existing Extended one. |
| `MaskingPluginDuration` | Observed once per mask attempt (successful or not), unchanged — same `hooks.OnMaskAttempt` duration parameter. |
| `MaskingErrorsTotal` | Incremented **exactly once** for a terminal masking failure, from the runtime's own final-error classification (mirrors `logExtendedRuntimeOutcome`'s existing `errors.Is(err, gateway.ErrExtendedMaskingFailed)` check, extended to also check `errors.Is(err, gateway.ErrSimpleMaskingFailed)` — never double-counted against `OnMaskAttempt`, exactly matching the existing Extended discipline documented in `cmd/gateway/main.go`'s `extendedMaskingHooks` comment). |

### Why default Simple-only `Transformer` behavior is unaffected

`Transformer` is **never constructed** in `mixed` mode
(`runMixedConnection`, Stage E, constructs only `MixedFrontend` +
`ExtendedRuntime`, exactly as `runExtendedConnection` does today for
`extended_only`). `simple_only` mode continues to construct exactly the
same `Transformer` it does today, calling the same (now-shared, after the
Stage D extraction) `BuildRowMaskPlanFromRowDescription` helper — a
behavior-preserving refactor, not a behavior change, verified by
`Transformer`'s complete existing test suite (`internal/masking/
transformer_test.go`) passing unmodified.

## Transaction-state behavior

`protocol.State.TransactionStatus()` (existing) is the **sole**
authoritative transaction status source in `mixed` mode — `protocol.
TxState` (the separate, atomic-based type `simple_only` mode uses via
`Gate.SetTxState`/`Transformer`'s `txState` field) is **not** used in
mixed mode at all. This is a deliberate simplification made possible by
mixed mode using a single `protocol.State` instance for the whole
connection (unlike `simple_only`, which has no `protocol.State` at all).

### New, additive `State` method

```go
// ApplySimpleQueryReadyForQuery updates transaction status and portal
// lifetime for a REAL ReadyForQuery that terminates an allowed Simple
// Query's response. Unlike ApplyReadyForQuery (which requires a pending
// OpSync operation and a non-empty outstandingSyncCycles queue), a Simple
// Query has no Parse/Bind/Sync identity - this method only:
//   1. validates status is exactly 'I'/'T'/'E' (else
//      ErrInvalidTransactionStatus, reused);
//   2. sets s.txStatus = status;
//   3. if status == TxStatusIdle, invalidates EVERY currently-tracked
//      portal (named and unnamed) - safe, and NOT merely an
//      approximation, because the boundary-only alternation rule (see
//      docs/design/0002-mixed-query-routing.md) guarantees
//      OutstandingCycleCount() == 0 at the moment a Simple Query is
//      allowed to start, so there is no later-pipelined Extended cycle's
//      portal to protect from premature invalidation, unlike
//      ApplyReadyForQuery's narrower, cycle-bounded
//      invalidatePortalsThroughCycle;
//   4. runs the existing internal cleanup() pass.
// Statements are never invalidated (same rule as ApplyReadyForQuery).
func (s *State) ApplySimpleQueryReadyForQuery(status byte) error
```

This is additive only — `ApplyReadyForQuery` itself is not modified.

### Locally blocked Simple Query vs. locally blocked Extended `Parse`

| | Locally blocked Simple `Query` | Locally blocked Extended `Parse` |
|---|---|---|
| Does PostgreSQL receive the query? | No — never forwarded. | No — never forwarded. |
| Does real transaction state change? | No — provably unchanged, since nothing was sent. | No — same. |
| Synthetic `ReadyForQuery` status used | `state.TransactionStatus()` — the last **real**, authoritative status. | N/A — no synthetic `ReadyForQuery` is produced at all for a blocked `Parse`. |
| Additional `Sync` required? | **No** — Simple Query has no `Sync` concept; the synthetic `ErrorResponse`+`ReadyForQuery` pair is a complete, self-contained response cycle, exactly matching what a *real* blocked Simple Query would look like to the client. | **Yes** — enters discard-until-`Sync`; the client must send `Sync` to receive its `ReadyForQuery` and return to a usable state (unchanged Extended-only recovery rule). |
| Connection remains usable immediately after? | **Yes**, immediately — no further client action required. | Only after the client sends `Sync` (unchanged). |

This satisfies the task's explicit requirement to contrast the two: a
blocked Simple Query is a complete, self-terminating response (matching
real Simple Query semantics, where every `Query` message always ends in
exactly one `ReadyForQuery`); a blocked Extended `Parse` is not — Extended
Query's own recovery model (discard-until-`Sync`) is unchanged and is not
short-circuited by mixed mode.

### Never inferred from SQL text

`BEGIN`/`COMMIT`/`ROLLBACK` (or any other SQL) appearing in a `Query`
string's *text* is never inspected to guess a resulting transaction
status. The authoritative status is set **exclusively** by real backend
`ReadyForQuery` frames (via `ApplySimpleQueryReadyForQuery` for Simple,
the existing `ApplyReadyForQuery` for Extended) — matching pgx's own
`BeginTx { c.Exec(ctx, "begin") ... }` flow exactly: pgx sends the literal
text `"begin"` as an ordinary Simple `Query`, and it is PostgreSQL's own
real `ReadyForQuery('T')` response, relayed and applied via
`ApplySimpleQueryReadyForQuery`, that updates `state.TransactionStatus()`
— never a client-side or gateway-side parse of the string `"begin"`
itself.

## Configuration and migration behavior

### Chosen model: new `query_mode` enum field, legacy boolean retained, mutually exclusive

Evaluated against the task's three options:

1. **New enum (`protocol.query_mode`), retaining the legacy boolean** —
   **chosen**. Three explicit string values map cleanly to three
   explicit modes; the legacy boolean continues to mean exactly what it
   means today for anyone who never adopts the new field.
2. **Retain the boolean, add a second boolean** (e.g. `mixed_mode_enabled`)
   — rejected: two independent booleans admit four combinations, one of
   which (`extended_query_enabled: true` + `mixed_mode_enabled: true`) is
   inherently ambiguous about precedence in a way a single enum value
   cannot be; a three-way choice is better modeled by one three-valued
   field than by two booleans whose cross-product must then be validated
   down to three valid combinations anyway.
3. **Another backward-compatible representation** (e.g. overloading
   `extended_query_enabled` to accept a string) — rejected: changes the
   field's YAML type, which is a strictly more disruptive backward-
   compatibility break for any existing tooling/config generation than
   adding a new, independent field.

### Exact YAML

```yaml
protocol:
  # New in this design. One of: "simple_only", "extended_only", "mixed".
  # Mutually exclusive with extended_query_enabled below - specifying
  # both is a configuration error (see "Conflict behavior").
  query_mode: mixed

  # Existing field, UNCHANGED meaning: true selects extended_only,
  # false (or omission) selects simple_only. Retained indefinitely for
  # backward compatibility - no deprecation timeline is proposed here.
  extended_query_enabled: false
```

### Go types (Stage E, illustrative — not implemented in this stage)

```go
type ProtocolConfig struct {
    // QueryMode, if non-empty, is authoritative and MUST be exactly one
    // of "simple_only"/"extended_only"/"mixed" (case-sensitive). Empty
    // string means "not set" - the empty string is never a valid mode
    // name, so this is an unambiguous absence marker (unlike bool).
    QueryMode string `yaml:"query_mode"`

    // ExtendedQueryEnabled, unchanged in TYPE MEANING from today except
    // for its Go representation: a *bool (not bool) so "not present in
    // YAML" (nil) is distinguishable from "explicitly false" (non-nil,
    // false) - required to detect the "both fields present" conflict
    // even when extended_query_enabled: false is explicitly written.
    ExtendedQueryEnabled *bool `yaml:"extended_query_enabled"`
}

type QueryMode int

const (
    QueryModeSimpleOnly QueryMode = iota + 1
    QueryModeExtendedOnly
    QueryModeMixed
)

// Resolve validates and returns the authoritative QueryMode, applying
// the exact precedence/conflict/default rules below. Called once from
// Config.Load, exactly like MaskingConfig.validate() is today.
func (p ProtocolConfig) Resolve() (QueryMode, error)
```

### Valid values, default, absence, conflict, and error behavior

| Situation | Resolved mode | Notes |
|---|---|---|
| Neither field present | `QueryModeSimpleOnly` | Identical to today's zero-value default — **no behavior change** for any config file that predates this design. |
| Only `extended_query_enabled: true` | `QueryModeExtendedOnly` | Identical to today. |
| Only `extended_query_enabled: false` | `QueryModeSimpleOnly` | Identical to today. |
| Only `query_mode: simple_only` \| `extended_only` \| `mixed` | The named mode | New capability; `mixed` is reachable **only** this way. |
| Only `query_mode: <anything else>` | *(load error)* | `ErrProtocolConfigInvalidMode` — fail-closed, not silently defaulted. |
| Both fields present, any values | *(load error)* | `ErrProtocolConfigConflict` — **always** an error, even if the two values would be "consistent" (e.g. `query_mode: extended_only` + `extended_query_enabled: true`); this is the simplest, least ambiguous rule and avoids ever needing to define cross-field precedence. |
| Unknown key anywhere under `protocol:` | *(load error)* | Unchanged — `yaml.Decoder.KnownFields(true)` already rejects this (`TestLoad_ProtocolUnknownFieldIsRejected`, existing, must continue to pass unmodified). |

### Environment-variable behavior

None. Consistent with today (`extended_query_enabled` has no environment
override; only `SENTINELDB_LISTEN_ADDR`/`TARGET_ADDR`/`METRICS_ADDR`/
`API_ADDR` are environment-driven, per `cmd/gateway/main.go`'s
`envOrDefault` calls) — `query_mode` remains YAML-only. No new
environment variable is introduced by this design.

### Migration path

None required. Existing `config.yaml` files (including the repository's
own root `config.yaml`, `deploy/driver-compat/config.yaml`, and any
operator's own file) continue to load and behave identically, forever —
`extended_query_enabled` is not deprecated by this document. Adopting
`mixed` is purely opt-in: an operator adds `query_mode: mixed` (and
removes `extended_query_enabled`, if present, to avoid the conflict
error).

### Compatibility vs. regression-testing intent

- `simple_only`, `extended_only`: the two existing, already-shipped
  modes — preserved for production use and as regression-test baselines
  proving mixed mode introduces no change to either (see
  [pgx compatibility acceptance criteria](#pgx-compatibility-acceptance-criteria),
  "Retain default Simple-only regression coverage" / "Retain a separate
  Extended-only configuration/test").
- `mixed`: the new capability this design specifies. Not claimed
  production-ready by this document (see [Status](#status)); intended,
  once implemented and its acceptance criteria pass, to become the
  recommended mode for real-driver compatibility.

### No automatic detection; shared startup

`RunStartupHandoff` is called identically for all three modes (today,
only `runExtendedConnection` calls it — Stage E's `cmd/gateway/main.go`
change additionally calls it from a new `runMixedConnection`, and
**could** additionally unify `runSimpleConnection` onto it too, but this
document does not require that: `simple_only` mode's own startup handling,
via `firewall.Gate.Run`'s `protocol.NewClientDecoder`, remains valid and
unchanged, since this design's compatibility requirement is only that
`mixed`/`extended_only` share `RunStartupHandoff`, which they already
will). No connection ever chooses its mode based on observed traffic —
`cfg.Protocol` (resolved once, at config-load time) is read exactly once,
at `handleConn`'s dispatch point, before any steady-state byte is
processed, for every mode.

## Error and shutdown behavior

### Fixed, safe error categories (new, `internal/gateway` and
`internal/firewall`, mirroring the existing `Err*` sentinel pattern)

| Category | Package | Meaning | Connection-fatal? |
|---|---|---|---|
| `ErrMalformedSimpleQueryFrame` | `firewall` (or `protocol`, for the framing-only part) | `Query` body fails structural validation (missing/extra NUL terminator, trailing bytes). | No — recoverable, synthesized `ErrorResponse`+`ReadyForQuery` via `RejectSimpleQuery`, no `Sync` needed (see [Transaction-state behavior](#transaction-state-behavior)). |
| `ErrMixedBoundaryViolation` | `gateway` | A `Query` or Extended message arrived outside the permitted clean boundary (Case 2). | **Yes** — see [justification](#what-happens-when-a-message-arrives-outside-the-boundary). |
| `ErrSimpleResponseOrderingViolation` | `protocol` | `SimpleQueryTracker` observed a backend message sequence the Simple Query grammar forbids. | Yes — mirrors `ErrImpossibleBackendOrdering`'s existing treatment. |
| `ErrSimpleMaskingFailed` | `gateway` | Terminal Simple Query masking failure (binary target, plugin error, malformed `DataRow`). | Yes — mirrors `ErrExtendedMaskingFailed` exactly, same SQLSTATE `58030`. |
| `ErrSimpleQueryCOPYUnsupported` | `protocol` | A COPY response observed during a Simple Query response. | Yes — mirrors `Transformer`'s existing COPY fail-closed behavior. |
| `ErrMixedFrontendUnsupportedMessage` | `firewall` | `FunctionCall`, unknown message type, or COPY frontend message in `MixedFrontend`. | Yes — reuses `ExtendedFrontend`'s existing category/behavior, renamed for the new type. |
| `ErrMixedFrontendDecodeFailed` | `firewall` | `NewSteadyStateFrontendFrameDecoder` framing failure. | Yes — mirrors `ErrExtendedFrontendDecodeFailed` exactly. |

**Reused, unchanged, from the existing `gateway`/`firewall`/`protocol`
packages** (no new sentinel needed): `ErrBackendWriteFailed`,
`ErrClientWriteFailed`, `ErrRuntimeStopped`, `ErrNotRunning`,
`ErrFrontendRegistrationDiverged` (for the narrower Simple-Query
divergence case: `State` mutated via `ApplyAllowedSimpleQuery()` but the
subsequent backend write fails — reuses `ErrBackendWriteFailed` directly,
since Simple Query has no separate "sequencer registration" step to
diverge from; there is no new divergence category needed for Simple
Query specifically), `ErrFrontendProtocolFailure`, `ErrBackendProtocolFailure`,
`ErrTruncatedBackendMessage`, `ErrInvalidTransactionStatus`.

None of the above ever wraps arbitrary transport error text, SQL, or
protocol payload bytes into its message — every one follows the existing
`errors.New("package: fixed category")` pattern (or, where an underlying
transport error must be classified, the existing safe-classification
pattern in `startup_handoff.go`'s `classifyClientReadErr`/etc., reused
unchanged).

### Startup, cancellation, and shutdown causality

Entirely unchanged from today's `extended_only` mode (mixed mode reuses
`RunStartupHandoff` and `ExtendedRuntime`'s existing shutdown-watcher/
`shutdownCause` machinery without modification):

- `CancelRequest` remains a separate, startup-style connection, forwarded
  exactly once by `RunStartupHandoff`, with no steady-state runtime ever
  constructed for it (`StartupResult.CancelOnly`). Mixed mode does not
  alter this — the boundary/tracker logic added by this design is purely
  steady-state (post-`RunStartupHandoff`) and never observes a
  `CancelRequest` at all.
- A cancellation's resulting `ErrorResponse` (`SQLSTATE 57014`) for an
  active Simple Query is relayed via the **unchanged** async/error path:
  it arrives as an ordinary backend `ErrorResponse` while
  `simpleQueryActive` is `true`, is validated and relayed by
  `SimpleQueryTracker` exactly like any other mid-response error (see the
  [transition table](#transition-table)), and the following real
  `ReadyForQuery` restores the clean boundary via
  `ApplySimpleQueryReadyForQuery`, exactly as
  [pgx compatibility acceptance criteria](#pgx-compatibility-acceptance-criteria)
  requires. No special-casing of cancellation is needed in
  `SimpleQueryTracker` — from its point of view, a cancellation's
  `ErrorResponse` is indistinguishable from any other backend-detected
  query error, which is exactly correct (SentinelDB never inspects
  `ErrorResponse` field values, including `SQLSTATE`, per
  [Privacy and logging guarantees](#privacy-and-logging-guarantees)).
- Initiating internal failure vs. later cancellation, parent cancellation
  vs. close-induced I/O errors, interruptible blocked reads/writes via
  transport closure, joined goroutines, open transports after successful
  handoff, fail-closed terminal runtime failure: all unchanged,
  inherited directly from `ExtendedRuntime.Run`'s existing, extensively
  tested `shutdownCause` CAS/linearization design
  (`extended_runtime.go:686-830`, unmodified by this document).

## Resource limits

| Structure | Limit | Source |
|---|---|---|
| `Query` frame size | Reuses existing `RuntimeLimits.MaxFrontendFrameBytes` (1 MiB, matches `protocol.maxMessageLength`). | No new limit type. |
| Unified plan units | N/A — Simple Query never enters `ResponseSequencer`'s plan queue at all (see [Response correlation and sequencing](#response-correlation-and-sequencing)); Extended's existing `SequencerLimits` (`MaxPlanUnits` etc.) are unchanged and apply only while `!simpleQueryActive`. | Reused, unchanged. |
| Active Simple response state | O(1) by construction — one `simpleQueryActive bool`, one `simpleMaskPlan RowMaskPlan`, one `SimpleQueryTracker` phase value, reused (reset, not reallocated) across cycles. | New, but not independently configurable — no growth is possible regardless of traffic. |
| `RowDescription` field count / frame size | Reuses existing `protocol.maxMessageLength` (1 MiB) and `masking.RowMaskPlan`'s existing shape validation (`ErrDataRowShapeMismatch`). | No new limit. |
| `DataRow` frame size | Same. | No new limit. |
| Number of statement-result groups per `Query` message | **Not tracked as a distinct counter** — each group is processed and its (bounded) plan state discarded before the next begins; memory usage is O(1) regardless of how many statements one `Query` message contains. | Explicitly a non-issue by design, not a limit needing a number. |
| Synthetic frame size (blocked-`Query` `ErrorResponse`) | Reuses the existing `SequencerLimits.MaxSyntheticFrameBytes`-style bound defensively, even though `RejectSimpleQuery`'s reason strings are always fixed/small (Policy block reasons are already bounded by `sqlmatch`'s match-length behavior; internal fixed strings are compile-time constants). | Reused pattern, not a new numeric proposal. |
| Masking plan memory | O(1) per active Simple Query response (one plan, replaced not accumulated). | Not independently limited. |
| Asynchronous messages | Never retained — relayed and discarded immediately, in both the Extended and Simple dispatch branches, matching the existing rule exactly. | No limit needed. |

Every limit exhaustion path: no partial upstream forwarding occurs before
validation completes (matches `validateFrontendOperationFrame`'s existing
"validate fully, then act" discipline); results in one of the fixed, safe
error categories above; is deterministically fail-closed (permanent
runtime termination, following the existing `loop()` →
`markInternalShutdown()` pipeline); and never produces unbounded
diagnostic output (every error is a fixed sentinel, never a formatted
dump of the offending frame).

## Privacy and logging guarantees

Unchanged, extended to the new code paths:

- No password or SASL content — mixed mode never touches
  authentication (owned exclusively by the shared, unmodified
  `RunStartupHandoff`).
- No startup parameter values — same.
- No Bind values — `MixedFrontend`'s reused `handleBind` logic is
  byte-for-byte the same as `ExtendedFrontend`'s (extracted shared
  helper, not reimplemented) — `bindParamNulls` continues to extract
  only NULL-ness, never values.
- No `DataRow` values — `masking.MaskDataRow`'s existing contract
  (never logs, never includes values in its returned errors) is reused
  unchanged for the Simple Query call site too.
- No cancellation key, no backend PID — untouched by this design
  (owned exclusively by `RunStartupHandoff`, unchanged).
- No `ErrorResponse` field values — `SimpleQueryTracker`'s validators
  (`validateFieldFraming`, reused) inspect only framing structure, never
  field content, exactly like `BackendCorrelator`'s existing rule.
- No statement or portal names — `ApplySimpleQueryReadyForQuery`
  operates on `protocol.State`'s existing generation-ID-keyed model,
  never names; `RejectSimpleQuery`/`ForwardSimpleQuery` never construct
  or log a statement/portal name (Simple Query has none).
- No SQL in fixed errors — every new sentinel in
  [Error and shutdown behavior](#error-and-shutdown-behavior) is a fixed,
  parameterless string.
- No SQL in normal logs unless `logging.log_full_queries` is explicitly
  enabled — the mixed-mode `Query` logging path reuses
  `cmd/gateway/main.go`'s existing `logGateDecision`/`logFullQueries`
  gate verbatim.

### Simple Query SQL retention proof

`queryText` (the parsed `Query` string) exists **only** on the
`MixedFrontend`'s own call stack, for the duration of steps 3–4 of
[Query handling](#query-handling) (parse, then exactly one synchronous
`Policy.Evaluate` call). It is:

- **not** passed into `runtime.ForwardSimpleQuery`/`RejectSimpleQuery` —
  both take only the already-framed `[]byte` (for forwarding, the
  original wire bytes, needed only to relay them verbatim upstream — not
  re-parsed or retained by the runtime) or fixed reason
  strings/SQLSTATEs (for rejection);
- **not** stored in `protocol.State` — `ApplyAllowedSimpleQuery()`'s
  existing signature takes no query-text parameter and never did;
- **not** stored in any `ResponseSequencer`/`SimpleQueryTracker` plan
  unit — `SimpleQueryTracker`'s transition table
  ([above](#transition-table)) operates purely on backend message
  *types*, never frontend query text;
- **not** stored in any long-lived runtime event — the `frontendEvent`
  values for the two new event kinds carry only the pre-copied wire
  `frame` bytes (needed transiently for the single `writeAll(r.backend,
  ...)` call, exactly like every existing Extended frontend event
  already does) or nothing at all (`RejectSimpleQuery`);
- **not** returned to the caller in any registration/acknowledgement
  value — unlike `RegisterAndForwardFrontendOperation`'s
  `FrontendRegistration`, `ForwardSimpleQuery`/`RejectSimpleQuery` return
  only `error` (`nil` on success) — there is no statement/portal identity
  for a Simple Query to hand back.

This mirrors the existing, already-audited guarantee `ExtendedFrontend.
handleParse` provides for `Parse`'s query text (`FrontendOperationRequest.Query`
is consumed synchronously by `Policy.Evaluate` and by
`State.CreateParse`'s own internal storage — which mixed mode's Simple
Query path does not even need, since `ApplyAllowedSimpleQuery()` never
stores query text at all, unlike `CreateParse`, which legitimately must
retain it as part of the prepared statement's own identity for later
`Bind`/`Describe`/`Execute` reference. Simple Query has no such later
reference — nothing about it is ever referenced again after its single
response completes — so it needs strictly *less* retention than Extended
`Parse` already safely provides.)

## Metrics behavior

No new production metric is proposed — the task requires a demonstrated
concrete operational gap before adding one, and none exists: every
metric mixed mode needs already exists and already has a well-defined,
reusable increment point.

| Metric | Mixed-mode behavior |
|---|---|
| `ConnectionsTotal` | Unchanged — incremented once per accepted TCP connection, in `main()`'s accept loop, before mode dispatch; mode-agnostic already. |
| `BlockedQueriesTotal` | Incremented exactly once per `Block` verdict, for a blocked `Query` **or** a blocked `Parse`, via the mixed mode's single, unified `onDecide` callback (mirrors `extendedOnDecide`'s existing structure). |
| `MaskedCellsTotal` | Incremented once per changed cell, from the Simple Query masking call site (new) **and** the existing Extended call site — both feed the same counter, as `Transformer`'s Simple-only call site and `ExtendedRuntime`'s Extended call site already both do today. |
| `MaskingPluginDuration` | Observed once per mask attempt from both call sites, unchanged histogram, unchanged buckets. |
| `MaskingErrorsTotal` | Incremented exactly once per terminal masking failure, from the runtime's single final-error classification point, now checking `errors.Is(err, gateway.ErrSimpleMaskingFailed)` in addition to the existing `ErrExtendedMaskingFailed` check — never double-counted against `OnMaskAttempt`, matching the existing discipline exactly. |

No metric label ever carries SQL text, parameter values, client-supplied
statement/portal names, or free-form error strings — unchanged (none of
the existing metrics are labeled at all; they are plain counters/one
histogram, and this design adds no labels).

## Test strategy

Full detail is deferred to
[Staged implementation plan](#staged-implementation-plan) (each stage
lists its required tests) and
[pgx compatibility acceptance criteria](#pgx-compatibility-acceptance-criteria)
below. Summary of test categories, matching
[docs/design/0001-extended-query-review-checklist.md](0001-extended-query-review-checklist.md)'s
"Tests" section discipline:

- **Unit**: `SimpleQueryTracker`'s full transition table (every row in
  the table above, both accept and reject cases); `ApplySimpleQueryReadyForQuery`'s
  status validation and portal-invalidation behavior; the boundary
  predicate's exact evaluation for every relevant `State`/runtime
  combination.
- **State-machine**: the full `MixedFrontend` dispatch table, including
  discard-time `Query` absorption (Case 1) and out-of-boundary rejection
  (Case 2), for every message type.
- **Malformed-input**: every row of the `Query` frame validation rules
  (missing terminator, trailing bytes, oversized frame); every rejected
  backend-message-ordering case in the transition table.
- **Fuzz**: `SimpleQueryTracker.Handle` fuzzed the same way
  `FuzzBackendCorrelatorSequence`/`FuzzResponseSequencer` already fuzz
  their respective components (see `internal/protocol/
  extended_correlation_test.go`/`extended_sequence_test.go` for the
  existing pattern to mirror).
- **Integration**: `cmd/gateway/main_test.go`-style connection-level
  tests for `runMixedConnection` (Stage E), covering an alternating
  Simple→Extended→Simple sequence end to end against an in-process fake
  backend, mirroring `TestRunSimpleConnection_*`'s existing style.
- **Real-driver E2E**: [pgx compatibility acceptance criteria](#pgx-compatibility-acceptance-criteria).
- **Concurrency/race**: `go test -race` across every new/changed
  package, plus the existing Linux CI race job, extended to also run
  against the new mixed-mode driver-compat stack (Stage F).
- **Shutdown**: parent-context cancellation while a Simple Query response
  is mid-flight (new — mirrors the existing
  `TestExtendedRuntime_ContextCancellation_ClosesBothEnds`-style test,
  applied to the new `simpleQueryActive` state).
- **Sensitive-log-scan**: the existing `scripts/driver-compat.ps1`/
  `scripts/lib/driver-compat-privacy.ps1` marker-scan machinery, extended
  with mixed-mode-specific canary values (a distinctive `Query`-text
  email, a distinctive blocked-Query phrase) exactly mirroring how the
  existing suite already does this for Extended-only masking/policy
  tests.

## Staged implementation plan

Each stage is independently reviewable and independently committable, per
the task's explicit requirement that no stage combine an unreviewable
protocol-core rewrite with live wiring, Docker, CI, and documentation all
at once.

### Stage A — pure protocol/state model

- **Files/types**: new `internal/protocol/simple_query.go`
  (`SimpleQueryTracker`, `SimpleQueryResult`, `ErrSimpleResponseOrderingViolation`,
  `ErrSimpleQueryCOPYUnsupported`); additive change to
  `internal/protocol/extended_state.go` (`ApplySimpleQueryReadyForQuery`
  only — no existing method signature changes).
- **Invariants introduced**: the full transition table above; "no cell/
  tag/field content retained"; "async messages checked before ordering."
- **Tests required**: `internal/protocol/simple_query_test.go` (every
  transition table row, both directions); a fuzz target
  (`FuzzSimpleQueryTracker`, mirroring the existing Extended fuzz
  targets' structure); `internal/protocol/extended_state_test.go`
  additions for `ApplySimpleQueryReadyForQuery` (status validation,
  portal invalidation on `'I'`, no invalidation on `'T'`/`'E'`, statements
  never invalidated).
- **Commit boundary**: no dependency on `internal/gateway`,
  `internal/firewall`, `internal/masking`, or `cmd/gateway` — pure,
  I/O-free, independently testable, exactly like `extended_state.go`/
  `extended_correlation.go`/`extended_sequence.go` were when first
  introduced.
- **Intentionally unsupported at this stage**: nothing is wired to a live
  connection yet; `SimpleQueryTracker`/`ApplySimpleQueryReadyForQuery`
  are unused by any runtime code, exactly as `ApplyAllowedSimpleQuery()`
  is today.

### Stage B — unified sequencing/runtime APIs

- **Files/types**: `internal/gateway/extended_runtime.go` (additive:
  `simpleQueryActive`/`simpleMaskPlan`/`simpleTracker` fields,
  `ForwardSimpleQuery`/`RejectSimpleQuery` methods, two new
  `frontendEventKind` values and their handlers, the backend-dispatch
  `if simpleQueryActive` branch, `ErrMixedBoundaryViolation`,
  `ErrMalformedSimpleQueryFrame`).
- **Invariants introduced**: the clean-boundary predicate, evaluated only
  inside the event-loop goroutine; "Simple Query never enters the
  `ResponseSequencer` plan queue"; "`simpleQueryActive` transitions are
  atomic within one event-loop turn."
- **Tests required**: `internal/gateway/extended_runtime_test.go`
  additions mirroring the existing `TestExtendedRuntime_*` structure —
  boundary-check acceptance/rejection for every `State`/`simpleQueryActive`
  combination; `ForwardSimpleQuery`/`RejectSimpleQuery` success and every
  failure path (malformed frame, boundary violation, backend write
  failure); a race test confirming no concurrent access to
  `simpleQueryActive`/`simpleMaskPlan` (via `-race`, mirroring the
  existing `TestExtendedRuntime_Writes_MaxConcurrencyIsOne`-style test).
- **Commit boundary**: no `firewall`/`cmd/gateway` changes yet — these
  new runtime methods are exercised only by new, direct unit tests
  constructing an `ExtendedRuntime` in-process (mirroring how existing
  `extended_runtime_test.go` tests already do, without a real
  `net.Conn`).
- **Intentionally unsupported at this stage**: no live gateway wiring;
  no frontend calls these methods yet.

### Stage C — mixed frontend

- **Files/types**: new `internal/firewall/mixed_frontend.go`
  (`MixedFrontend`, `Gate.RunMixed`, `ErrMixedFrontendUnsupportedMessage`,
  `ErrMixedFrontendDecodeFailed`); refactor of
  `internal/firewall/extended_frontend.go` to extract shared
  per-message-type handler logic (Parse/Bind/Describe/Execute/Close/
  Flush/Sync/Terminate/discard) into helpers both `ExtendedFrontend` and
  `MixedFrontend` call — `ExtendedFrontend`'s own public behavior
  unchanged.
- **Invariants introduced**: `Query` participates in discard-until-`Sync`
  absorption (Case 1); Extended messages rejected connection-fatally
  while `simpleQueryActive` (Case 2, frontend side); `Terminate` honored
  in every state including mid-Simple-response.
- **Tests required**: `internal/firewall/mixed_frontend_test.go`,
  mirroring `extended_frontend_test.go`'s existing structure — every
  dispatch-table row; discard-time `Query` absorption; boundary-violation
  connection-fatal rejection (using a fake runtime double reporting
  `ErrMixedBoundaryViolation`); a regression test confirming
  `ExtendedFrontend`'s existing test suite still passes unmodified after
  the shared-helper extraction.
- **Commit boundary**: `MixedFrontend` is constructed and exercised only
  by new unit tests, using the same fake-runtime-double pattern
  `extended_frontend_test.go` already uses — no `cmd/gateway` wiring yet.
- **Intentionally unsupported at this stage**: no live connection uses
  `MixedFrontend` yet.

### Stage D — Simple masking in the runtime

- **Files/types**: `internal/masking/row_mask.go` or a new
  `internal/masking/simple.go` (the extracted
  `BuildRowMaskPlanFromRowDescription` helper); refactor of
  `internal/masking/transformer.go`'s `handleRowDescription` to call it
  (behavior-preserving); `internal/gateway/extended_runtime.go` wiring of
  `simpleMaskPlan` set/clear/mask-call into the Stage B dispatch branch;
  `ErrSimpleMaskingFailed`.
- **Invariants introduced**: single-active-plan correctness (no
  generation keying needed); the four plan-clearing trigger points
  (`CommandComplete`/`EmptyQueryResponse`/`ErrorResponse`/`ReadyForQuery`);
  `MaskingErrorsTotal`'s exactly-once rule extended to the new error.
- **Tests required**: `internal/masking/transformer_test.go` — confirm
  zero behavior change after the extraction (run unmodified, must still
  pass byte-for-byte); a new multi-statement-Simple-Query masking test
  (row-returning statement, then non-row-returning statement, then a
  second row-returning statement, in one `Query` message, mixed masked/
  unmasked columns, `NULL` preservation); binary-target fail-closed;
  COPY fail-closed; metrics-hook increment tests mirroring
  `extendedMaskingHooks`' existing test coverage.
- **Commit boundary**: still no live `cmd/gateway` wiring — exercised via
  direct `ExtendedRuntime` unit tests, as in Stage B.
- **Intentionally unsupported at this stage**: no live connection yet.

### Stage E — configuration and live gateway wiring

- **Files/types**: `internal/config/config.go` (`QueryMode string`,
  `ExtendedQueryEnabled *bool`, `ProtocolConfig.Resolve()`,
  `ErrProtocolConfigConflict`, `ErrProtocolConfigInvalidMode`);
  `cmd/gateway/main.go` (`handleConn`'s three-way dispatch;
  `runMixedConnection`, constructing `MixedFrontend`+`ExtendedRuntime`
  via `RunStartupHandoff`, mirroring `runExtendedConnection`'s existing
  structure).
- **Invariants introduced**: the full configuration resolution table
  above; shared `RunStartupHandoff` for `mixed` and `extended_only`;
  `simple_only`/`extended_only` byte-for-byte unchanged.
- **Tests required**: `internal/config/config_test.go` additions for
  every row of the resolution table, including both conflict-error
  cases and the invalid-mode-string case; `cmd/gateway/main_test.go`
  additions mirroring `TestRunSimpleConnection_*`'s existing structure,
  for `runMixedConnection` — allowed Simple, blocked Simple, allowed
  Extended, blocked Extended `Parse`, an alternating sequence, a
  boundary-violation case; a regression test confirming
  `runSimpleConnection`/`runExtendedConnection` are unreachable-changed
  (existing tests for both continue to pass unmodified).
- **Commit boundary**: this is the first stage with a live, dispatchable
  `mixed` mode — but still no Docker/CI/docs changes.
- **Intentionally unsupported at this stage**: no `deploy/driver-compat`
  variant, no CI job, no `integration/pgxcompat` coverage yet — `mixed`
  mode exists and is unit/integration-tested in-process only.

### Stage F — pgx/Docker/CI/docs compatibility

- **Files/types**: new `integration/pgxcompat` test files (see
  [pgx compatibility acceptance criteria](#pgx-compatibility-acceptance-criteria));
  a new `deploy/driver-compat` config variant (e.g.
  `deploy/driver-compat/config-mixed.yaml`, `query_mode: mixed`) and any
  needed Compose parameterization, following the existing
  `deploy/driver-compat/docker-compose.yml`/`config.yaml` pattern exactly
  (dedicated ports, dedicated volume, no Prometheus/Grafana/dashboard);
  a new `.github/workflows/ci.yml` matrix entry or job, following the
  existing `driver-compat` job's exact structure (privacy-scan self-test
  first, then the stack, then the suite, then privacy-scanned failure
  diagnostics, then unconditional teardown); `scripts/driver-compat.ps1`
  extended with a mode parameter (or a sibling script) to select
  `simple_only`/`extended_only`/`mixed` config variants.
- **Invariants introduced**: none new — this stage proves the invariants
  introduced by Stages A–E hold against a real PostgreSQL 16/18 server
  and a real, unmodified pgx v5.10.0 client.
- **Tests required**: every item in
  [pgx compatibility acceptance criteria](#pgx-compatibility-acceptance-criteria).
- **Commit boundary**: this stage may reasonably span a few closely
  related commits (new test package, new Compose/CI wiring, doc updates)
  but should not be combined with any of Stages A–E's own protocol-core
  changes.
- **Intentionally unsupported at this stage, and beyond**: full cross-
  sub-protocol pipelining (Option A); TLS; `COPY`; drivers other than
  pgx v5.10.0.

## Compatibility claims and remaining limitations

This document, once implemented, will support claiming (not claimed
today):

- One connection, `mixed` mode, alternating Simple and Extended Query at
  clean boundaries, with pgx v5.10.0's `Ping`, zero-argument `Exec`, and
  convenience `Begin`/`Commit`/`Rollback` all succeeding.
- Text-format masking working identically whether reached via Simple or
  Extended Query.
- Policy evaluation, blocked-query recovery, and cancellation all working
  across both sub-protocols on one connection.

This document does **not**, and will not once implemented, support
claiming:

- Arbitrary cross-sub-protocol pipelining (explicitly out of scope — see
  [Non-goals](#non-goals)).
- Compatibility with any driver other than pgx v5.10.0.
- TLS, `COPY`, or binary-format masking-target support.
- A universal ORM/driver compatibility guarantee — this remains
  compatibility evidence for one driver, one gateway mode, not a general
  claim, exactly as `docs/postgresql-protocol.md`'s existing pgx section
  already states for `extended_only`.
- SQL-injection-proof policy enforcement — `sqlmatch`'s existing
  documented text-matching limitations are unchanged and apply equally
  to `Query` and `Parse` evaluation in `mixed` mode.

## pgx compatibility acceptance criteria

The later implementation (Stage F) must update
`integration/pgxcompat` with tests proving, on **one** connection, in a
new `mixed`-mode `deploy/driver-compat` configuration variant:

1. `conn.Ping(ctx)` succeeds (contrast with the existing
   `TestConnectionStartupAuthAndProtocolNegotiation`, which currently
   proves `Ping` *fails* against `extended_only` — a new, separate test
   against the `mixed` configuration proves the opposite, without
   weakening or removing the existing `extended_only` test).
2. `conn.Exec(ctx, sql)` with zero arguments succeeds (pgx's Simple-
   Protocol-forced path).
3. `conn.Begin(ctx)` (pgx's convenience API, `"begin"` via zero-argument
   `Exec`) succeeds.
4. A parameterized Extended Query (`conn.QueryRow(ctx, "SELECT ... WHERE
   id = $1", id)`) succeeds **inside** that transaction.
5. `tx.Commit(ctx)` (pgx's convenience API, `"commit"` via zero-argument
   `Exec`) succeeds.
6. A second `Begin` + a parameterized Extended Query + `tx.Rollback(ctx)`
   succeeds, and the rollback is observably effective.
7. Alternating Simple and Extended operations repeatedly (at least 5
   round trips of each, interleaved) remains stable — no error, no
   connection drop, matching
   [Chosen architecture](#chosen-architecture)'s "ordinary sequential pgx
   flows are unaffected" proof empirically.
8. Named prepared statements continue working according to the existing
   PostgreSQL/`State` lifecycle rules (reuse the existing
   `TestNamedPreparedStatement` pattern against the `mixed` configuration).
9. Text masking works identically via a Simple Query `SELECT` and via an
   Extended `QueryRow` on the same connection, same masked value.
10. A binary-format-requested masking target remains fail-closed in
    `mixed` mode's Extended path, exactly as in `extended_only` today
    (reuse `TestExtendedQueryBinaryMaskedColumnFailsClosed`'s pattern).
11. A Simple `Query` policy block is recoverable on the same connection
    (no reconnect, immediately usable — reuse
    `TestParseTimePolicyRejectionAndRecovery`'s pattern, adapted for
    `Query` instead of `Parse`).
12. An Extended `Parse` policy block still requires `Sync` recovery in
    `mixed` mode, unchanged from `extended_only` (regression test,
    proving mixed mode did not weaken Extended's existing recovery rule).
13. A real `CancelRequest` works during both an active Simple Query and
    an active Extended Query, on separate test connections, against both
    PostgreSQL 16 and 18 (reuse `TestCancelRequest`'s exact pattern,
    parameterized for which sub-protocol is active when cancellation is
    sent).
14. Both PostgreSQL 16 and 18 pass every test above (matrix, exactly like
    the existing `driver-compat` CI job).
15. No privacy markers appear in captured logs (reuse
    `scripts/lib/driver-compat-privacy.ps1`'s existing marker-scan
    machinery unchanged, with new canary values for the new tests'
    distinctive emails/blocked phrases).

**Explicitly required, not optional, per the task**:

- The existing `TestSimpleQueryRejectedOnExtendedOnlyGateway` is **not**
  removed or weakened — it continues to prove `extended_only` rejects
  Simple Query, using the existing `extended_only` `deploy/driver-compat`
  configuration, unchanged.
- A **new**, separate test (or configuration-parameterized variant)
  proves the same Simple-Query-rejection boundary now has a `mixed`-mode
  counterpart only for the out-of-boundary case (Case 2 above) — a
  well-behaved Simple Query at a clean boundary succeeds in `mixed`
  mode; only a boundary-violating one is rejected, and only then
  connection-fatally, per this document's own design.
- The existing default `simple_only` regression coverage
  (`cmd/gateway/main_test.go`'s `TestRunSimpleConnection_*`,
  `scripts/e2e-demo.ps1`, the root `docker-compose.yml`/`config.yaml`)
  is retained, unmodified, and continues to pass.

## Alternatives considered

| Alternative | Verdict | Reason |
|---|---|---|
| Running `Gate.Run` and `ExtendedRuntime` concurrently on the same connection | **Rejected** | Two independent goroutine pairs would both attempt to read the client `net.Conn`/write the backend `net.Conn` — violates the single-reader/single-writer invariant directly; no hand-off protocol between them is specified or needed once `ExtendedRuntime` is extended in place instead. |
| Switching between the old Simple goroutine pair and `ExtendedRuntime` mid-connection | **Rejected** | Requires tearing down and reconstructing decoders/writers/`TxState` mid-stream, with a real risk of losing or duplicating already-buffered bytes at the switch point; `RunStartupHandoff`'s own design principle ("ownership never overlaps... no private prefetch buffer that could lose or duplicate bytes") is the reason a similar one-time, clean hand-off works for startup, but a *repeated*, steady-state version of the same problem (potentially many times per connection) is a fundamentally harder, unbounded-frequency version of the same hazard — not adopted. |
| Allowing multiple client writers through `SerializedWriter` | **Rejected** | `SerializedWriter` (used only by `simple_only`'s `Gate`/`Transformer` pair) guarantees byte-level non-interleaving, **not** semantic response ordering across independent goroutines — exactly the distinction `docs/design/0001-extended-query-review-checklist.md`'s "Response ordering" section already establishes as insufficient. Not reused for mixed mode; `processActions` (single goroutine, no mutex needed) remains the sole client writer instead. |
| Forwarding `Query` directly from the frontend goroutine | **Rejected** | Violates "no direct backend write from multiple frontend handlers" and "no direct client write from the frontend policy layer" — `MixedFrontend` never writes to either transport; only the runtime event-loop does, exactly as `ExtendedFrontend` already never writes today. |
| Letting `masking.Transformer` own the backend during Simple responses | **Rejected** | Would reintroduce a second transport-owning component alongside `ExtendedRuntime`, the exact problem this design exists to avoid; `Transformer`'s masking *logic* (via the extracted `BuildRowMaskPlanFromRowDescription` helper) is reused, but its I/O ownership is not. |
| Automatically choosing a connection mode from the first steady-state message | **Rejected** | Explicit non-goal (task requirement and this document's own [Non-goals](#non-goals)) — the mode is a configuration decision, read once, never inferred from traffic; auto-detection would also make `RunStartupHandoff`'s shared, mode-agnostic design meaningless, since the mode must be known before startup completes in order to decide which runtime to construct afterward. |
| Treating `Query` as an ordinary Extended `OperationKind` | **Rejected** | `Query` has no Parse/Bind identity, no generation, no multi-cycle pipelining need, and a fundamentally different response grammar (see [Simple Query response grammar](#simple-query-response-grammar)) — forcing it into `OperationKind`/`PendingOperation`/`ResponseSequencer` would require either inventing a fake statement/portal generation for every `Query` (semantically wrong — PostgreSQL itself has no such object for Simple Query) or special-casing the sequencer extensively for a grammar it was never designed to model, both worse than the chosen mutually-exclusive-tracker design. |
| Arbitrary cross-sub-protocol pipelining in the first stage | **Rejected for this stage** (Option A) | See [The supported mixed-routing boundary model](#the-supported-mixed-routing-boundary-model-b-chosen) — not ruled out forever, but explicitly deferred; this stage prioritizes a provably correct, minimal-risk design over maximal generality. |
| Parsing SQL to infer transaction state | **Rejected** | Explicitly forbidden by the task and by [Transaction-state behavior](#transaction-state-behavior) — `BEGIN`/`COMMIT`/`ROLLBACK` text is never inspected; only real backend `ReadyForQuery` frames are authoritative, exactly matching the existing Extended-only design principle (`docs/design/0001-extended-query.md`'s own "Never infer transaction status from SQL text" discipline, now explicitly extended to Simple Query too). |
| Reconnecting to PostgreSQL when changing sub-protocol | **Rejected** | Would break `BackendKeyData`/session-scoped state (temp tables, session variables, advisory locks, the real transaction itself) and contradicts Goal 2's explicit "same connection" requirement; also structurally impossible to do transparently to the client, which expects one persistent `BackendKeyData` for its whole session (see [Protocol requirements](#protocol-requirements), `CancelRequest`'s dependence on a stable, session-long secret key). |
| Implementing mixed routing only as a pgx-specific workaround | **Rejected** | Explicitly forbidden by the prior branch's own instructions and by this document's design: every rule above (boundary predicate, `SimpleQueryTracker`'s grammar, policy/masking reuse) is generic PostgreSQL protocol behavior, with no driver-name detection or pgx-specific branch anywhere in the design. pgx is the *acceptance test*, not a design input beyond confirming which real-world call patterns (`Ping`, zero-arg `Exec`, `Tx`) motivate the feature. |

## Review checklist

- [ ] **Single transport ownership**: exactly one client reader (frontend
      goroutine), one backend reader (backend-reader goroutine), one
      client writer, one backend writer, one `protocol.State` owner, one
      active response-sequencing subsystem at any instant — all
      (re-)stated in [Ownership model](#ownership-model) and preserved
      per [Preserve one steady-state transport owner](#ownership-model).
- [ ] **Registration-before-forwarding**: preserved for both Simple
      (`ApplyAllowedSimpleQuery()` before `writeAll(r.backend,...)`) and
      Extended (unchanged) — see
      [Unified runtime request model](#runtime-state-machine) /
      [Runtime state machine](#runtime-state-machine).
- [ ] **Clean-boundary definition**: precise, four-condition predicate,
      evaluated only inside the runtime event-loop goroutine, stated in
      [Chosen architecture](#chosen-architecture).
- [ ] **Simple response grammar**: full transition table, every backend
      message type addressed, in
      [Simple Query response grammar](#simple-query-response-grammar).
- [ ] **Multi-statement responses**: explicitly modeled (repeated
      `AwaitingFirstMessage`↔`AwaitingGroupOrReady`↔`InRows` transitions
      within one `Query` message), O(1) memory regardless of statement
      count.
- [ ] **Async messages**: checked before ordering validation, in both
      the Extended (unchanged) and new Simple dispatch paths.
- [ ] **Transaction status**: single authoritative source
      (`protocol.State.TransactionStatus()`), never inferred from SQL
      text, `protocol.TxState` explicitly unused in mixed mode — see
      [Transaction-state behavior](#transaction-state-behavior).
- [ ] **Unnamed object lifecycle**: `ApplyAllowedSimpleQuery()` (existing,
      previously unused) reused exactly per the quoted official
      PostgreSQL rule; named objects explicitly unaffected.
- [ ] **Synthetic policy response**: blocked `Query` gets a complete,
      self-terminating `ErrorResponse`+`ReadyForQuery` (no `Sync` needed),
      explicitly contrasted with blocked Extended `Parse`'s
      discard-until-`Sync` requirement — see
      [Transaction-state behavior](#transaction-state-behavior).
- [ ] **Extended discard-until-`Sync`**: unchanged ownership and
      mechanism, extended in scope to also absorb `Query` during discard
      (Case 1) — never bypassed.
- [ ] **Masking isolation**: single active `RowMaskPlan` for Simple
      (mirrors `Transformer` exactly, no generation-keyed cache needed);
      `ExtendedTracker` completely unchanged for Extended.
- [ ] **Binary fail-closed**: reused, unchanged (`ErrRowMaskBinaryTarget`
      via the same `masking.MaskDataRow` call).
- [ ] **COPY fail-closed**: reused pattern, new sentinel
      (`ErrSimpleQueryCOPYUnsupported`), same terminal behavior.
- [ ] **Bounded resources**: every new structure is O(1) or reuses an
      existing bound — see [Resource limits](#resource-limits).
- [ ] **Fixed safe errors**: every new sentinel listed in
      [Error and shutdown behavior](#error-and-shutdown-behavior)
      is a fixed, value-free category; none wraps arbitrary transport/SQL
      text.
- [ ] **Shutdown causality**: entirely inherited, unmodified, from
      `ExtendedRuntime.Run`'s existing `shutdownCause` design.
- [ ] **Default Simple-only preservation**: `simple_only` behavior is
      byte-for-byte unchanged (no code path in `runSimpleConnection` is
      touched; `Transformer`'s only change is a behavior-preserving
      helper extraction, verified by its unmodified existing tests).
- [ ] **Extended-only preservation**: `extended_only` behavior is
      byte-for-byte unchanged (`ExtendedFrontend`'s own logic is
      extracted into shared helpers, not modified; its existing tests
      must pass unmodified).
- [ ] **pgx mixed-mode acceptance**: full 15-item list in
      [pgx compatibility acceptance criteria](#pgx-compatibility-acceptance-criteria).
- [ ] **PostgreSQL 16/18**: required for every acceptance-criteria test,
      matching the existing `driver-compat` CI matrix pattern.
- [ ] **Privacy**: no password/SASL/startup-parameter/Bind-value/
      DataRow-value/cancellation-key/PID/`ErrorResponse`-field/statement-
      or-portal-name content in any log or fixed error, in either
      sub-protocol's new code path — see
      [Privacy and logging guarantees](#privacy-and-logging-guarantees).
- [ ] **Test/fuzz/race plan**: stated per stage in
      [Staged implementation plan](#staged-implementation-plan) and
      summarized in [Test strategy](#test-strategy).
- [ ] **Remaining limitations**: stated plainly in
      [Compatibility claims and remaining limitations](#compatibility-claims-and-remaining-limitations)
      — no universal driver/ORM claim, no arbitrary pipelining claim, no
      TLS/COPY/binary-masking claim.

### Sign-off

- [ ] All sections above have been reviewed against the current text of
      this document, not from memory of an earlier draft.
- [ ] Every file/type/method reference has been checked against the
      actual current source (commit `0d9505c` or later) before this
      checklist is signed off, since line numbers and signatures drift as
      the codebase changes.
- [ ] Any unchecked item above has either been resolved by an edit to
      this document, or explicitly accepted as a documented open
      question/deferred decision before implementation work (Stage A)
      begins.

**Genuinely open questions** (deliberately left open, not decided
defensively):

1. Whether `ForwardSimpleQuery`'s Case-2 boundary-violation error should
   eventually carry enough structured information for `MixedFrontend` to
   distinguish "Extended work pending" from "Simple response already
   active" for logging purposes (currently: a single fixed category
   covers both, per [Error categories](#error-and-shutdown-behavior); a
   future revision could split this into two sentinels if operational
   experience shows the distinction is operationally useful — this
   document does not decide that now).
2. Whether `simple_only` mode should eventually be migrated onto
   `RunStartupHandoff` for architectural uniformity (this document's
   [Configuration and migration behavior](#configuration-and-migration-behavior)
   section notes this is possible but explicitly does not require it —
   left for a future, separately justified stage, since it is not needed
   for any goal this document sets).
3. The exact numeric values for the resource limits noted as "reused,
   defensive" in [Resource limits](#resource-limits) (e.g. whether the
   Simple synthetic-frame bound should literally reuse
   `SequencerLimits.MaxSyntheticFrameBytes`'s default or have its own,
   independently-tunable constant) — deferred to Stage B's implementation,
   consistent with 0001's own precedent of not finalizing exact numbers
   in the design document itself.

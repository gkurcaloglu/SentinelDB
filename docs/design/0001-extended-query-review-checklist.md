# Extended Query Protocol design review checklist

Companion to [docs/design/0001-extended-query.md](0001-extended-query.md).
This checklist is for reviewing the **design**, before any implementation
is approved to begin. It is not a test plan and not an implementation
task list (see the design document's own
[Implementation decomposition](0001-extended-query.md#implementation-decomposition)
and [Test matrix](0001-extended-query.md#test-matrix) for those).

Every item below should be checked against the design document's actual
content — not against intent or memory of a discussion. If an item cannot
be verified from the document as written, it should be treated as unchecked.

## Protocol correctness

- [ ] `Parse`/`Bind`/`Describe`/`Execute`/`Close`/`Flush`/`Sync`/`Terminate`
      message semantics match the official PostgreSQL protocol
      documentation (message formats, protocol flow), not a
      driver-specific or blog-sourced description.
- [ ] Named vs. unnamed statement/portal lifetime and replacement
      semantics are described accurately (unnamed = implicitly replaced;
      named = explicit `Close` required, reuse-without-close is a real
      server error).
- [ ] **Statement and portal lifetimes are described as distinct, not
      conflated**: a named prepared statement persists until `Close` or
      session end (unaffected by transaction boundaries); a named portal
      persists only until `Close` **or the end of the current
      transaction**, whichever comes first.
- [ ] The design specifies concrete backend-protocol evidence (not
      guesswork) for how SentinelDB detects a transaction has ended, and
      that this evidence is used to invalidate open portal registry
      entries.
- [ ] **Transaction-end detection triggers on the *reported value* of a
      real `ReadyForQuery` (`'I'`), not on a transition from a prior
      status** — a transition-only rule misses the ordinary case of an
      implicit Extended Query transaction observed as `I → I` (no `'T'`
      ever surfaces, since `ReadyForQuery` is only sent after `Sync`, by
      which point an implicit transaction has already closed).
- [ ] The design explicitly covers `I → T` (entering an explicit
      transaction, no invalidation), `T → T` (remaining in one across
      multiple cycles, no invalidation), `E → E` (remaining in a failed
      transaction, no invalidation), and confirms invalidation never
      depends on comparing to a previous status.
- [ ] A Simple Query message's effect on the unnamed prepared statement
      and unnamed portal is explicitly documented, not omitted.
- [ ] The distinction between statement-level `Describe` (always
      text-format `RowDescription`) and portal-level `Describe`
      (format-accurate `RowDescription`) is correctly captured.
- [ ] `Execute`'s row-count limit and `PortalSuspended` continuation
      semantics are correctly described.
- [ ] Pipelining and positional (FIFO) response correlation are correctly
      described — no keyed-by-name correlation is proposed for backend
      acknowledgements that carry no name.
- [ ] `Sync`'s dual role (implicit transaction closure + error-recovery
      boundary) is correctly and separately addressed.
- [ ] **`Execute` is specified as never producing `RowDescription`** —
      its response is limited to `DataRow*` followed by exactly one of
      `CommandComplete`/`EmptyQueryResponse`/`PortalSuspended`/
      `ErrorResponse`. `RowDescription` is sourced only from `Describe`.

## State lifecycle

- [ ] The proposed state model distinguishes `pending` (forwarded,
      unacknowledged), `committed` (backend-acknowledged), and `blocked`
      (never forwarded) for both statements and portals.
- [ ] State (a generation's `pending`/`committed`/`blocked` status) is
      committed only on the corresponding backend acknowledgement
      (`ParseComplete`/`BindComplete`/`CloseComplete`), never optimistically
      at forward-time. **The design explicitly carves out *resolvability*
      of the unnamed slot as a distinct, narrower exception to this rule**
      (the "current pointer" moves at forward time for `""`, not at
      acknowledgement time) and states why — this is not a violation of
      the general principle, but it must be explicit, not silently
      inconsistent with it.
- [ ] The pending-operation queue's FIFO correlation model is consistent
      with pipelining (multiple in-flight, unacknowledged operations).
- [ ] Replacement semantics for the unnamed statement/portal slot are
      described, including the effect (or explicit non-effect) on portals
      already bound from a since-replaced unnamed statement, **and are
      explicitly distinguished from named-object semantics — not treated
      as the same rule** (§ below).
- [ ] **`Close` behavior is asymmetric and correctly stated**: closing a
      statement cascades to implicitly close every portal built from it
      (this is official, documented PostgreSQL behavior, not an optional
      design choice); closing a portal never affects its statement.
- [ ] The statement-close cascade is specified to commit locally only on
      the matching `CloseComplete` (not eagerly when `Close` is
      forwarded), and to remove all dependent portal registry entries in
      the same step.
- [ ] A later reference to a portal removed by the statement-close cascade
      (or by transaction-end invalidation) is specified to fail closed,
      not to be silently resolved against stale metadata.
- [ ] Registry entries are keyed so that a named `Parse`/`Bind` for a name
      that already has a committed or pending entry cannot overwrite or
      destabilize that existing entry before the real server acknowledges
      the new one (e.g. generation IDs, pending overlays, or an
      equivalent explicit mechanism — not a bare name-keyed map).
- [ ] The design states explicitly what happens to a failed duplicate
      named `Parse`/`Bind`: the pre-existing committed statement/portal
      must remain intact and usable.
- [ ] **Named and unnamed replacement-failure semantics are explicitly
      described as different, not as one shared rule:**
      - A conflicting **named** `Parse`/`Bind` is rejected without ever
        replacing/touching the old object — a failed named generation
        therefore leaves the previously committed named object intact.
      - A new **unnamed** `Parse`/`Bind`, once *forwarded* (allowed by
        policy), immediately retires the previous unnamed statement's/
        portal's resolvability — **before** `ParseComplete`/`BindComplete`
        is known — because the real server destroys the old unnamed
        object as an early side effect of merely processing the new one,
        regardless of whether the new one succeeds. A failed unnamed
        replacement (`ErrorResponse` instead of the expected
        acknowledgement) does **not** restore the previous unnamed
        object — the slot is left empty/unresolvable.
      - A **locally blocked** (never-forwarded) new unnamed `Parse`/`Bind`
        does not disturb the previous unnamed object at all, since the
        real server never saw it.
- [ ] Historical (superseded) statement/portal generations are specified
      to be retained internally, immutably, only as long as a portal entry
      still references them at `Bind` time — and are explicitly never
      "the current slot" again once superseded.

## Local rejection recovery

- [ ] The discard-until-`Sync` state is entered on any locally-generated
      `ErrorResponse` during an Extended Query cycle, not just on a
      blocked `Parse`.
- [ ] **Discard-until-`Sync` begins atomically at the moment the local
      block/rejection *decision* is accepted and its synthetic unit is
      *submitted* (enqueued) — not when that unit's `ErrorResponse` bytes
      are actually drained and become client-visible.** These two moments
      must be treated as different in the design, since a synthetic unit
      can sit queued behind unfinished earlier pass-through units for an
      arbitrary amount of time.
- [ ] A test scenario proves this: an allowed operation A is still
      pending; a blocked operation B is queued behind it; further
      frontend messages (C) that arrive **before** B's `ErrorResponse` is
      client-visible are still discarded and never forwarded.
- [ ] Exactly one `ErrorResponse` is generated per local rejection event;
      subsequent discarded messages generate no further response.
- [ ] `Terminate` is explicitly exempted from discard-mode suppression.
- [ ] The mixed/pipelined case (some operations legitimately forwarded
      before a later block in the same cycle) is addressed, not just the
      fully-local-block case.
- [ ] The design states explicitly whether `Sync` is forwarded to the real
      server in every case, including when nothing was forwarded earlier
      in the cycle, and justifies that choice.
- [ ] `ReadyForQuery` production is unambiguous: locally synthesized vs.
      relayed from the real server, with a stated rationale either way.

## Upstream synchronization

- [ ] The design states an explicit invariant that the gateway never sends
      the real server a message referencing an object the real server was
      never told about.
- [ ] The design explains why the real server's own cycle/transaction
      bookkeeping cannot drift from the client-facing view under the
      proposed forwarding rules.
- [ ] Terminate-before-`Sync` behavior is specified.
- [ ] A state diagram (or equivalent) is present and its transitions match
      the prose description.
- [ ] **A genuine upstream `ErrorResponse` (not one SentinelDB generated
      itself) is tracked as a distinct, separate state from the
      client-facing discard-until-`Sync` flag**, not conflated with it.
- [ ] The design specifies that all later pending operations in the same
      cycle are immediately abandoned (never left waiting) once a real
      upstream `ErrorResponse` is observed, since the real server will not
      acknowledge them individually.
- [ ] The design distinguishes "a real `ErrorResponse` in place of an
      expected acknowledgement" (normal, protocol-legal) from "a message
      matching no recognized pending operation at all" (true
      desynchronization, fail closed) — these must not be handled
      identically.
- [ ] The design specifies that objects already committed in an earlier,
      completed cycle are unaffected by a real upstream error in a later
      cycle.
- [ ] Server-discard-until-`Sync` and pending-operation abandonment are
      scoped **per cycle ID**, not as a single connection-wide flag — a
      real error in one pipelined cycle must not abandon or otherwise
      affect a different, already-forwarded, later cycle's operations.

## Pipeline cycle identities

- [ ] An explicit, monotonically increasing per-connection cycle ID is
      defined, and every pending-operation entry and response-plan unit
      is stated to carry it.
- [ ] The design states precisely when a cycle ID increments (at `Sync`,
      for the *next* frontend message) and that `Sync` is always the
      final response-plan unit for its own cycle.
- [ ] Real `ReadyForQuery` messages are matched to outstanding `Sync`
      units **FIFO** (oldest first), not assumed to belong to "the current
      cycle" — this must be explicit given that multiple cycles can be
      pipelined ahead of their `ReadyForQuery`s.
- [ ] Per-cycle state (pending operations, response-plan units, discard
      flags) is specified to be released only after that specific cycle's
      matching real `ReadyForQuery`.
- [ ] Test scenarios exist for at least: two successful cycles pipelined
      before either `ReadyForQuery` arrives; one cycle erroring while a
      second, already-forwarded cycle succeeds; a local block in one
      cycle not affecting another already-forwarded cycle (in both
      orderings); and correct `ReadyForQuery`-to-`Sync` FIFO correlation
      under multi-cycle pipelining.
- [ ] The resource-exhaustion discussion accounts for unbounded
      *outstanding cycle count* as a distinct risk from registry size or
      per-cycle pending-operation-queue depth.

## Event-driven sequencer

- [ ] **The design does not rely on `masking.Transformer`'s (or any
      backend-socket-reading component's) blocking read loop as the sole
      mechanism for noticing newly enqueued synthetic units.** A loop
      whose only wake-up source is backend traffic cannot notice a unit
      enqueued while the backend socket is idle.
- [ ] An explicit, dedicated response sequencer component is designed,
      woken by **either** of two independent event sources: new
      response-plan units from `firewall.Gate`, or decoded backend frames
      from a dedicated backend reader.
- [ ] **Exactly one goroutine owns the response-plan queue and the
      pending-operation queue**, and is the only component that writes
      client-bound Extended Query bytes — `firewall.Gate` and the backend
      reader only ever submit events, never mutate either queue directly.
- [ ] Event types, channel ownership (single writer, single reader per
      channel), and queue ownership are all stated explicitly, not implied.
- [ ] Backpressure is addressed explicitly: the backend reader's `Read()`
      must never be blocked by a stalled client write, and `Gate`'s client
      read must never be blocked by a stalled client write either — the
      actual bound on unconsumed work is the already-recommended
      pending-operation/outstanding-cycle caps, not an accidental deadlock
      from a blocked channel send.
- [ ] What happens on client-socket failure, backend-socket failure (while
      a synthetic unit is pending, and while a pass-through unit is
      pending), and client disconnect while both event sources are active
      is each specified explicitly.
- [ ] **Shutdown and cancellation ownership is explicit**: the sequencer's
      termination is derived from its two input channels closing, which in
      turn follows from the existing shutdown mechanism (force-closing
      tracked connections) unblocking `Gate`'s and the backend reader's
      socket reads — no new, separate cancellation primitive is silently
      assumed or left unstated.
- [ ] A Mermaid component/sequence diagram illustrates the three
      cooperating components (Gate, backend reader, sequencer) and the two
      event channels.
- [ ] Test scenarios exist for: blocked-first with no backend traffic;
      a synthetic unit enqueued while the backend reader's `Read()` is
      blocked; a synthetic unit queued behind an unfinished pass-through
      unit; backend disconnect while a synthetic unit is pending; client
      disconnect while both event sources are active; and shutdown without
      goroutine leaks.

## Response ordering

- [ ] The design explicitly acknowledges that a mutex/`SerializedWriter`
      alone guarantees byte-level non-interleaving but **not** semantic
      response ordering across independent goroutines, and does not treat
      the mutex as a substitute for an ordering mechanism.
- [ ] An explicit ordered-response mechanism is designed (e.g. a unified
      response-plan queue, an ordering barrier tied to operation
      count/generation, or an equivalent with its own correctness
      argument) — not left as an assumption.
- [ ] The design states, with an explicit correctness argument (not just
      an assertion), why real responses for earlier-forwarded operations
      are always delivered to the client before a later, locally
      synthesized `ErrorResponse` for a subsequently blocked operation in
      the same pipelined cycle.
- [ ] A Mermaid sequence diagram illustrates the chosen ordering mechanism
      for a concrete mixed (allowed-then-blocked) pipeline.
- [ ] Explicit invariants for the ordering mechanism are stated
      (e.g. "a synthetic unit is never drained before every earlier unit
      is fully drained").
- [ ] Test scenarios exist for: pipelined allowed-before-blocked,
      blocked-first (no preceding allowed operation), and multiple
      would-be-blocked messages before a single `Sync` (confirming only
      one `ErrorResponse`/response unit is produced).
- [ ] **A real `ErrorResponse` on an earlier unit is specified to suppress
      every later unit in the same cycle up to (not including) `Sync`,
      including later *synthetic* units** — a locally blocked operation
      queued after an operation that later fails for real must not also
      produce its own client-visible error, matching genuine PostgreSQL
      behavior (only one error is ever visible per cycle in that
      scenario).
- [ ] The design states this suppression check happens at **drain time**,
      not enqueue time, since whether an earlier operation will fail is
      not known when a later operation is blocked.
- [ ] The cycle's `Sync` unit is explicitly stated to never be skipped,
      regardless of an earlier real failure in the same cycle.
- [ ] A Mermaid sequence diagram illustrates the real-error-precedence
      scenario specifically (distinct from the base ordering diagram).
- [ ] Test scenarios exist for: an earlier real `Parse`/`Bind`/`Execute`
      error each suppressing a later local block, and (as a regression
      guard) an earlier operation succeeding so the later local block is
      emitted normally.

## Frontend/backend message completeness

- [ ] The design explicitly states which forwarded frontend messages
      create **no** response-plan unit (`Flush`, `Terminate`), separate
      from those that do (`Parse`/`Bind`/`Describe`/`Execute`/`Close`/
      `Sync`).
- [ ] `Flush` is specified as forwarded but untracked, and its only effect
      on the response plan is possibly hastening delivery of an
      **already-enqueued** unit's backend traffic.
- [ ] `Terminate` is specified as ending the connection immediately with
      no unit and no expectation of further response.
- [ ] `NoticeResponse`, `ParameterStatus`, and `NotificationResponse` are
      explicitly designed as an always-valid, asynchronous category that:
      is relayed through the sole ordered client writer, preserves backend
      arrival order, never completes or consumes a pending operation, and
      never alters statement/portal/cycle/discard state.
- [ ] The design states explicitly that these three async message types
      are recognized **before** any "unexpected ordering" check, not
      handled as a special case of it.
- [ ] Authentication/startup-phase messages are explicitly described as
      out of scope for the Extended Query response planner (handled
      entirely by the existing, unchanged startup path).
- [ ] Test scenarios exist for: `Flush` between `Execute` and `Sync`;
      repeated `Flush`; `NoticeResponse` during `Execute`'s `DataRow`s;
      `ParameterStatus` between `CommandComplete` and `ReadyForQuery`;
      `NotificationResponse` while nominally idle; an asynchronous message
      arriving while a synthetic unit is pending drain; and `Terminate`
      during an incomplete cycle.

## Masking safety

- [ ] The design explains why a statement-level `Describe`'s
      `RowDescription` format codes cannot be trusted for a later
      `Execute`'s actual wire format.
- [ ] The design identifies the *authoritative* source of a portal's
      actual result wire format (the creating `Bind`'s result-format-codes).
- [ ] Per-portal (not per-connection-global) shape/format tracking is
      proposed, replacing today's single-active-result-set assumption.
- [ ] `PortalSuspended` → later `Execute` reuses cached masking metadata
      rather than re-deriving it.
- [ ] Multiple concurrently-open portals are addressed, not just
      multiple sequential result sets.

## Binary formats

- [ ] A masking-target column returned in binary format is specified to
      fail closed, not to be silently forwarded or silently coerced to
      text.
- [ ] Non-target binary-format columns are specified to be left unchanged
      (forwarded, not masked, not rejected).
- [ ] The design does not propose treating binary bytes as UTF-8 text
      under any circumstance.
- [ ] Binary-format *parameters* (`Bind`) are addressed (even if deferred),
      not silently omitted from scope.

## Transaction state

- [ ] The design confirms the existing shared `*protocol.TxState`
      component needs no structural change, only additional call sites.
- [ ] The design explains how the real server's `ReadyForQuery` (relayed,
      not synthesized, per the local-rejection design) keeps `TxState`
      accurate for later use, including later Simple Query use on the same
      connection.

## Pipelining

- [ ] Multiple in-flight (forwarded, unacknowledged) operations are
      explicitly supported by the pending-operation queue design.
- [ ] A pipelined sequence mixing allowed and blocked operations in the
      same `Sync` cycle is explicitly walked through, not just a
      single-operation-per-cycle case.
- [ ] `Flush`'s behavior in both normal and discard-until-`Sync` modes is
      specified.

## Resource limits

- [ ] Prepared-statement and portal registry exhaustion are identified as
      attack surfaces.
- [ ] Pending-operation queue depth (pipelining-driven resource
      consumption) is identified as an attack surface distinct from
      registry size alone.
- [ ] The design is explicit that specific numeric limits are recommended
      but *not* finalized/implemented by this document.

## Observability

- [ ] The design explicitly prohibits SQL text, parameter values,
      client-supplied statement names, client-supplied portal names, and
      free-form error strings as metric labels.
- [ ] Existing metrics that remain valid unchanged are identified by name.
- [ ] Any candidate new metrics are proposed with bounded cardinality by
      construction, not merely by convention.

## Compatibility claims

- [ ] The design does not claim universal ORM/driver compatibility.
- [ ] "Required for first implementation" vs. "explicitly deferred" vs.
      "must be rejected fail-closed" are three distinct, non-overlapping
      lists.
- [ ] Mixing Simple Query and Extended Query on the same connection over
      time is explicitly addressed, **including that an *allowed* (not
      locally blocked) Simple Query destroys the real server's unnamed
      statement and unnamed portal**, and that SentinelDB's own
      unnamed-slot registry entries are invalidated to match (named
      entries must be unaffected either way).
- [ ] **This invalidation is specified to happen atomically, immediately
      before the `Query` bytes are forwarded upstream — not deferred to
      that query's own `ReadyForQuery`, and not conditioned on the query's
      own success/failure.** A locally blocked Simple Query (never
      forwarded) is explicitly specified to invalidate nothing.
- [ ] The design states that in-flight response-correlation snapshots
      (pass-through units/pending-operation entries already forwarded
      before the Simple Query, referencing an older statement/portal
      generation) do not depend on the mutable "current" unnamed pointer
      and remain valid until their own responses complete.

## Tests

- [ ] The test matrix includes unit, state-machine, malformed-input, fuzz,
      integration, real-driver E2E, concurrency, race, shutdown, and
      sensitive-log-scan categories — not just happy-path functional
      tests.
- [ ] The blocked-`Parse`-then-pipelined-continuation scenario has a named
      test entry, not just prose discussion.
- [ ] Portal suspension/resume has a named test entry.
- [ ] A test entry confirms Simple Query behavior is unaffected after an
      Extended Query cycle completes on the same connection.
- [ ] Named test entries exist for all four transaction-end scenarios
      (implicit closure at `Sync`, explicit `COMMIT`, explicit `ROLLBACK`,
      failed-transaction `ROLLBACK`) and for a portal reference after
      transaction end.
- [ ] Named test entries exist for a Simple Query issued after an unnamed
      statement/portal was created via Extended Query, covering both the
      invalidation itself and a later reference to the invalidated object.
- [ ] Named test entries exist for a duplicate named `Parse`/`Bind` whose
      failure must leave the pre-existing committed object intact.
- [ ] Named test entries exist for: an allowed Simple Query immediately
      followed by a pipelined `Bind`/`Execute` referencing the *former*
      unnamed statement/portal (sent before that Simple Query's own
      `ReadyForQuery`); a Simple Query that later returns `ErrorResponse`
      still having invalidated the unnamed slots; a locally blocked Simple
      Query preserving the upstream-backed unnamed objects; and named
      objects surviving both allowed and blocked Simple Query messages.
- [ ] Named test entries exist for: successful and failed unnamed `Parse`
      replacement, successful and failed unnamed `Bind` replacement, and
      historical generations retained only while a live portal reference
      exists.

## Documentation truthfulness

- [ ] The design document's "Status" section states plainly that no
      implementation exists yet.
- [ ] The "Existing SentinelDB architecture" section describes only
      current, verifiable behavior (with file/function references), never
      planned behavior presented as already-existing.
- [ ] The design does not alter or imply an alteration of the current
      README roadmap status (Extended Query remains "not supported" until
      an implementation actually ships).
- [ ] Every specific file/function reference in the design document
      (e.g. `internal/firewall/gate.go:213`) is checked against the actual
      current source before this checklist is signed off, since line
      numbers drift as the codebase changes.
- [ ] Open questions in the design document are genuinely open (not
      settled decisions written defensively as "open" to avoid commitment).
      Specifically confirm the five that must remain open: binary
      parameter timing, proactive `Describe` vs. fail-closed unknown
      shape, concrete numeric resource limits, real-ORM compatibility
      strategy, and blocked-`Parse` metric choice.
- [ ] **No section still claims** any of the following, all confirmed
      wrong by review: transaction completion is detected only by a
      `'T'`/`'E'` → `'I'` transition (misses the `I → I` implicit-cycle
      case); all synthetic errors are always emitted regardless of
      earlier real failures; a single global discard boolean is
      sufficient across multiple pipelined `Sync` cycles; every forwarded
      frontend message necessarily produces a backend response (`Flush`
      and `Terminate` do not); every backend message must correlate to
      the pending-operation head (asynchronous messages do not).
- [ ] **No section still claims**, from the third review pass: that
      `masking.Transformer`'s (or any) blocking backend-socket-read loop
      alone can observe newly enqueued response-plan units; that discard-
      until-`Sync` begins only after the synthetic `ErrorResponse` is
      physically written to the client; that all generation-replacement
      failures (named and unnamed alike) preserve the previous object;
      that unnamed-slot replacement commits (becomes resolvable) only on
      `ParseComplete`/`BindComplete`; that Simple Query's unnamed-slot
      invalidation waits for that query's `ReadyForQuery`; or that named
      and unnamed replacement semantics are the same rule applied twice.

## Sign-off

- [ ] All sections above have been reviewed against the current text of
      `docs/design/0001-extended-query.md`, not from memory of an earlier
      draft.
- [ ] Any unchecked item above has either been resolved by an edit to the
      design document, or explicitly accepted as a documented open
      question / deferred decision before implementation work begins.

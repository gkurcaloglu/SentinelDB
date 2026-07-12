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
- [ ] State is committed only on the corresponding backend acknowledgement
      (`ParseComplete`/`BindComplete`/`CloseComplete`), never optimistically
      at forward-time.
- [ ] The pending-operation queue's FIFO correlation model is consistent
      with pipelining (multiple in-flight, unacknowledged operations).
- [ ] Replacement semantics for the unnamed statement/portal slot are
      described, including the effect (or explicit non-effect) on portals
      already bound from a since-replaced unnamed statement.
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

## Local rejection recovery

- [ ] The discard-until-`Sync` state is entered on any locally-generated
      `ErrorResponse` during an Extended Query cycle, not just on a
      blocked `Parse`.
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
      time is explicitly addressed, **including that a forwarded Simple
      Query destroys the real server's unnamed statement and unnamed
      portal**, and that SentinelDB's own unnamed-slot registry entries
      are invalidated to match (named entries must be unaffected).

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

## Sign-off

- [ ] All sections above have been reviewed against the current text of
      `docs/design/0001-extended-query.md`, not from memory of an earlier
      draft.
- [ ] Any unchecked item above has either been resolved by an edit to the
      design document, or explicitly accepted as a documented open
      question / deferred decision before implementation work begins.

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
- [ ] `Close` behavior (portal survives statement close and vice versa) is
      addressed.

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
      time is explicitly addressed.

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

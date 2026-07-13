package masking

import (
	"errors"
	"testing"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

func newTracker(t *testing.T, enabled bool, columns []string) *ExtendedTracker {
	t.Helper()
	tr, err := NewExtendedTracker(NewConfig(enabled, columns), DefaultExtendedLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return tr
}

func rowDescBody(fields []protocol.RowField) []byte {
	// Reuse rowdescription.go's own parser as the oracle by round-tripping
	// through the same encoder transformer_test.go already uses for
	// RowDescription bodies (minus the tag+length prefix).
	full := encodeRowDescription(fields)
	return full[5:]
}

// --- Construction / limits -------------------------------------------

func TestExtendedTracker_InvalidLimitsRejected(t *testing.T) {
	cases := []ExtendedLimits{
		{MaxStatementShapes: 0, MaxPortalShapes: 1, MaxFieldsPerShape: 1, MaxTotalShapeFields: 1},
		{MaxStatementShapes: 1, MaxPortalShapes: 0, MaxFieldsPerShape: 1, MaxTotalShapeFields: 1},
		{MaxStatementShapes: 1, MaxPortalShapes: 1, MaxFieldsPerShape: 0, MaxTotalShapeFields: 1},
		{MaxStatementShapes: 1, MaxPortalShapes: 1, MaxFieldsPerShape: 1, MaxTotalShapeFields: 0},
	}
	for i, l := range cases {
		if _, err := NewExtendedTracker(NewConfig(true, nil), l); !errors.Is(err, ErrInvalidExtendedLimits) {
			t.Fatalf("case %d: expected ErrInvalidExtendedLimits, got %v", i, err)
		}
	}
}

func TestExtendedTracker_DefaultLimitsAreValid(t *testing.T) {
	if err := DefaultExtendedLimits().validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- ExpandResultFormats (Bind result-format expansion) ----------------

func TestExpandResultFormats_ZeroCodes_AllText(t *testing.T) {
	out, err := ExpandResultFormats(nil, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, v := range out {
		if v != 0 {
			t.Fatalf("field %d: expected text(0), got %d", i, v)
		}
	}
}

func TestExpandResultFormats_OneTextCode_AppliesToAll(t *testing.T) {
	out, err := ExpandResultFormats([]int16{0}, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, v := range out {
		if v != 0 {
			t.Fatalf("field %d: expected text(0), got %d", i, v)
		}
	}
}

func TestExpandResultFormats_OneBinaryCode_AppliesToAll(t *testing.T) {
	out, err := ExpandResultFormats([]int16{1}, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, v := range out {
		if v != 1 {
			t.Fatalf("field %d: expected binary(1), got %d", i, v)
		}
	}
}

func TestExpandResultFormats_NCodes_Positional(t *testing.T) {
	out, err := ExpandResultFormats([]int16{0, 1, 0}, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int16{0, 1, 0}
	for i, v := range out {
		if v != want[i] {
			t.Fatalf("field %d: expected %d, got %d", i, want[i], v)
		}
	}
}

func TestExpandResultFormats_InvalidCount_Rejected(t *testing.T) {
	if _, err := ExpandResultFormats([]int16{0, 1}, 3); !errors.Is(err, ErrExtendedInvalidResultFormat) {
		t.Fatalf("expected ErrExtendedInvalidResultFormat, got %v", err)
	}
}

func TestExpandResultFormats_InvalidCode_Rejected(t *testing.T) {
	if _, err := ExpandResultFormats([]int16{2}, 3); !errors.Is(err, ErrExtendedInvalidResultFormat) {
		t.Fatalf("expected ErrExtendedInvalidResultFormat, got %v", err)
	}
}

// --- Shape observation --------------------------------------------------

func TestExtendedTracker_StatementDescribe_RowDescription_CachesShape(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	gen := protocol.GenerationID(1)
	body := rowDescBody(idAndEmailFields(0))
	if err := tr.ObserveStatementDescribeRowDescription(gen, body); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !tr.HasStatementShape(gen) {
		t.Fatal("expected statement shape cached")
	}
}

func TestExtendedTracker_StatementDescribe_NoData_CachesKnownNoData(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	gen := protocol.GenerationID(1)
	if err := tr.ObserveStatementDescribeNoData(gen); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !tr.HasStatementShape(gen) {
		t.Fatal("expected known-NoData shape cached (distinct from unknown)")
	}
	plan, err := tr.ResolveExecutePlan(protocol.NoGeneration, gen, nil)
	if err != nil {
		t.Fatalf("expected known-NoData to allow Execute, got error: %v", err)
	}
	if len(plan.Targets) != 0 {
		t.Fatalf("expected an empty plan for known-NoData, got %+v", plan)
	}
}

func TestExtendedTracker_PortalDescribe_RowDescription_CachesActualFormats(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	gen := protocol.GenerationID(1)
	body := rowDescBody(idAndEmailFields(0))
	if err := tr.ObservePortalDescribeRowDescription(gen, body, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !tr.HasPortalShape(gen) {
		t.Fatal("expected portal shape cached")
	}
}

func TestExtendedTracker_PortalDescribe_NoData_CachesKnownNoData(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	gen := protocol.GenerationID(1)
	if err := tr.ObservePortalDescribeNoData(gen); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !tr.HasPortalShape(gen) {
		t.Fatal("expected known-NoData portal shape cached")
	}
}

func TestExtendedTracker_PortalDescribe_FormatMismatch_FailsClosed(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	gen := protocol.GenerationID(1)
	// RowDescription claims text(0) for the email column, but the Bind
	// requested binary(1) - an impossible mismatch.
	body := rowDescBody(idAndEmailFields(0))
	err := tr.ObservePortalDescribeRowDescription(gen, body, []int16{1})
	if !errors.Is(err, ErrExtendedInvalidResultFormat) {
		t.Fatalf("expected ErrExtendedInvalidResultFormat, got %v", err)
	}
	if tr.HasPortalShape(gen) {
		t.Fatal("expected no shape cached after a format mismatch")
	}
}

func TestExtendedTracker_StatementDescribeFormatZeros_NotTreatedAsActual(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	stmtGen := protocol.GenerationID(1)
	// Statement Describe reports format 0 (placeholder) for the target
	// column, but the actual Bind requests binary(1) for it.
	body := rowDescBody(idAndEmailFields(0))
	if err := tr.ObserveStatementDescribeRowDescription(stmtGen, body); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err := tr.ResolveExecutePlan(protocol.NoGeneration, stmtGen, []int16{0, 1})
	if !errors.Is(err, ErrExtendedBinaryTarget) {
		t.Fatalf("expected the actual Bind format (binary) to be honored and rejected, got %v", err)
	}
}

// --- Execute preflight (ResolveExecutePlan) -----------------------------

func TestExtendedTracker_ResolveExecutePlan_StatementShapeTextFormats_Allowed(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	stmtGen := protocol.GenerationID(1)
	tr.ObserveStatementDescribeRowDescription(stmtGen, rowDescBody(idAndEmailFields(0)))

	plan, err := tr.ResolveExecutePlan(protocol.NoGeneration, stmtGen, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Targets) != 1 || plan.Targets[0].ColumnName != "email" {
		t.Fatalf("expected one target 'email', got %+v", plan.Targets)
	}
}

func TestExtendedTracker_ResolveExecutePlan_PortalShapeTakesPrecedence(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	stmtGen := protocol.GenerationID(1)
	portalGen := protocol.GenerationID(2)
	// Statement shape has no email column at all.
	tr.ObserveStatementDescribeRowDescription(stmtGen, rowDescBody([]protocol.RowField{{Name: "note"}}))
	// Portal shape (from a portal-Describe) DOES have email - must win.
	tr.ObservePortalDescribeRowDescription(portalGen, rowDescBody(idAndEmailFields(0)), nil)

	plan, err := tr.ResolveExecutePlan(portalGen, stmtGen, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Targets) != 1 || plan.Targets[0].ColumnName != "email" {
		t.Fatalf("expected portal shape to take precedence, got %+v", plan.Targets)
	}
}

func TestExtendedTracker_ResolveExecutePlan_UnknownShape_MaskingEnabled_Rejected(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	_, err := tr.ResolveExecutePlan(protocol.GenerationID(99), protocol.GenerationID(98), nil)
	if !errors.Is(err, ErrExtendedShapeUnknown) {
		t.Fatalf("expected ErrExtendedShapeUnknown, got %v", err)
	}
}

func TestExtendedTracker_ResolveExecutePlan_UnknownShape_MaskingDisabled_Allowed(t *testing.T) {
	tr := newTracker(t, false, []string{"email"})
	plan, err := tr.ResolveExecutePlan(protocol.GenerationID(99), protocol.GenerationID(98), nil)
	if err != nil {
		t.Fatalf("expected masking-disabled Execute to be allowed regardless of shape, got %v", err)
	}
	if len(plan.Targets) != 0 {
		t.Fatalf("expected an empty plan when masking is disabled, got %+v", plan)
	}
}

func TestExtendedTracker_ResolveExecutePlan_BinaryTarget_Rejected(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	stmtGen := protocol.GenerationID(1)
	tr.ObserveStatementDescribeRowDescription(stmtGen, rowDescBody(idAndEmailFields(0)))

	_, err := tr.ResolveExecutePlan(protocol.NoGeneration, stmtGen, []int16{0, 1})
	if !errors.Is(err, ErrExtendedBinaryTarget) {
		t.Fatalf("expected ErrExtendedBinaryTarget, got %v", err)
	}
}

func TestExtendedTracker_ResolveExecutePlan_BinaryNonTarget_Allowed(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	stmtGen := protocol.GenerationID(1)
	tr.ObserveStatementDescribeRowDescription(stmtGen, rowDescBody(idAndEmailFields(0)))

	// id (non-target) is binary(1), email (target) stays text(0).
	plan, err := tr.ResolveExecutePlan(protocol.NoGeneration, stmtGen, []int16{1, 0})
	if err != nil {
		t.Fatalf("expected a binary non-target column to be allowed, got %v", err)
	}
	if len(plan.Targets) != 1 || plan.Targets[0].Index != 1 {
		t.Fatalf("expected exactly one target at index 1, got %+v", plan.Targets)
	}
}

func TestExtendedTracker_ResolveExecutePlan_InvalidFormatCount_Rejected(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	stmtGen := protocol.GenerationID(1)
	tr.ObserveStatementDescribeRowDescription(stmtGen, rowDescBody(idAndEmailFields(0)))

	_, err := tr.ResolveExecutePlan(protocol.NoGeneration, stmtGen, []int16{0, 0, 0})
	if !errors.Is(err, ErrExtendedInvalidResultFormat) {
		t.Fatalf("expected ErrExtendedInvalidResultFormat, got %v", err)
	}
}

func TestExtendedTracker_ResolveExecutePlan_NoTargetColumns_EmptyPlan(t *testing.T) {
	tr := newTracker(t, true, []string{"nonexistent_column"})
	stmtGen := protocol.GenerationID(1)
	tr.ObserveStatementDescribeRowDescription(stmtGen, rowDescBody(idAndEmailFields(0)))

	plan, err := tr.ResolveExecutePlan(protocol.NoGeneration, stmtGen, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Targets) != 0 {
		t.Fatalf("expected no targets, got %+v", plan.Targets)
	}
}

// --- Plan commit/lookup --------------------------------------------------

func TestExtendedTracker_CommitAndLookupPlan(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	portalGen := protocol.GenerationID(1)
	plan := RowMaskPlan{ColumnCount: 2, Targets: []MaskTarget{{Index: 1, ColumnName: "email"}}}

	if err := tr.CommitExecutePlan(portalGen, plan); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, ok := tr.LookupExecutePlan(portalGen)
	if !ok {
		t.Fatal("expected the plan to be found")
	}
	if len(got.Targets) != 1 || got.Targets[0].ColumnName != "email" {
		t.Fatalf("expected the committed plan to be returned unchanged, got %+v", got)
	}
}

func TestExtendedTracker_LookupMissingPlan_NotFound(t *testing.T) {
	tr := newTracker(t, true, nil)
	if _, ok := tr.LookupExecutePlan(protocol.GenerationID(42)); ok {
		t.Fatal("expected no plan to be found")
	}
}

func TestExtendedTracker_PortalSuspended_PlanPreservedAcrossResume(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	portalGen := protocol.GenerationID(1)
	plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email"}}}
	tr.CommitExecutePlan(portalGen, plan)

	// PortalSuspended does not retire anything - the plan must still be
	// present for a subsequent resumed Execute of the same portal.
	got, ok := tr.LookupExecutePlan(portalGen)
	if !ok || len(got.Targets) != 1 {
		t.Fatalf("expected the plan to survive (PortalSuspended never retires it), got ok=%v plan=%+v", ok, got)
	}
}

// --- Lifecycle / cleanup --------------------------------------------------

func TestExtendedTracker_RetireStatement_RemovesShape(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	gen := protocol.GenerationID(1)
	tr.ObserveStatementDescribeRowDescription(gen, rowDescBody(idAndEmailFields(0)))
	if !tr.HasStatementShape(gen) {
		t.Fatal("expected shape present before retirement")
	}
	tr.RetireStatement(gen)
	if tr.HasStatementShape(gen) {
		t.Fatal("expected shape removed after retirement")
	}
	if tr.TotalFieldCount() != 0 {
		t.Fatalf("expected total field count reclaimed, got %d", tr.TotalFieldCount())
	}
}

func TestExtendedTracker_RetirePortal_RemovesShapeAndPlan(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	gen := protocol.GenerationID(1)
	tr.ObservePortalDescribeRowDescription(gen, rowDescBody(idAndEmailFields(0)), nil)
	tr.CommitExecutePlan(gen, RowMaskPlan{ColumnCount: 2, Targets: []MaskTarget{{Index: 1, ColumnName: "email"}}})

	tr.RetirePortal(gen)
	if tr.HasPortalShape(gen) {
		t.Fatal("expected portal shape removed")
	}
	if tr.HasPortalPlan(gen) {
		t.Fatal("expected portal plan removed")
	}
}

func TestExtendedTracker_NewGenerationSameKeyDoesNotInheritOldShape(t *testing.T) {
	tr := newTracker(t, true, []string{"email"})
	oldGen := protocol.GenerationID(1)
	newGen := protocol.GenerationID(2)

	tr.ObserveStatementDescribeRowDescription(oldGen, rowDescBody(idAndEmailFields(0)))
	tr.RetireStatement(oldGen)

	// A later, distinct generation (simulating a replacement unnamed
	// Parse reusing the same client-supplied name) must start unknown,
	// never silently inheriting the retired generation's shape.
	if tr.HasStatementShape(newGen) {
		t.Fatal("expected the new generation to have no inherited shape")
	}
	_, err := tr.ResolveExecutePlan(protocol.NoGeneration, newGen, nil)
	if !errors.Is(err, ErrExtendedShapeUnknown) {
		t.Fatalf("expected ErrExtendedShapeUnknown for the new generation, got %v", err)
	}
}

func TestExtendedTracker_ReplacingShapeForSameGeneration_AccountedCorrectly(t *testing.T) {
	tr := newTracker(t, true, []string{"a", "b", "c"})
	gen := protocol.GenerationID(1)
	// First Describe: 1 target.
	tr.ObserveStatementDescribeRowDescription(gen, rowDescBody([]protocol.RowField{{Name: "a"}}))
	if tr.TotalFieldCount() != 1 {
		t.Fatalf("expected 1 total field, got %d", tr.TotalFieldCount())
	}
	// Re-Describe of the SAME generation with more targets - must replace,
	// not accumulate.
	tr.ObserveStatementDescribeRowDescription(gen, rowDescBody([]protocol.RowField{{Name: "a"}, {Name: "b"}, {Name: "c"}}))
	if tr.TotalFieldCount() != 3 {
		t.Fatalf("expected 3 total fields after replacement, got %d", tr.TotalFieldCount())
	}
	if tr.StatementShapeCount() != 1 {
		t.Fatalf("expected exactly 1 statement shape entry, got %d", tr.StatementShapeCount())
	}
}

// --- Resource limits ------------------------------------------------------

func TestExtendedTracker_MaxStatementShapes_Enforced(t *testing.T) {
	tr, err := NewExtendedTracker(NewConfig(true, nil), ExtendedLimits{MaxStatementShapes: 1, MaxPortalShapes: 10, MaxFieldsPerShape: 10, MaxTotalShapeFields: 100})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := tr.ObserveStatementDescribeNoData(protocol.GenerationID(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err = tr.ObserveStatementDescribeNoData(protocol.GenerationID(2))
	if !errors.Is(err, ErrExtendedCapacityExceeded) {
		t.Fatalf("expected ErrExtendedCapacityExceeded, got %v", err)
	}
}

func TestExtendedTracker_MaxFieldsPerShape_Enforced(t *testing.T) {
	tr, err := NewExtendedTracker(NewConfig(true, nil), ExtendedLimits{MaxStatementShapes: 10, MaxPortalShapes: 10, MaxFieldsPerShape: 1, MaxTotalShapeFields: 100})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err = tr.ObserveStatementDescribeRowDescription(protocol.GenerationID(1), rowDescBody(idAndEmailFields(0)))
	if !errors.Is(err, ErrExtendedCapacityExceeded) {
		t.Fatalf("expected ErrExtendedCapacityExceeded, got %v", err)
	}
}

func TestExtendedTracker_MaxTotalShapeFields_Enforced(t *testing.T) {
	tr, err := NewExtendedTracker(NewConfig(true, []string{"email"}), ExtendedLimits{MaxStatementShapes: 10, MaxPortalShapes: 10, MaxFieldsPerShape: 10, MaxTotalShapeFields: 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := tr.ObserveStatementDescribeRowDescription(protocol.GenerationID(1), rowDescBody(idAndEmailFields(0))); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err = tr.ObserveStatementDescribeRowDescription(protocol.GenerationID(2), rowDescBody(idAndEmailFields(0)))
	if !errors.Is(err, ErrExtendedCapacityExceeded) {
		t.Fatalf("expected ErrExtendedCapacityExceeded, got %v", err)
	}
}

func TestExtendedTracker_MaxPortalShapes_ReclaimedAfterCleanup(t *testing.T) {
	tr, err := NewExtendedTracker(NewConfig(true, nil), ExtendedLimits{MaxStatementShapes: 10, MaxPortalShapes: 1, MaxFieldsPerShape: 10, MaxTotalShapeFields: 100})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := tr.ObservePortalDescribeNoData(protocol.GenerationID(1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := tr.ObservePortalDescribeNoData(protocol.GenerationID(2)); !errors.Is(err, ErrExtendedCapacityExceeded) {
		t.Fatalf("expected capacity exceeded before cleanup, got %v", err)
	}
	tr.RetirePortal(protocol.GenerationID(1))
	if err := tr.ObservePortalDescribeNoData(protocol.GenerationID(2)); err != nil {
		t.Fatalf("expected capacity reclaimed after RetirePortal, got %v", err)
	}
}

// FuzzExtendedTracker drives a bounded sequence of Describe observations,
// Bind-format expansions and Execute preflight resolutions against a
// SINGLE ExtendedTracker with SMALL capacity limits (to make capacity
// boundaries reachable quickly), using arbitrary bytes for the
// RowDescription bodies and arbitrary generation IDs/format arrays.
// Invariants: no panic, no out-of-bounds access, retained metadata never
// exceeds the configured limits, and errors/plans never carry more targets
// than the (validated) shape allows.
func FuzzExtendedTracker(f *testing.F) {
	f.Add([]byte{0, 2, 'i', 'd', 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0}, uint64(1), uint64(2), []byte{0})
	f.Add([]byte{0, 0}, uint64(1), uint64(1), []byte{})
	f.Add([]byte{}, uint64(3), uint64(4), []byte{1})

	f.Fuzz(func(t *testing.T, rowDescBody []byte, stmtGenRaw, portalGenRaw uint64, formatBytes []byte) {
		limits := ExtendedLimits{MaxStatementShapes: 4, MaxPortalShapes: 4, MaxFieldsPerShape: 8, MaxTotalShapeFields: 16}
		tr, err := NewExtendedTracker(NewConfig(true, []string{"id", "email", "a", "b"}), limits)
		if err != nil {
			t.Fatalf("unexpected error constructing tracker: %v", err)
		}

		stmtGen := protocol.GenerationID(stmtGenRaw%8 + 1) // bounded, nonzero domain to make repeats likely
		portalGen := protocol.GenerationID(portalGenRaw%8 + 1)

		formats := make([]int16, 0, len(formatBytes))
		for _, b := range formatBytes {
			formats = append(formats, int16(b&1))
		}

		// Statement Describe observation - must never panic regardless of
		// body content.
		_ = tr.ObserveStatementDescribeRowDescription(stmtGen, rowDescBody)

		// Portal Describe observation with the SAME arbitrary body,
		// validated against the arbitrary formats.
		_ = tr.ObservePortalDescribeRowDescription(portalGen, rowDescBody, formats)

		// Execute preflight resolution must never panic and must never
		// return a plan with more targets than the shape's own column
		// count, nor a target index out of range.
		plan, planErr := tr.ResolveExecutePlan(portalGen, stmtGen, formats)
		if planErr == nil {
			for _, tgt := range plan.Targets {
				if tgt.Index < 0 || tgt.Index >= plan.ColumnCount {
					t.Fatalf("plan target index out of range: %+v (columnCount=%d)", tgt, plan.ColumnCount)
				}
				if tgt.FormatCode != 0 {
					t.Fatalf("plan contains a binary-format target (should have been rejected): %+v", tgt)
				}
			}
			if err := tr.CommitExecutePlan(portalGen, plan); err != nil {
				// Capacity exhaustion is an expected, safe outcome - not a
				// panic/invariant violation.
				_ = err
			}
		}

		// Retained metadata must never exceed configured limits.
		if tr.StatementShapeCount() > limits.MaxStatementShapes {
			t.Fatalf("statement shape count %d exceeds limit %d", tr.StatementShapeCount(), limits.MaxStatementShapes)
		}
		if tr.PortalShapeCount() > limits.MaxPortalShapes {
			t.Fatalf("portal shape count %d exceeds limit %d", tr.PortalShapeCount(), limits.MaxPortalShapes)
		}
		if tr.PortalPlanCount() > limits.MaxPortalShapes {
			t.Fatalf("portal plan count %d exceeds limit %d", tr.PortalPlanCount(), limits.MaxPortalShapes)
		}
		if tr.TotalFieldCount() > limits.MaxTotalShapeFields {
			t.Fatalf("total field count %d exceeds limit %d", tr.TotalFieldCount(), limits.MaxTotalShapeFields)
		}
		if tr.TotalFieldCount() < 0 {
			t.Fatalf("total field count went negative: %d", tr.TotalFieldCount())
		}

		// Lifecycle cleanup must never panic and must actually reclaim
		// capacity.
		tr.RetireStatement(stmtGen)
		tr.RetirePortal(portalGen)
		if tr.HasStatementShape(stmtGen) {
			t.Fatal("expected statement shape retired")
		}
		if tr.HasPortalShape(portalGen) || tr.HasPortalPlan(portalGen) {
			t.Fatal("expected portal shape/plan retired")
		}
	})
}

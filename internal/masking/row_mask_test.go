package masking

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

func TestMaskDataRow_NoTargets_ValidFrame_ReturnsIndependentCopy(t *testing.T) {
	// No targets means no masking OBLIGATION, but the frame is still a
	// well-formed DataRow (encodeDataRow always produces valid framing) -
	// it is structurally validated like any other frame before the
	// no-target fast path returns it unchanged.
	frame := encodeDataRow([]protocol.DataCell{{Value: []byte("anything, the VALUE content is irrelevant here")}})
	masker := emailLikeMasker()

	out, changed, err := MaskDataRow(context.Background(), masker, RowMaskPlan{}, frame, Hooks{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Fatal("expected changed=false when there are no targets")
	}
	if !bytes.Equal(out, frame) {
		t.Fatalf("expected byte-identical output, got %x want %x", out, frame)
	}
	// Independent ownership: mutating out must not mutate frame.
	out[0] = 'X'
	if frame[0] == 'X' {
		t.Fatal("expected output bytes to be independently owned, not aliased to input")
	}
	if len(masker.calls) != 0 {
		t.Fatalf("expected no Mask calls, got %+v", masker.calls)
	}
}

func TestMaskDataRow_NoTargets_MalformedFrame_Rejected(t *testing.T) {
	// The no-target fast path must NOT bypass structural validation - a
	// malformed frame is rejected even when plan.Targets is empty.
	malformed := []byte{'D', 0, 0, 0, 100} // claims length 100, body absent
	_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), RowMaskPlan{}, malformed, Hooks{})
	if !errors.Is(err, ErrInvalidDataRowFrame) {
		t.Fatalf("expected ErrInvalidDataRowFrame, got %v", err)
	}
}

func TestMaskDataRow_WrongMessageTag_Rejected(t *testing.T) {
	frame := encodeDataRow([]protocol.DataCell{{Value: []byte("x")}})
	frame[0] = 'T' // RowDescription tag, not DataRow
	_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), RowMaskPlan{}, frame, Hooks{})
	if !errors.Is(err, ErrInvalidDataRowFrame) {
		t.Fatalf("expected ErrInvalidDataRowFrame for a wrong tag, got %v", err)
	}
}

func TestMaskDataRow_MissingLength_Rejected(t *testing.T) {
	_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), RowMaskPlan{}, []byte{'D', 0, 0}, Hooks{})
	if !errors.Is(err, ErrInvalidDataRowFrame) {
		t.Fatalf("expected ErrInvalidDataRowFrame, got %v", err)
	}
}

func TestMaskDataRow_DeclaredLengthBelowFour_Rejected(t *testing.T) {
	frame := []byte{'D', 0, 0, 0, 3} // length field must be >= 4 (itself included)
	_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), RowMaskPlan{}, frame, Hooks{})
	if !errors.Is(err, ErrInvalidDataRowFrame) {
		t.Fatalf("expected ErrInvalidDataRowFrame, got %v", err)
	}
}

func TestMaskDataRow_ShorterBodyThanDeclared_Rejected(t *testing.T) {
	full := encodeDataRow([]protocol.DataCell{{Value: []byte("hello")}})
	truncated := full[:len(full)-3] // declared length still claims the full size
	_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), RowMaskPlan{}, truncated, Hooks{})
	if !errors.Is(err, ErrInvalidDataRowFrame) {
		t.Fatalf("expected ErrInvalidDataRowFrame for a truncated body, got %v", err)
	}
}

func TestMaskDataRow_TrailingBytes_Rejected(t *testing.T) {
	full := encodeDataRow([]protocol.DataCell{{Value: []byte("hello")}})
	withTrailer := append(append([]byte{}, full...), 0xAA, 0xBB, 0xCC)
	_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), RowMaskPlan{}, withTrailer, Hooks{})
	if !errors.Is(err, ErrInvalidDataRowFrame) {
		t.Fatalf("expected ErrInvalidDataRowFrame for trailing bytes, got %v", err)
	}
}

func TestMaskDataRow_ValidFramePlusSecondFrame_Rejected(t *testing.T) {
	one := encodeDataRow([]protocol.DataCell{{Value: []byte("a")}})
	two := encodeDataRow([]protocol.DataCell{{Value: []byte("b")}})
	both := append(append([]byte{}, one...), two...)
	// MaskDataRow accepts exactly ONE complete frame - a second frame
	// appended after a valid first one must be rejected, not silently
	// processed as if it were trailing garbage on the first frame's own
	// declared length (which it is NOT: the declared length only covers
	// the first frame).
	_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), RowMaskPlan{}, both, Hooks{})
	if !errors.Is(err, ErrInvalidDataRowFrame) {
		t.Fatalf("expected ErrInvalidDataRowFrame when a second frame follows, got %v", err)
	}
}

func TestMaskDataRow_TooShortFrame_Errors(t *testing.T) {
	_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), RowMaskPlan{}, []byte{'D', 0, 0}, Hooks{})
	if err == nil {
		t.Fatal("expected an error for a too-short frame")
	}
}

func TestMaskDataRow_MasksConfiguredTarget(t *testing.T) {
	frame := encodeDataRow([]protocol.DataCell{
		{Value: []byte("1")},
		{Value: []byte("john@example.com")},
	})
	masker := emailLikeMasker()
	plan := RowMaskPlan{ColumnCount: 2, Targets: []MaskTarget{{Index: 1, ColumnName: "email", FormatCode: 0}}}

	out, changed, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	row, err := protocol.ParseDataRow(out[5:])
	if err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}
	if string(row.Cells[1].Value) != "MASKED" {
		t.Fatalf("expected masked email, got %q", row.Cells[1].Value)
	}
	if string(row.Cells[0].Value) != "1" {
		t.Fatalf("expected non-target column unchanged, got %q", row.Cells[0].Value)
	}
	if len(masker.calls) != 1 || masker.calls[0].column != "email" {
		t.Fatalf("expected exactly one Mask call for 'email', got %+v", masker.calls)
	}
}

func TestMaskDataRow_MasksSeveralTargets(t *testing.T) {
	frame := encodeDataRow([]protocol.DataCell{
		{Value: []byte("a@example.com")},
		{Value: []byte("plain")},
		{Value: []byte("b@example.com")},
	})
	masker := emailLikeMasker()
	plan := RowMaskPlan{ColumnCount: 3, Targets: []MaskTarget{
		{Index: 0, ColumnName: "email1"},
		{Index: 2, ColumnName: "email2"},
	}}

	out, changed, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	row, err := protocol.ParseDataRow(out[5:])
	if err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}
	if string(row.Cells[0].Value) != "MASKED" || string(row.Cells[2].Value) != "MASKED" {
		t.Fatalf("expected both target cells masked, got %+v", row.Cells)
	}
	if string(row.Cells[1].Value) != "plain" {
		t.Fatalf("expected non-target column unchanged, got %q", row.Cells[1].Value)
	}
	if len(masker.calls) != 2 {
		t.Fatalf("expected 2 Mask calls, got %+v", masker.calls)
	}
}

func TestMaskDataRow_NullTargetSkipsMasker(t *testing.T) {
	frame := encodeDataRow([]protocol.DataCell{{Null: true}})
	masker := emailLikeMasker()
	plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email"}}}

	out, changed, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Fatal("expected changed=false for a NULL-only row")
	}
	if !bytes.Equal(out, frame) {
		t.Fatalf("expected byte-identical output for a NULL target, got %x want %x", out, frame)
	}
	if len(masker.calls) != 0 {
		t.Fatalf("expected no Mask calls for a NULL cell, got %+v", masker.calls)
	}
}

func TestMaskDataRow_UnchangedMaskerResultPreservesBytes(t *testing.T) {
	frame := encodeDataRow([]protocol.DataCell{{Value: []byte("not-an-email")}})
	masker := emailLikeMasker()
	plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email"}}}

	out, changed, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Fatal("expected changed=false when Masker reports no change")
	}
	if !bytes.Equal(out, frame) {
		t.Fatalf("expected byte-identical output, got %x want %x", out, frame)
	}
}

func TestMaskDataRow_BinaryTargetRejectedFailClosed(t *testing.T) {
	frame := encodeDataRow([]protocol.DataCell{{Value: []byte("john@example.com")}})
	masker := emailLikeMasker()
	plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email", FormatCode: 1}}}

	_, _, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
	if err == nil {
		t.Fatal("expected an error for a binary-format target column")
	}
	if len(masker.calls) != 0 {
		t.Fatal("expected the masker never to be called for a binary-format column")
	}
}

func TestMaskDataRow_BinaryTargetWithNullValueNotRejected(t *testing.T) {
	// Format-code rejection is a per-cell check downstream of the NULL
	// skip (matches the original Simple Query Transformer's exact
	// behavior, preserved here for byte-for-byte compatibility) - a
	// binary-format target whose value happens to be NULL in THIS row is
	// not rejected by the row core itself (the Extended preflight layer
	// is the primary, unconditional defense; see extended.go).
	frame := encodeDataRow([]protocol.DataCell{{Null: true}})
	masker := emailLikeMasker()
	plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email", FormatCode: 1}}}

	_, changed, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Fatal("expected changed=false")
	}
}

func TestMaskDataRow_FieldCountMismatchErrors(t *testing.T) {
	frame := encodeDataRow([]protocol.DataCell{{Value: []byte("1")}, {Value: []byte("2")}, {Value: []byte("3")}})
	masker := emailLikeMasker()
	plan := RowMaskPlan{ColumnCount: 2, Targets: []MaskTarget{{Index: 1, ColumnName: "email"}}}

	_, _, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
	if err == nil {
		t.Fatal("expected a field-count mismatch error")
	}
	if len(masker.calls) != 0 {
		t.Fatal("expected the masker never reached on a field-count mismatch")
	}
}

func TestMaskDataRow_MalformedFrameErrors(t *testing.T) {
	masker := emailLikeMasker()
	plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email"}}}

	malformed := []byte{'D', 0, 0, 0, 100} // claims length 100 but body is empty
	_, _, err := MaskDataRow(context.Background(), masker, plan, malformed, Hooks{})
	if err == nil {
		t.Fatal("expected an error for a malformed DataRow body")
	}
}

func TestMaskDataRow_InvalidTargetIndexErrors(t *testing.T) {
	frame := encodeDataRow([]protocol.DataCell{{Value: []byte("1")}})
	masker := emailLikeMasker()
	plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 5, ColumnName: "email"}}}

	_, _, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
	if err == nil {
		t.Fatal("expected an error for an out-of-range target index")
	}
}

func TestMaskDataRow_MaskerErrorPropagates(t *testing.T) {
	frame := encodeDataRow([]protocol.DataCell{{Value: []byte("john@example.com")}})
	masker := &fakeMasker{maskFunc: func(column, value string) (string, bool, error) {
		return "", false, errors.New("plugin crashed")
	}}
	plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email"}}}

	_, _, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
	if err == nil {
		t.Fatal("expected the masker error to propagate")
	}
}

func TestMaskDataRow_ContextPassedDirectlyToMasker(t *testing.T) {
	frame := encodeDataRow([]protocol.DataCell{{Value: []byte("john@example.com")}})
	masker := emailLikeMasker()
	plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email"}}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, _, err := MaskDataRow(ctx, masker, plan, frame, Hooks{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if masker.lastCtx != ctx {
		t.Fatal("expected the exact same context to be passed to Masker")
	}
}

func TestMaskDataRow_ErrorsNeverContainCellValues(t *testing.T) {
	const secretValue = "SECRET_ROWMASK_VALUE_MARKER"
	frame := encodeDataRow([]protocol.DataCell{{Value: []byte(secretValue)}})
	masker := &fakeMasker{maskFunc: func(column, value string) (string, bool, error) {
		return "", false, errors.New("boom")
	}}
	plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email"}}}

	_, _, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Fatalf("expected the error not to contain the cell value, got: %v", err)
	}

	// Field-count mismatch path.
	mismatchFrame := encodeDataRow([]protocol.DataCell{{Value: []byte(secretValue)}, {Value: []byte("extra")}})
	_, _, err = MaskDataRow(context.Background(), masker, plan, mismatchFrame, Hooks{})
	if err == nil {
		t.Fatal("expected a field-count mismatch error")
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Fatalf("expected the mismatch error not to contain any cell value, got: %v", err)
	}
}

// TestMaskDataRow_MaliciousMaskerError_NeverDisclosed proves that an
// adversarial or careless Masker whose returned error embeds the complete
// input cell value and other sensitive markers can NEVER leak them through
// MaskDataRow's returned error - only the fixed ErrMaskerInvocationFailed
// category crosses that boundary. The hook is still permitted to observe
// the original error by design (existing contract), so it is checked
// separately and MUST still receive the marker-bearing error unchanged.
func TestMaskDataRow_MaliciousMaskerError_NeverDisclosed(t *testing.T) {
	const cellValue = "SECRET_CELL_VALUE_MARKER"
	const sqlMarker = "SECRET_SQL_MARKER SELECT * FROM users"
	const nameMarker = "SECRET_COLUMN_NAME_MARKER"

	frame := encodeDataRow([]protocol.DataCell{{Value: []byte(cellValue)}})
	malicious := &fakeMasker{maskFunc: func(column, value string) (string, bool, error) {
		return "", false, fmt.Errorf("plugin failed on value %q, sql=%q, name=%q", value, sqlMarker, nameMarker)
	}}
	plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email"}}}

	var hookErr error
	_, _, err := MaskDataRow(context.Background(), malicious, plan, frame, Hooks{
		OnMaskAttempt: func(column string, changed bool, err error, d time.Duration) { hookErr = err },
	})

	if !errors.Is(err, ErrMaskerInvocationFailed) {
		t.Fatalf("expected ErrMaskerInvocationFailed, got %v", err)
	}
	for _, marker := range []string{cellValue, sqlMarker, nameMarker} {
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("expected the returned error not to contain marker %q, got: %v", marker, err)
		}
		if strings.Contains(fmt.Sprintf("%v", err), marker) || strings.Contains(fmt.Sprintf("%+v", err), marker) || strings.Contains(fmt.Sprintf("%#v", err), marker) {
			t.Fatalf("expected no %%v/%%+v/%%#v formatting of the returned error to contain marker %q", marker)
		}
	}

	// The hook, by existing design, MAY still observe the original error.
	if hookErr == nil {
		t.Fatal("expected the hook to receive the original Masker error")
	}
	if !strings.Contains(hookErr.Error(), cellValue) {
		t.Fatal("expected the hook's error to be the ORIGINAL, unredacted Masker error (existing contract)")
	}
}

func TestMaskDataRow_ErrorCategories_SupportErrorsIs(t *testing.T) {
	cases := []struct {
		name string
		run  func() error
	}{
		{"malformed frame", func() error {
			_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), RowMaskPlan{}, []byte{'D', 0, 0}, Hooks{})
			return err
		}},
		{"shape mismatch", func() error {
			frame := encodeDataRow([]protocol.DataCell{{Value: []byte("a")}, {Value: []byte("b")}})
			plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email"}}}
			_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), plan, frame, Hooks{})
			return err
		}},
		{"binary target", func() error {
			frame := encodeDataRow([]protocol.DataCell{{Value: []byte("a@example.com")}})
			plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email", FormatCode: 1}}}
			_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), plan, frame, Hooks{})
			return err
		}},
		{"invalid plan (out-of-range index)", func() error {
			frame := encodeDataRow([]protocol.DataCell{{Value: []byte("a")}})
			plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 5, ColumnName: "email"}}}
			_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), plan, frame, Hooks{})
			return err
		}},
		{"masker invocation failed", func() error {
			frame := encodeDataRow([]protocol.DataCell{{Value: []byte("a@example.com")}})
			plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email"}}}
			masker := &fakeMasker{maskFunc: func(column, value string) (string, bool, error) { return "", false, errors.New("x") }}
			_, _, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
			return err
		}},
		{"unexpected DataRow for NoData", func() error {
			frame := encodeDataRow([]protocol.DataCell{{Value: []byte("a")}})
			plan := RowMaskPlan{KnownNoData: true}
			_, _, err := MaskDataRow(context.Background(), emailLikeMasker(), plan, frame, Hooks{})
			return err
		}},
	}
	wantErrs := []error{
		ErrInvalidDataRowFrame, ErrDataRowShapeMismatch, ErrRowMaskBinaryTarget,
		ErrInvalidRowMaskPlan, ErrMaskerInvocationFailed, ErrUnexpectedDataRowForNoData,
	}
	for i, c := range cases {
		err := c.run()
		if !errors.Is(err, wantErrs[i]) {
			t.Fatalf("%s: expected errors.Is match for %v, got %v", c.name, wantErrs[i], err)
		}
	}
}

func TestMaskDataRow_KnownNoData_RejectsAnyDataRow(t *testing.T) {
	frame := encodeDataRow([]protocol.DataCell{{Value: []byte("unexpected")}})
	plan := RowMaskPlan{KnownNoData: true}
	masker := emailLikeMasker()

	_, _, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
	if !errors.Is(err, ErrUnexpectedDataRowForNoData) {
		t.Fatalf("expected ErrUnexpectedDataRowForNoData, got %v", err)
	}
	if len(masker.calls) != 0 {
		t.Fatal("expected the masker never called for a KnownNoData plan")
	}
}

func TestMaskDataRow_HookReceivesColumnNameButNoValue(t *testing.T) {
	const secretValue = "SECRET_ROWMASK_HOOK_MARKER"
	frame := encodeDataRow([]protocol.DataCell{{Value: []byte(secretValue)}})
	masker := emailLikeMasker()
	plan := RowMaskPlan{ColumnCount: 1, Targets: []MaskTarget{{Index: 0, ColumnName: "email"}}}

	var sawColumn string
	var attempts int
	_, _, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{
		OnMaskAttempt: func(column string, changed bool, err error, d time.Duration) {
			attempts++
			sawColumn = column
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected exactly 1 mask attempt, got %d", attempts)
	}
	if sawColumn != "email" {
		t.Fatalf("expected the hook to receive only the column name, got %q", sawColumn)
	}
}

// FuzzMaskDataRow proves MaskDataRow never panics and never emits an
// out-of-bounds/impossible frame, regardless of malformed DataRow bodies,
// arbitrary plans (including out-of-range indexes and binary format
// codes), or NULL/non-NULL cell mixes.
// FuzzMaskDataRow drives both DEEP masking-logic coverage (a well-formed
// frame with a fuzzed body, per corruptionMode 0) and COMPLETE-FRAME
// corruption (wrong tag, corrupted length field, trailing bytes/a second
// frame, truncation, and fully arbitrary raw bytes) - proving
// validateCompleteDataRowFrame's checks, not merely protocol.ParseDataRow's
// own body parsing, are exercised.
func FuzzMaskDataRow(f *testing.F) {
	f.Add([]byte{0, 2, 0, 0, 0, 1, 'a', 0xFF, 0xFF, 0xFF, 0xFF}, 2, 0, "email", int16(0), byte(0), []byte{})
	f.Add([]byte{0, 0}, 0, 0, "", int16(0), byte(1), []byte{'D', 0, 0, 0, 4})
	f.Add([]byte{}, 1, 5, "x", int16(1), byte(2), []byte{})
	f.Add([]byte{0, 1, 0, 0, 0, 1, 'a'}, 1, 0, "email", int16(0), byte(3), []byte{})
	f.Add([]byte{0, 1, 0, 0, 0, 1, 'a'}, 1, 0, "email", int16(0), byte(4), []byte{1, 2, 3})
	f.Add([]byte{0, 1, 0, 0, 0, 1, 'a'}, 1, 0, "email", int16(0), byte(5), []byte{})

	f.Fuzz(func(t *testing.T, body []byte, columnCount int, targetIndex int, columnName string, formatCode int16, corruptionMode byte, rawFrame []byte) {
		if columnCount < -8 || columnCount > 64 {
			return
		}
		if len(rawFrame) > 4096 || len(body) > 4096 {
			return
		}

		wellFormed := make([]byte, 0, len(body)+5)
		wellFormed = append(wellFormed, 'D')
		lenBuf := make([]byte, 4)
		total := uint32(len(body) + 4)
		lenBuf[0] = byte(total >> 24)
		lenBuf[1] = byte(total >> 16)
		lenBuf[2] = byte(total >> 8)
		lenBuf[3] = byte(total)
		wellFormed = append(wellFormed, lenBuf...)
		wellFormed = append(wellFormed, body...)

		var frame []byte
		switch corruptionMode % 6 {
		case 0: // well-formed frame, arbitrary body content - deep coverage
			frame = wellFormed
		case 1: // completely arbitrary bytes
			frame = rawFrame
		case 2: // wrong message tag
			frame = append([]byte{}, wellFormed...)
			if len(frame) > 0 {
				frame[0] = 'T'
			}
		case 3: // corrupted length field
			frame = append([]byte{}, wellFormed...)
			if len(frame) >= 5 {
				frame[4] ^= 0xFF
			}
		case 4: // trailing bytes / a second frame appended
			frame = append(append([]byte{}, wellFormed...), rawFrame...)
		case 5: // truncated body
			frame = append([]byte{}, wellFormed...)
			if n := len(frame); n > 0 {
				cut := int(formatCode) % (n + 1)
				if cut < 0 {
					cut = -cut
				}
				if cut > n {
					cut = n
				}
				frame = frame[:n-cut]
			}
		}

		plan := RowMaskPlan{ColumnCount: columnCount, Targets: []MaskTarget{{Index: targetIndex, ColumnName: columnName, FormatCode: formatCode}}}
		masker := emailLikeMasker()

		out, _, err := MaskDataRow(context.Background(), masker, plan, frame, Hooks{})
		if err != nil {
			return
		}
		if len(out) < 5 {
			t.Fatalf("output frame shorter than a valid header: %x", out)
		}
		if out[0] != 'D' {
			t.Fatalf("output frame has wrong tag: %x", out)
		}
		declared := uint32(out[1])<<24 | uint32(out[2])<<16 | uint32(out[3])<<8 | uint32(out[4])
		if int(declared)+1 != len(out) {
			t.Fatalf("output frame length field inconsistent with actual length: declared=%d actual=%d", declared, len(out))
		}
		// A successful output must itself pass the same complete-frame
		// validation MaskDataRow applies to its input (self-consistency).
		if _, verr := validateCompleteDataRowFrame(out); verr != nil {
			t.Fatalf("MaskDataRow produced an output that fails its own frame validation: %v", verr)
		}
	})
}

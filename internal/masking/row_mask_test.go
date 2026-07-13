package masking

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

func TestMaskDataRow_NoTargets_ReturnsIndependentCopyUnparsed(t *testing.T) {
	frame := encodeDataRow([]protocol.DataCell{{Value: []byte("anything, not even valid framing matters here")}})
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
func FuzzMaskDataRow(f *testing.F) {
	f.Add([]byte{0, 2, 0, 0, 0, 1, 'a', 0xFF, 0xFF, 0xFF, 0xFF}, 2, 0, "email", int16(0))
	f.Add([]byte{0, 0}, 0, 0, "", int16(0))
	f.Add([]byte{}, 1, 5, "x", int16(1))

	f.Fuzz(func(t *testing.T, body []byte, columnCount int, targetIndex int, columnName string, formatCode int16) {
		if columnCount < -8 || columnCount > 64 {
			return
		}
		frame := make([]byte, 0, len(body)+5)
		frame = append(frame, 'D')
		lenBuf := make([]byte, 4)
		total := uint32(len(body) + 4)
		lenBuf[0] = byte(total >> 24)
		lenBuf[1] = byte(total >> 16)
		lenBuf[2] = byte(total >> 8)
		lenBuf[3] = byte(total)
		frame = append(frame, lenBuf...)
		frame = append(frame, body...)

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
	})
}

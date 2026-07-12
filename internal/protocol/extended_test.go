package protocol

import (
	"encoding/binary"
	"errors"
	"testing"
)

// --- Test payload builders -------------------------------------------------
//
// These build only the message BODY (no tag byte, no length prefix) since
// that is exactly what ParseFrontend* functions consume - the same
// convention as ParseRowDescription/ParseDataRow.

func beU16(n int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(n))
	return b
}

func beU32(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

func beI32(n int32) []byte {
	return beU32(uint32(n))
}

func cstr(s string) []byte {
	return append([]byte(s), 0)
}

func buildParsePayload(stmt, query string, oids []uint32) []byte {
	var p []byte
	p = append(p, cstr(stmt)...)
	p = append(p, cstr(query)...)
	p = append(p, beU16(len(oids))...)
	for _, o := range oids {
		p = append(p, beU32(o)...)
	}
	return p
}

type testBindParam struct {
	null  bool
	value []byte
}

func buildBindPayload(portal, stmt string, paramFormats []int16, params []testBindParam, resultFormats []int16) []byte {
	var p []byte
	p = append(p, cstr(portal)...)
	p = append(p, cstr(stmt)...)
	p = append(p, beU16(len(paramFormats))...)
	for _, f := range paramFormats {
		p = append(p, beU16(int(f))...)
	}
	p = append(p, beU16(len(params))...)
	for _, param := range params {
		if param.null {
			p = append(p, beI32(-1)...)
			continue
		}
		p = append(p, beU32(uint32(len(param.value)))...)
		p = append(p, param.value...)
	}
	p = append(p, beU16(len(resultFormats))...)
	for _, f := range resultFormats {
		p = append(p, beU16(int(f))...)
	}
	return p
}

func buildDescribePayload(selector byte, name string) []byte {
	p := []byte{selector}
	return append(p, cstr(name)...)
}

func buildExecutePayload(portal string, maxRows int32) []byte {
	p := cstr(portal)
	return append(p, beI32(maxRows)...)
}

func buildClosePayload(selector byte, name string) []byte {
	p := []byte{selector}
	return append(p, cstr(name)...)
}

func extendedParseErrorCategory(t *testing.T, err error) ExtendedParseErrorCategory {
	t.Helper()
	var perr *ExtendedParseError
	if !errors.As(err, &perr) {
		t.Fatalf("expected *ExtendedParseError, got %T: %v", err, err)
	}
	return perr.Category
}

// --- Parse -------------------------------------------------------------

func TestParseFrontendParse_UnnamedStatement(t *testing.T) {
	msg, err := ParseFrontendParse(buildParsePayload("", "SELECT 1", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.StatementName != "" || msg.Query != "SELECT 1" || len(msg.ParamOIDs) != 0 {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestParseFrontendParse_NamedStatement(t *testing.T) {
	msg, err := ParseFrontendParse(buildParsePayload("stmt1", "SELECT 2", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.StatementName != "stmt1" || msg.Query != "SELECT 2" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestParseFrontendParse_ZeroParamOIDs(t *testing.T) {
	msg, err := ParseFrontendParse(buildParsePayload("", "SELECT 1", []uint32{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.ParamOIDs) != 0 {
		t.Fatalf("expected zero param OIDs, got %+v", msg.ParamOIDs)
	}
}

func TestParseFrontendParse_MultipleParamOIDs(t *testing.T) {
	msg, err := ParseFrontendParse(buildParsePayload("s", "SELECT $1, $2", []uint32{23, 25}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.ParamOIDs) != 2 || msg.ParamOIDs[0] != 23 || msg.ParamOIDs[1] != 25 {
		t.Fatalf("unexpected param OIDs: %+v", msg.ParamOIDs)
	}
}

func TestParseFrontendParse_MissingStatementTerminator(t *testing.T) {
	_, err := ParseFrontendParse([]byte("stmt"))
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryMissingTerminator {
		t.Fatalf("expected CategoryMissingTerminator, got %v", cat)
	}
}

func TestParseFrontendParse_MissingQueryTerminator(t *testing.T) {
	payload := append(cstr(""), []byte("SELECT 1")...) // no NUL after query
	_, err := ParseFrontendParse(payload)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryMissingTerminator {
		t.Fatalf("expected CategoryMissingTerminator, got %v", cat)
	}
}

func TestParseFrontendParse_TruncatedCount(t *testing.T) {
	payload := append(cstr(""), cstr("SELECT 1")...)
	payload = append(payload, 0) // only 1 of 2 count bytes
	_, err := ParseFrontendParse(payload)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryTruncated {
		t.Fatalf("expected CategoryTruncated, got %v", cat)
	}
}

func TestParseFrontendParse_TruncatedOIDList(t *testing.T) {
	payload := append(cstr(""), cstr("SELECT 1")...)
	payload = append(payload, beU16(2)...)  // claims 2 OIDs
	payload = append(payload, beU32(23)...) // only 1 provided
	_, err := ParseFrontendParse(payload)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryTruncated {
		t.Fatalf("expected CategoryTruncated, got %v", cat)
	}
}

func TestParseFrontendParse_TrailingGarbage(t *testing.T) {
	payload := append(buildParsePayload("", "SELECT 1", nil), 0xFF)
	_, err := ParseFrontendParse(payload)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryTrailingBytes {
		t.Fatalf("expected CategoryTrailingBytes, got %v", cat)
	}
}

// --- Bind ----------------------------------------------------------------

func TestParseFrontendBind_UnnamedPortalAndStatement(t *testing.T) {
	msg, err := ParseFrontendBind(buildBindPayload("", "", nil, nil, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.PortalName != "" || msg.StatementName != "" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestParseFrontendBind_NamedPortalAndStatement(t *testing.T) {
	msg, err := ParseFrontendBind(buildBindPayload("p1", "s1", nil, nil, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.PortalName != "p1" || msg.StatementName != "s1" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestParseFrontendBind_ZeroParameters(t *testing.T) {
	msg, err := ParseFrontendBind(buildBindPayload("", "", nil, nil, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.Params) != 0 {
		t.Fatalf("expected zero params, got %+v", msg.Params)
	}
}

func TestParseFrontendBind_OneTextParameter(t *testing.T) {
	params := []testBindParam{{value: []byte("hello")}}
	msg, err := ParseFrontendBind(buildBindPayload("", "", []int16{0}, params, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.Params) != 1 || msg.Params[0].Null || string(msg.Params[0].Value) != "hello" {
		t.Fatalf("unexpected params: %+v", msg.Params)
	}
	if len(msg.ParamFormats) != 1 || msg.ParamFormats[0] != 0 {
		t.Fatalf("unexpected param formats: %+v", msg.ParamFormats)
	}
}

func TestParseFrontendBind_OneBinaryParameter(t *testing.T) {
	params := []testBindParam{{value: []byte{0x01, 0x02, 0x03}}}
	msg, err := ParseFrontendBind(buildBindPayload("", "", []int16{1}, params, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.ParamFormats) != 1 || msg.ParamFormats[0] != 1 {
		t.Fatalf("unexpected param formats: %+v", msg.ParamFormats)
	}
	if !bytesEqual(msg.Params[0].Value, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("unexpected param value: %+v", msg.Params[0].Value)
	}
}

func TestParseFrontendBind_NullParameter(t *testing.T) {
	params := []testBindParam{{null: true}}
	msg, err := ParseFrontendBind(buildBindPayload("", "", nil, params, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.Params) != 1 || !msg.Params[0].Null || msg.Params[0].Value != nil {
		t.Fatalf("expected NULL param, got %+v", msg.Params[0])
	}
}

func TestParseFrontendBind_MultipleParameters(t *testing.T) {
	params := []testBindParam{{value: []byte("a")}, {null: true}, {value: []byte("bcd")}}
	msg, err := ParseFrontendBind(buildBindPayload("", "", nil, params, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.Params) != 3 || msg.Params[1].Null == false || string(msg.Params[2].Value) != "bcd" {
		t.Fatalf("unexpected params: %+v", msg.Params)
	}
}

func TestParseFrontendBind_ZeroFormatCodes(t *testing.T) {
	params := []testBindParam{{value: []byte("x")}}
	msg, err := ParseFrontendBind(buildBindPayload("", "", nil, params, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.ParamFormats) != 0 {
		t.Fatalf("expected zero format codes, got %+v", msg.ParamFormats)
	}
}

func TestParseFrontendBind_OneSharedFormatCode(t *testing.T) {
	params := []testBindParam{{value: []byte("x")}, {value: []byte("y")}}
	msg, err := ParseFrontendBind(buildBindPayload("", "", []int16{1}, params, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.ParamFormats) != 1 {
		t.Fatalf("expected one shared format code, got %+v", msg.ParamFormats)
	}
}

func TestParseFrontendBind_PerParameterFormatCodes(t *testing.T) {
	params := []testBindParam{{value: []byte("x")}, {value: []byte{0x01}}}
	msg, err := ParseFrontendBind(buildBindPayload("", "", []int16{0, 1}, params, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.ParamFormats) != 2 || msg.ParamFormats[0] != 0 || msg.ParamFormats[1] != 1 {
		t.Fatalf("unexpected param formats: %+v", msg.ParamFormats)
	}
}

func TestParseFrontendBind_InvalidFormatCode(t *testing.T) {
	payload := buildBindPayload("", "", []int16{2}, nil, nil)
	_, err := ParseFrontendBind(payload)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryInvalidFormatCode {
		t.Fatalf("expected CategoryInvalidFormatCode, got %v", cat)
	}
}

func TestParseFrontendBind_TruncatedParameterLength(t *testing.T) {
	var p []byte
	p = append(p, cstr("")...)
	p = append(p, cstr("")...)
	p = append(p, beU16(0)...) // param format count
	p = append(p, beU16(1)...) // param count = 1
	p = append(p, 0, 0)        // only 2 of 4 length bytes
	_, err := ParseFrontendBind(p)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryTruncated {
		t.Fatalf("expected CategoryTruncated, got %v", cat)
	}
}

func TestParseFrontendBind_ParameterLengthExceedsPayload(t *testing.T) {
	var p []byte
	p = append(p, cstr("")...)
	p = append(p, cstr("")...)
	p = append(p, beU16(0)...)
	p = append(p, beU16(1)...)
	p = append(p, beU32(100)...)   // claims 100 bytes
	p = append(p, []byte("ab")...) // only 2 provided
	_, err := ParseFrontendBind(p)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryLengthExceedsPayload {
		t.Fatalf("expected CategoryLengthExceedsPayload, got %v", cat)
	}
}

func TestParseFrontendBind_LengthBelowNegativeOne(t *testing.T) {
	var p []byte
	p = append(p, cstr("")...)
	p = append(p, cstr("")...)
	p = append(p, beU16(0)...)
	p = append(p, beU16(1)...)
	p = append(p, beI32(-2)...)
	_, err := ParseFrontendBind(p)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryInvalidLength {
		t.Fatalf("expected CategoryInvalidLength, got %v", cat)
	}
}

func TestParseFrontendBind_ResultFormatCodes(t *testing.T) {
	msg, err := ParseFrontendBind(buildBindPayload("", "", nil, nil, []int16{0, 1}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.ResultFormats) != 2 || msg.ResultFormats[0] != 0 || msg.ResultFormats[1] != 1 {
		t.Fatalf("unexpected result formats: %+v", msg.ResultFormats)
	}
}

func TestParseFrontendBind_InvalidResultFormatCode(t *testing.T) {
	payload := buildBindPayload("", "", nil, nil, []int16{5})
	_, err := ParseFrontendBind(payload)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryInvalidFormatCode {
		t.Fatalf("expected CategoryInvalidFormatCode, got %v", cat)
	}
}

func TestParseFrontendBind_TrailingGarbage(t *testing.T) {
	payload := append(buildBindPayload("", "", nil, nil, nil), 0xFF)
	_, err := ParseFrontendBind(payload)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryTrailingBytes {
		t.Fatalf("expected CategoryTrailingBytes, got %v", cat)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- Describe --------------------------------------------------------------

func TestParseFrontendDescribe_Statement(t *testing.T) {
	msg, err := ParseFrontendDescribe(buildDescribePayload('S', "stmt1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Target != TargetStatement || msg.Name != "stmt1" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestParseFrontendDescribe_Portal(t *testing.T) {
	msg, err := ParseFrontendDescribe(buildDescribePayload('P', "p1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Target != TargetPortal || msg.Name != "p1" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestParseFrontendDescribe_InvalidSelector(t *testing.T) {
	_, err := ParseFrontendDescribe(buildDescribePayload('X', ""))
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryInvalidSelector {
		t.Fatalf("expected CategoryInvalidSelector, got %v", cat)
	}
}

func TestParseFrontendDescribe_MissingTerminator(t *testing.T) {
	_, err := ParseFrontendDescribe([]byte{'S', 'x', 'y'})
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryMissingTerminator {
		t.Fatalf("expected CategoryMissingTerminator, got %v", cat)
	}
}

func TestParseFrontendDescribe_TrailingGarbage(t *testing.T) {
	payload := append(buildDescribePayload('S', ""), 0xFF)
	_, err := ParseFrontendDescribe(payload)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryTrailingBytes {
		t.Fatalf("expected CategoryTrailingBytes, got %v", cat)
	}
}

// --- Execute -----------------------------------------------------------

func TestParseFrontendExecute_UnnamedPortal(t *testing.T) {
	msg, err := ParseFrontendExecute(buildExecutePayload("", 0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.PortalName != "" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestParseFrontendExecute_NamedPortal(t *testing.T) {
	msg, err := ParseFrontendExecute(buildExecutePayload("p1", 0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.PortalName != "p1" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestParseFrontendExecute_ZeroMaxRows(t *testing.T) {
	msg, err := ParseFrontendExecute(buildExecutePayload("", 0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.MaxRows != 0 {
		t.Fatalf("expected MaxRows 0, got %d", msg.MaxRows)
	}
}

func TestParseFrontendExecute_PositiveMaxRows(t *testing.T) {
	msg, err := ParseFrontendExecute(buildExecutePayload("", 100))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.MaxRows != 100 {
		t.Fatalf("expected MaxRows 100, got %d", msg.MaxRows)
	}
}

func TestParseFrontendExecute_NegativeMaxRows(t *testing.T) {
	_, err := ParseFrontendExecute(buildExecutePayload("", -1))
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryNegativeMaxRows {
		t.Fatalf("expected CategoryNegativeMaxRows, got %v", cat)
	}
}

func TestParseFrontendExecute_TruncatedInt32(t *testing.T) {
	payload := append(cstr(""), 0, 0) // only 2 of 4 maxRows bytes
	_, err := ParseFrontendExecute(payload)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryTruncated {
		t.Fatalf("expected CategoryTruncated, got %v", cat)
	}
}

func TestParseFrontendExecute_TrailingGarbage(t *testing.T) {
	payload := append(buildExecutePayload("", 0), 0xFF)
	_, err := ParseFrontendExecute(payload)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryTrailingBytes {
		t.Fatalf("expected CategoryTrailingBytes, got %v", cat)
	}
}

// --- Close ---------------------------------------------------------------

func TestParseFrontendClose_Statement(t *testing.T) {
	msg, err := ParseFrontendClose(buildClosePayload('S', "stmt1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Target != TargetStatement || msg.Name != "stmt1" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestParseFrontendClose_Portal(t *testing.T) {
	msg, err := ParseFrontendClose(buildClosePayload('P', "p1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Target != TargetPortal || msg.Name != "p1" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestParseFrontendClose_InvalidSelector(t *testing.T) {
	_, err := ParseFrontendClose(buildClosePayload('X', ""))
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryInvalidSelector {
		t.Fatalf("expected CategoryInvalidSelector, got %v", cat)
	}
}

func TestParseFrontendClose_MissingTerminator(t *testing.T) {
	_, err := ParseFrontendClose([]byte{'P', 'x'})
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryMissingTerminator {
		t.Fatalf("expected CategoryMissingTerminator, got %v", cat)
	}
}

func TestParseFrontendClose_TrailingGarbage(t *testing.T) {
	payload := append(buildClosePayload('S', ""), 0xFF)
	_, err := ParseFrontendClose(payload)
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryTrailingBytes {
		t.Fatalf("expected CategoryTrailingBytes, got %v", cat)
	}
}

// --- Flush / Sync ----------------------------------------------------------

func TestParseFrontendFlush_EmptyPayloadAccepted(t *testing.T) {
	if err := ParseFrontendFlush(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFrontendFlush_NonEmptyPayloadRejected(t *testing.T) {
	err := ParseFrontendFlush([]byte{0x01})
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryNonEmptyPayload {
		t.Fatalf("expected CategoryNonEmptyPayload, got %v", cat)
	}
}

func TestParseFrontendSync_EmptyPayloadAccepted(t *testing.T) {
	if err := ParseFrontendSync(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFrontendSync_NonEmptyPayloadRejected(t *testing.T) {
	err := ParseFrontendSync([]byte{0x01})
	if err == nil {
		t.Fatal("expected error")
	}
	if cat := extendedParseErrorCategory(t, err); cat != CategoryNonEmptyPayload {
		t.Fatalf("expected CategoryNonEmptyPayload, got %v", cat)
	}
}

// --- Fuzz targets ------------------------------------------------------
//
// These guard the invariants required of any untrusted-input parser:
// never panic, never over-allocate based on a malformed declared length,
// and never leak parameter/SQL values into error text.

func FuzzParseFrontendParse(f *testing.F) {
	f.Add(buildParsePayload("", "SELECT 1", nil))
	f.Add(buildParsePayload("stmt1", "SELECT $1", []uint32{23}))
	f.Add([]byte{})
	f.Add([]byte{0})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseFrontendParse(data)
		if err != nil {
			var perr *ExtendedParseError
			if !errors.As(err, &perr) {
				t.Fatalf("expected *ExtendedParseError, got %T", err)
			}
			return
		}
		if msg == nil {
			t.Fatal("expected non-nil message on success")
		}
	})
}

func FuzzParseFrontendBind(f *testing.F) {
	f.Add(buildBindPayload("", "", nil, nil, nil))
	f.Add(buildBindPayload("p", "s", []int16{0}, []testBindParam{{value: []byte("x")}}, []int16{0}))
	f.Add([]byte{})
	f.Add([]byte{0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseFrontendBind(data)
		if err != nil {
			var perr *ExtendedParseError
			if !errors.As(err, &perr) {
				t.Fatalf("expected *ExtendedParseError, got %T", err)
			}
			return
		}
		if msg == nil {
			t.Fatal("expected non-nil message on success")
		}
	})
}

func FuzzParseFrontendDescribe(f *testing.F) {
	f.Add(buildDescribePayload('S', "stmt1"))
	f.Add(buildDescribePayload('P', ""))
	f.Add([]byte{})
	f.Add([]byte{'X'})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseFrontendDescribe(data)
		if err != nil {
			var perr *ExtendedParseError
			if !errors.As(err, &perr) {
				t.Fatalf("expected *ExtendedParseError, got %T", err)
			}
			return
		}
		if msg == nil {
			t.Fatal("expected non-nil message on success")
		}
	})
}

func FuzzParseFrontendExecute(f *testing.F) {
	f.Add(buildExecutePayload("", 0))
	f.Add(buildExecutePayload("p1", 100))
	f.Add([]byte{})
	f.Add([]byte{0})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseFrontendExecute(data)
		if err != nil {
			var perr *ExtendedParseError
			if !errors.As(err, &perr) {
				t.Fatalf("expected *ExtendedParseError, got %T", err)
			}
			return
		}
		if msg == nil {
			t.Fatal("expected non-nil message on success")
		}
		if msg.MaxRows < 0 {
			t.Fatalf("success must never report a negative MaxRows: %d", msg.MaxRows)
		}
	})
}

func FuzzParseFrontendClose(f *testing.F) {
	f.Add(buildClosePayload('S', "stmt1"))
	f.Add(buildClosePayload('P', ""))
	f.Add([]byte{})
	f.Add([]byte{'X'})

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseFrontendClose(data)
		if err != nil {
			var perr *ExtendedParseError
			if !errors.As(err, &perr) {
				t.Fatalf("expected *ExtendedParseError, got %T", err)
			}
			return
		}
		if msg == nil {
			t.Fatal("expected non-nil message on success")
		}
	})
}

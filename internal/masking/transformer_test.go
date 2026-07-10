package masking

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/gkurcaloglu/sentineldb/internal/protocol"
)

// --- test yardimcilari: ham backend mesaji kodlayicilari ---

func encodeSimpleMessage(tag byte, payload []byte) []byte {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)+4))
	return append(append([]byte{tag}, length...), payload...)
}

func encodeRowDescription(fields []protocol.RowField) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, uint16(len(fields)))
	for _, f := range fields {
		body = append(body, []byte(f.Name)...)
		body = append(body, 0)

		buf4 := make([]byte, 4)
		buf2 := make([]byte, 2)
		binary.BigEndian.PutUint32(buf4, f.TableOID)
		body = append(body, buf4...)
		binary.BigEndian.PutUint16(buf2, uint16(f.Attribute))
		body = append(body, buf2...)
		binary.BigEndian.PutUint32(buf4, f.DataTypeOID)
		body = append(body, buf4...)
		binary.BigEndian.PutUint16(buf2, uint16(f.DataTypeSize))
		body = append(body, buf2...)
		binary.BigEndian.PutUint32(buf4, uint32(f.TypeModifier))
		body = append(body, buf4...)
		binary.BigEndian.PutUint16(buf2, uint16(f.FormatCode))
		body = append(body, buf2...)
	}
	return encodeSimpleMessage('T', body)
}

func encodeDataRow(cells []protocol.DataCell) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, uint16(len(cells)))
	for _, c := range cells {
		lenBuf := make([]byte, 4)
		if c.Null {
			binary.BigEndian.PutUint32(lenBuf, 0xFFFFFFFF)
			body = append(body, lenBuf...)
			continue
		}
		binary.BigEndian.PutUint32(lenBuf, uint32(len(c.Value)))
		body = append(body, lenBuf...)
		body = append(body, c.Value...)
	}
	return encodeSimpleMessage('D', body)
}

func encodeCommandComplete(tag string) []byte {
	return encodeSimpleMessage('C', append([]byte(tag), 0))
}

func encodeReadyForQuery(status byte) []byte {
	return encodeSimpleMessage('Z', []byte{status})
}

func encodeAuthenticationOk() []byte {
	return encodeSimpleMessage('R', []byte{0, 0, 0, 0})
}

func encodeCopyOutResponse() []byte {
	return encodeSimpleMessage('H', []byte{0, 0, 0})
}

// --- sahte Masker ---

type maskCall struct {
	column, kind, value string
}

type fakeMasker struct {
	maskFunc func(column, value string) (string, bool, error)
	calls    []maskCall
}

func (f *fakeMasker) Mask(ctx context.Context, column, kind, value string) (string, bool, string, error) {
	f.calls = append(f.calls, maskCall{column, kind, value})
	if f.maskFunc == nil {
		return value, false, "", nil
	}
	masked, changed, err := f.maskFunc(column, value)
	return masked, changed, "", err
}

// emailLikeMasker, gercek eklenti mantigini tekrarlamadan (o zaten
// plugins/firewall ve internal/wasm seviyesinde test ediliyor), Transformer
// orkestrasyonunu izole test etmek icin basit bir "@" iceriyorsa maskele
// kurali uygular.
func emailLikeMasker() *fakeMasker {
	return &fakeMasker{
		maskFunc: func(column, value string) (string, bool, error) {
			if !strings.Contains(value, "@") {
				return value, false, nil
			}
			return "MASKED", true, nil
		},
	}
}

func idAndEmailFields(emailFormatCode int16) []protocol.RowField {
	return []protocol.RowField{
		{Name: "id", DataTypeOID: 23, DataTypeSize: 4, TypeModifier: -1, FormatCode: 0},
		{Name: "email", DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, FormatCode: emailFormatCode},
	}
}

// --- testler ---

func TestTransformer_MasksConfiguredColumn(t *testing.T) {
	var client bytes.Buffer
	masker := emailLikeMasker()
	cfg := NewConfig(true, []string{"email"})
	tr := NewTransformer(cfg, masker, &client, nil, Hooks{})

	var stream bytes.Buffer
	stream.Write(encodeRowDescription(idAndEmailFields(0)))
	stream.Write(encodeDataRow([]protocol.DataCell{
		{Value: []byte("1")},
		{Value: []byte("john@example.com")},
	}))

	if err := tr.Run(&stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	row, err := protocol.ParseDataRow(lastMessagePayload(t, client.Bytes()))
	if err != nil {
		t.Fatalf("failed to parse output DataRow: %v", err)
	}
	if string(row.Cells[1].Value) != "MASKED" {
		t.Fatalf("expected email cell to be masked, got %q", row.Cells[1].Value)
	}
	if len(masker.calls) != 1 || masker.calls[0].column != "email" {
		t.Fatalf("expected exactly one Mask call for column 'email', got %+v", masker.calls)
	}
}

func TestTransformer_NonTargetColumnUnchanged(t *testing.T) {
	var client bytes.Buffer
	masker := emailLikeMasker()
	cfg := NewConfig(true, []string{"email"})
	tr := NewTransformer(cfg, masker, &client, nil, Hooks{})

	var stream bytes.Buffer
	stream.Write(encodeRowDescription(idAndEmailFields(0)))
	stream.Write(encodeDataRow([]protocol.DataCell{
		{Value: []byte("42")},
		{Value: []byte("john@example.com")},
	}))

	if err := tr.Run(&stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	row, err := protocol.ParseDataRow(lastMessagePayload(t, client.Bytes()))
	if err != nil {
		t.Fatalf("failed to parse output DataRow: %v", err)
	}
	if string(row.Cells[0].Value) != "42" {
		t.Fatalf("expected non-target column 'id' unchanged, got %q", row.Cells[0].Value)
	}
}

func TestTransformer_NullEmailUnchanged_MaskerNeverCalled(t *testing.T) {
	var client bytes.Buffer
	masker := emailLikeMasker()
	cfg := NewConfig(true, []string{"email"})
	tr := NewTransformer(cfg, masker, &client, nil, Hooks{})

	var stream bytes.Buffer
	stream.Write(encodeRowDescription(idAndEmailFields(0)))
	dataRow := encodeDataRow([]protocol.DataCell{
		{Value: []byte("1")},
		{Null: true},
	})
	stream.Write(dataRow)

	if err := tr.Run(&stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(masker.calls) != 0 {
		t.Fatalf("expected the masker to never be called for a NULL cell, got %+v", masker.calls)
	}

	out := lastMessage(t, client.Bytes())
	if !bytes.Equal(out, dataRow) {
		t.Fatalf("expected the DataRow to be forwarded byte-for-byte unchanged\ngot:  %v\nwant: %v", out, dataRow)
	}
}

func TestTransformer_InvalidEmailUnchanged(t *testing.T) {
	var client bytes.Buffer
	masker := emailLikeMasker()
	cfg := NewConfig(true, []string{"email"})
	tr := NewTransformer(cfg, masker, &client, nil, Hooks{})

	var stream bytes.Buffer
	stream.Write(encodeRowDescription(idAndEmailFields(0)))
	dataRow := encodeDataRow([]protocol.DataCell{
		{Value: []byte("1")},
		{Value: []byte("not-an-email")},
	})
	stream.Write(dataRow)

	if err := tr.Run(&stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := lastMessage(t, client.Bytes())
	if !bytes.Equal(out, dataRow) {
		t.Fatalf("expected the DataRow to be forwarded unchanged for a non-email value\ngot:  %v\nwant: %v", out, dataRow)
	}
}

func TestTransformer_MultipleRows(t *testing.T) {
	var client bytes.Buffer
	masker := emailLikeMasker()
	cfg := NewConfig(true, []string{"email"})
	tr := NewTransformer(cfg, masker, &client, nil, Hooks{})

	var stream bytes.Buffer
	stream.Write(encodeRowDescription(idAndEmailFields(0)))
	stream.Write(encodeDataRow([]protocol.DataCell{{Value: []byte("1")}, {Value: []byte("a@example.com")}}))
	stream.Write(encodeDataRow([]protocol.DataCell{{Value: []byte("2")}, {Value: []byte("b@example.com")}}))
	stream.Write(encodeDataRow([]protocol.DataCell{{Value: []byte("3")}, {Null: true}}))

	if err := tr.Run(&stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(masker.calls) != 2 {
		t.Fatalf("expected 2 mask calls (NULL row skipped), got %d: %+v", len(masker.calls), masker.calls)
	}

	messages := splitMessages(t, client.Bytes())
	if len(messages) != 4 { // RowDescription + 3 DataRow
		t.Fatalf("expected 4 forwarded messages, got %d", len(messages))
	}
}

func TestTransformer_MultipleResultSets_ClearsStateBetweenSets(t *testing.T) {
	var client bytes.Buffer
	masker := emailLikeMasker()
	cfg := NewConfig(true, []string{"email"})
	tr := NewTransformer(cfg, masker, &client, nil, Hooks{})

	var stream bytes.Buffer
	// Birinci sonuc kumesi: email sutunu var, maskelenmeli.
	stream.Write(encodeRowDescription(idAndEmailFields(0)))
	stream.Write(encodeDataRow([]protocol.DataCell{{Value: []byte("1")}, {Value: []byte("a@example.com")}}))
	stream.Write(encodeCommandComplete("SELECT 1"))

	// Ikinci sonuc kumesi: email sutunu YOK (farkli bir sorgu); '@' iceren
	// bir deger olsa bile RowDescription'da "email" adinda bir sutun
	// olmadigindan maskeleme denenmemeli.
	stream.Write(encodeRowDescription([]protocol.RowField{
		{Name: "note", DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, FormatCode: 0},
	}))
	stream.Write(encodeDataRow([]protocol.DataCell{{Value: []byte("contains @ but not a target column")}}))
	stream.Write(encodeCommandComplete("SELECT 1"))
	stream.Write(encodeReadyForQuery('I'))

	if err := tr.Run(&stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(masker.calls) != 1 {
		t.Fatalf("expected exactly 1 mask call (only the first result set has an email column), got %d: %+v", len(masker.calls), masker.calls)
	}
}

func TestTransformer_CaseInsensitiveColumnMatching(t *testing.T) {
	var client bytes.Buffer
	masker := emailLikeMasker()
	cfg := NewConfig(true, []string{"EmAiL"})
	tr := NewTransformer(cfg, masker, &client, nil, Hooks{})

	var stream bytes.Buffer
	stream.Write(encodeRowDescription([]protocol.RowField{
		{Name: "Email", DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, FormatCode: 0},
	}))
	stream.Write(encodeDataRow([]protocol.DataCell{{Value: []byte("john@example.com")}}))

	if err := tr.Run(&stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(masker.calls) != 1 {
		t.Fatalf("expected case-insensitive column matching to trigger masking, got %+v", masker.calls)
	}
}

func TestTransformer_BinaryFormatColumnFailsClosed(t *testing.T) {
	var client bytes.Buffer
	masker := emailLikeMasker()
	cfg := NewConfig(true, []string{"email"})
	tr := NewTransformer(cfg, masker, &client, nil, Hooks{})

	var stream bytes.Buffer
	stream.Write(encodeRowDescription(idAndEmailFields(1))) // format code 1 = binary
	stream.Write(encodeDataRow([]protocol.DataCell{
		{Value: []byte("1")},
		{Value: []byte("john@example.com")},
	}))

	err := tr.Run(&stream)
	if !IsFailClosed(err) {
		t.Fatalf("expected a fail-closed error for a binary-format target column, got %v", err)
	}
	if len(masker.calls) != 0 {
		t.Fatal("expected the masker to never be called for a binary-format column")
	}
	if client.Len() == 0 {
		t.Fatal("expected an ErrorResponse to be written to the client")
	}
}

func TestTransformer_FieldCountMismatchFailsClosed(t *testing.T) {
	var client bytes.Buffer
	masker := emailLikeMasker()
	cfg := NewConfig(true, []string{"email"})
	tr := NewTransformer(cfg, masker, &client, nil, Hooks{})

	var stream bytes.Buffer
	stream.Write(encodeRowDescription(idAndEmailFields(0))) // 2 alan bekleniyor
	stream.Write(encodeDataRow([]protocol.DataCell{
		{Value: []byte("1")},
		{Value: []byte("john@example.com")},
		{Value: []byte("extra")}, // 3 hucre - uyusmuyor
	}))

	err := tr.Run(&stream)
	if !IsFailClosed(err) {
		t.Fatalf("expected a fail-closed error for a field-count mismatch, got %v", err)
	}
}

func TestTransformer_FragmentedReadsAreHandledCorrectly(t *testing.T) {
	var client bytes.Buffer
	masker := emailLikeMasker()
	cfg := NewConfig(true, []string{"email"})
	tr := NewTransformer(cfg, masker, &client, nil, Hooks{})

	var full bytes.Buffer
	full.Write(encodeRowDescription(idAndEmailFields(0)))
	full.Write(encodeDataRow([]protocol.DataCell{{Value: []byte("1")}, {Value: []byte("john@example.com")}}))

	if err := tr.Run(&fragmentedReader{data: full.Bytes(), chunkSize: 3}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(masker.calls) != 1 {
		t.Fatalf("expected masking to still occur despite fragmented reads, got %+v", masker.calls)
	}
	row, err := protocol.ParseDataRow(lastMessagePayload(t, client.Bytes()))
	if err != nil {
		t.Fatalf("failed to parse output DataRow: %v", err)
	}
	if string(row.Cells[1].Value) != "MASKED" {
		t.Fatalf("expected masked email despite fragmentation, got %q", row.Cells[1].Value)
	}
}

func TestTransformer_MaskerErrorFailsClosed(t *testing.T) {
	var client bytes.Buffer
	masker := &fakeMasker{maskFunc: func(column, value string) (string, bool, error) {
		return "", false, errors.New("wasm cöktü")
	}}
	cfg := NewConfig(true, []string{"email"})

	var loggedErr error
	tr := NewTransformer(cfg, masker, &client, nil, Hooks{
		OnError: func(err error) { loggedErr = err },
	})

	var stream bytes.Buffer
	stream.Write(encodeRowDescription(idAndEmailFields(0)))
	stream.Write(encodeDataRow([]protocol.DataCell{{Value: []byte("1")}, {Value: []byte("john@example.com")}}))

	err := tr.Run(&stream)
	if !IsFailClosed(err) {
		t.Fatalf("expected a fail-closed error when the masker errors, got %v", err)
	}
	if loggedErr == nil {
		t.Fatal("expected OnError to be called")
	}
}

func TestTransformer_CopyProtocolFailsClosed(t *testing.T) {
	var client bytes.Buffer
	tr := NewTransformer(NewConfig(false, nil), emailLikeMasker(), &client, nil, Hooks{})

	stream := bytes.NewReader(encodeCopyOutResponse())
	err := tr.Run(stream)
	if !IsFailClosed(err) {
		t.Fatalf("expected COPY protocol messages to fail closed, got %v", err)
	}
}

func TestTransformer_ReadyForQuery_UpdatesTxState(t *testing.T) {
	var client bytes.Buffer
	txState := protocol.NewTxState()
	tr := NewTransformer(NewConfig(false, nil), emailLikeMasker(), &client, txState, Hooks{})

	stream := bytes.NewReader(encodeReadyForQuery(protocol.TxStatusInTransaction))
	if err := tr.Run(stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := txState.Get(); got != protocol.TxStatusInTransaction {
		t.Fatalf("expected txState to be updated to 'T', got %q", got)
	}
}

func TestTransformer_UnrelatedMessagesForwardedUnchanged(t *testing.T) {
	var client bytes.Buffer
	tr := NewTransformer(NewConfig(false, nil), emailLikeMasker(), &client, nil, Hooks{})

	auth := encodeAuthenticationOk()
	if err := tr.Run(bytes.NewReader(auth)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(client.Bytes(), auth) {
		t.Fatalf("expected Authentication forwarded byte-for-byte\ngot:  %v\nwant: %v", client.Bytes(), auth)
	}
}

func TestTransformer_MaskingDisabled_NoMaskingAttempted(t *testing.T) {
	var client bytes.Buffer
	masker := emailLikeMasker()
	tr := NewTransformer(NewConfig(false, []string{"email"}), masker, &client, nil, Hooks{})

	var stream bytes.Buffer
	stream.Write(encodeRowDescription(idAndEmailFields(0)))
	dataRow := encodeDataRow([]protocol.DataCell{{Value: []byte("1")}, {Value: []byte("john@example.com")}})
	stream.Write(dataRow)

	if err := tr.Run(&stream); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(masker.calls) != 0 {
		t.Fatalf("expected no masking when disabled, got %+v", masker.calls)
	}
	if !bytes.Equal(lastMessage(t, client.Bytes()), dataRow) {
		t.Fatal("expected DataRow forwarded unchanged when masking is disabled")
	}
}

// --- genel test yardimcilari ---

// fragmentedReader, TCP parcalanmasini (fragmentation) simule etmek icin
// veriyi kucuk parcalar halinde dondurur.
type fragmentedReader struct {
	data      []byte
	chunkSize int
	pos       int
}

func (r *fragmentedReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := r.chunkSize
	if n > len(p) {
		n = len(p)
	}
	if r.pos+n > len(r.data) {
		n = len(r.data) - r.pos
	}
	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	return n, nil
}

// splitMessages, ham bir backend bayt akisini tag+length cercevelerine
// gore mesajlara boler (test dogrulamalari icin).
func splitMessages(t *testing.T, data []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(data) > 0 {
		if len(data) < 5 {
			t.Fatalf("trailing incomplete message: %v", data)
		}
		length := binary.BigEndian.Uint32(data[1:5])
		total := 1 + int(length)
		if total > len(data) {
			t.Fatalf("message length exceeds remaining buffer: %v", data)
		}
		out = append(out, data[:total])
		data = data[total:]
	}
	return out
}

func lastMessage(t *testing.T, data []byte) []byte {
	t.Helper()
	msgs := splitMessages(t, data)
	if len(msgs) == 0 {
		t.Fatal("expected at least one forwarded message")
	}
	return msgs[len(msgs)-1]
}

func lastMessagePayload(t *testing.T, data []byte) []byte {
	t.Helper()
	msg := lastMessage(t, data)
	return msg[5:]
}

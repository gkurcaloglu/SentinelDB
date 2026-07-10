package wasm

import "context"

// Masker, mevcut Runtime'i (firewall Evaluate ile AYNI, tek yüklü Wasm
// modülü) internal/masking.Masker arayüzünden besleyen bir adaptördür.
// Bu, internal/wasm.Policy'nin firewall.Policy arayüzünü Runtime.Evaluate'
// ten beslediği desenin tam bir eşidir.
type Masker struct {
	rt *Runtime
}

// NewMasker, rt üzerinden çalışan bir Masker oluşturur.
func NewMasker(rt *Runtime) *Masker {
	return &Masker{rt: rt}
}

// Mask, internal/masking.Masker arayüzünü karşılar.
func (m *Masker) Mask(ctx context.Context, column, kind, value string) (maskedValue string, changed bool, reason string, err error) {
	res, err := m.rt.Mask(ctx, column, kind, value)
	if err != nil {
		return "", false, "", err
	}
	return res.Value, res.Changed, res.Reason, nil
}

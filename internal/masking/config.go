// Package masking, PostgreSQL backend yanıtlarında yapılandırılmış
// sütunları (ör. "email") mevcut sandbox'lı Wasm eklentisi aracılığıyla
// maskeleyen aktif bir yanıt dönüştürücüyü (Transformer) barındırır.
package masking

import "strings"

// Config, hangi sütunların maskeleneceğinin host tarafı tanımıdır (bkz.
// internal/config.MaskingConfig, cmd/gateway'in bu paketten bağımsız
// tuttuğu YAML şeması). Eşleştirme yalnızca RowDescription'daki sütun
// adına karşı, büyük/küçük harf duyarsız TAM eşleşme ile yapılır: regex,
// şema keşfi ya da AI tabanlı sınıflandırma yoktur.
type Config struct {
	Enabled bool
	columns map[string]struct{} // kucuk harfe cevrilmis sutun adi -> var
}

// NewConfig, enabled ve columns'tan bir Config oluşturur.
func NewConfig(enabled bool, columns []string) Config {
	set := make(map[string]struct{}, len(columns))
	for _, c := range columns {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		set[strings.ToLower(c)] = struct{}{}
	}
	return Config{Enabled: enabled, columns: set}
}

// ShouldMask, columnName'in (büyük/küçük harf duyarsız) yapılandırılmış
// maskelenecek sütunlardan biri olup olmadığını bildirir. Enabled false
// ise her zaman false döner.
func (c Config) ShouldMask(columnName string) bool {
	if !c.Enabled {
		return false
	}
	_, ok := c.columns[strings.ToLower(columnName)]
	return ok
}

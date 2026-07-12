// Package config, SentinelDB gateway'inin config.yaml dosyasından okuduğu
// çalışma zamanı ayarlarını tanımlar.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config, config.yaml dosyasının kök yapısıdır.
type Config struct {
	Firewall FirewallConfig `yaml:"firewall"`
	Wasm     WasmConfig     `yaml:"wasm"`
	Logging  LoggingConfig  `yaml:"logging"`
	Masking  MaskingConfig  `yaml:"masking"`
}

// FirewallConfig, firewall politikasını besleyen ayarlardır. BlockedPhrases
// listesi, karar mantığı ister native (firewall.DenyKeywords) ister Wasm
// eklentisi (internal/wasm.Policy) üzerinden çalışsın, tek kaynaktır.
type FirewallConfig struct {
	// BlockedPhrases, Simple Query metninde geçtiğinde sorgunun
	// engelleneceği ifadelerdir (büyük/küçük harf ve boşluk duyarsız).
	BlockedPhrases []string `yaml:"blocked_phrases"`
}

// WasmConfig, internal/wasm.Runtime'in yükleyeceği firewall Wasm eklentisini
// tanımlar.
type WasmConfig struct {
	// PluginPath, GOOS=wasip1 GOARCH=wasm ile derlenmiş .wasm dosyasının
	// yoludur (bkz. plugins/firewall).
	PluginPath string `yaml:"plugin_path"`
}

// LoggingConfig, gateway'in logladığı bilginin kapsamını kontrol eder.
type LoggingConfig struct {
	// LogFullQueries, true ise Simple Query mesajlarının tam SQL metnini
	// (potansiyel olarak PII/hassas veri içerebilir) loglara yazar.
	// Varsayılan olarak false'tur: SentinelDB üretimde sorgu metnini
	// loglamaz, yalnızca verdict/mesaj tipi/süre/bağlantı kimliği gibi
	// güvenli metadata loglar. Yalnızca lokal geliştirme/hata ayıklama
	// için açıkça etkinleştirilmelidir.
	LogFullQueries bool `yaml:"log_full_queries"`
}

// MaskingConfig, PII maskeleme davranışını kontrol eder. Eşleştirme
// yalnızca RowDescription'daki sütun adına karşı, büyük/küçük harf
// duyarsız tam eşleşme ile yapılır - regex, şema keşfi (schema discovery)
// ya da AI tabanlı sınıflandırma yoktur (bkz. internal/masking.Config).
type MaskingConfig struct {
	// Enabled, false ise hiçbir sütun maskelenmez ve internal/masking
	// Wasm eklentisini hiç çağırmaz.
	Enabled bool `yaml:"enabled"`
	// Columns, maskeleneceği yapılandırılmış sütun adlarının listesidir
	// (ör. "email"). Yalnızca configured (bu listede olan) sütunlar
	// incelenir; diğer sütunların değerleri hiç okunmaz/tahmin edilmez.
	Columns []string `yaml:"columns"`
}

// validate, masking.enabled=true iken en az bir boş olmayan sütun adı
// verilmiş olmasını zorunlu kılar. Aksi halde maskeleme "açık ama hiçbir
// şey yapmıyor" gibi sessizce yanlış bir duruma düşebilirdi.
func (m MaskingConfig) validate() error {
	if !m.Enabled {
		return nil
	}
	for _, c := range m.Columns {
		if strings.TrimSpace(c) != "" {
			return nil
		}
	}
	return fmt.Errorf("masking.enabled=true ama masking.columns bos; en az bir sutun adi gerekli")
}

// Load, path'teki YAML dosyasını okuyup bir Config'e ayrıştırır.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config dosyasi okunamadi (%s): %w", path, err)
	}

	// yaml.Unmarshal bilinmeyen alanlari sessizce yok sayar (ör. bir yazim
	// hatasi iceren anahtar hicbir hataya yol acmadan goz ardi edilirdi).
	// Bunun yerine sıkı bir Decoder kullanarak bilinmeyen her alani acik
	// bir hata olarak reddediyoruz - operatorun config.yaml'daki bir yazim
	// hatasi ya da gecersiz anahtar yuzunden beklediginden farkli bir
	// davranisi sessizce almasini onlemek icin.
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	// Bos bir dosya (ör. sifir bayt) gecerli, tum alanlari sifir-degerli bir
	// Config olarak kabul edilir - yaml.Unmarshal'in onceki davranisiyla
	// birebir ayni (bkz. TestLoad_EmptyBlockedPhrasesIsValid gibi testler).
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config dosyasi ayristirilamadi (%s): %w", path, err)
	}

	if err := cfg.Masking.validate(); err != nil {
		return nil, fmt.Errorf("config gecersiz (%s): %w", path, err)
	}

	return &cfg, nil
}

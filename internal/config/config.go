// Package config, SentinelDB gateway'inin config.yaml dosyasından okuduğu
// çalışma zamanı ayarlarını tanımlar.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config, config.yaml dosyasının kök yapısıdır.
type Config struct {
	Firewall FirewallConfig `yaml:"firewall"`
	Wasm     WasmConfig     `yaml:"wasm"`
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

// Load, path'teki YAML dosyasını okuyup bir Config'e ayrıştırır.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config dosyasi okunamadi (%s): %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config dosyasi ayristirilamadi (%s): %w", path, err)
	}

	return &cfg, nil
}

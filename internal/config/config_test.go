package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	return path
}

func TestLoad_ParsesBlockedPhrases(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
    - "DELETE FROM"
    - "TRUNCATE"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"DROP TABLE", "DELETE FROM", "TRUNCATE"}
	got := cfg.Firewall.BlockedPhrases
	if len(got) != len(want) {
		t.Fatalf("expected %d phrases, got %d: %+v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("phrase %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoad_ParsesWasmPluginPath(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
wasm:
  plugin_path: "plugins/firewall/v2.wasm"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "plugins/firewall/v2.wasm"; cfg.Wasm.PluginPath != want {
		t.Fatalf("Wasm.PluginPath = %q, want %q", cfg.Wasm.PluginPath, want)
	}
}

func TestLoad_LogFullQueriesDefaultsToFalse(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Logging.LogFullQueries {
		t.Fatal("expected LogFullQueries to default to false when logging section is absent")
	}
}

func TestLoad_ParsesLogFullQueriesWhenExplicitlyEnabled(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
logging:
  log_full_queries: true
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Logging.LogFullQueries {
		t.Fatal("expected LogFullQueries to be true when explicitly enabled")
	}
}

func TestLoad_MaskingDisabledByDefault(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Masking.Enabled {
		t.Fatal("expected Masking.Enabled to default to false when masking section is absent")
	}
}

func TestLoad_ParsesMaskingConfig(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
masking:
  enabled: true
  columns:
    - email
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Masking.Enabled {
		t.Fatal("expected Masking.Enabled to be true")
	}
	if len(cfg.Masking.Columns) != 1 || cfg.Masking.Columns[0] != "email" {
		t.Fatalf("expected Masking.Columns = [email], got %+v", cfg.Masking.Columns)
	}
}

func TestLoad_MaskingEnabledWithNoColumnsIsInvalid(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
masking:
  enabled: true
  columns: []
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error when masking is enabled with an empty column list")
	}
}

func TestLoad_MaskingEnabledWithOnlyBlankColumnsIsInvalid(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
masking:
  enabled: true
  columns:
    - "   "
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error when masking is enabled with only blank column names")
	}
}

func TestLoad_MaskingDisabledWithNoColumnsIsValid(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
masking:
  enabled: false
`)

	if _, err := Load(path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoad_MissingFileReturnsError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected an error for a missing config file, got nil")
	}
}

func TestLoad_MalformedYAMLReturnsError(t *testing.T) {
	path := writeTempConfig(t, "firewall: [this is not: a valid map")

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error for malformed YAML, got nil")
	}
}

func TestLoad_EmptyBlockedPhrasesIsValid(t *testing.T) {
	path := writeTempConfig(t, "firewall:\n  blocked_phrases: []\n")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Firewall.BlockedPhrases) != 0 {
		t.Fatalf("expected no blocked phrases, got %+v", cfg.Firewall.BlockedPhrases)
	}
}

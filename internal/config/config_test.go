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

func TestLoad_ProtocolExtendedQueryDisabledByDefault(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Protocol.ExtendedQueryEnabled {
		t.Fatal("expected Protocol.ExtendedQueryEnabled to default to false when the protocol section is absent")
	}
}

func TestLoad_ProtocolExtendedQueryExplicitFalse(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
protocol:
  extended_query_enabled: false
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Protocol.ExtendedQueryEnabled {
		t.Fatal("expected Protocol.ExtendedQueryEnabled to be false when explicitly set to false")
	}
}

func TestLoad_ProtocolExtendedQueryExplicitTrue(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
protocol:
  extended_query_enabled: true
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Protocol.ExtendedQueryEnabled {
		t.Fatal("expected Protocol.ExtendedQueryEnabled to be true when explicitly enabled")
	}
}

func TestLoad_ProtocolUnknownFieldIsRejected(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
protocol:
  extended_query_enabled: true
  unknown_protocol_field: "oops"
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown protocol config field")
	}
}

func TestLoad_ProtocolWrongYAMLTypeIsRejected(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
protocol:
  extended_query_enabled: "not-a-bool"
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a non-boolean protocol.extended_query_enabled value")
	}
}

func TestLoad_ProtocolEnabledDoesNotAffectMaskingValidation(t *testing.T) {
	// masking.enabled=true with no columns must still be rejected exactly
	// as before, regardless of protocol.extended_query_enabled.
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
protocol:
  extended_query_enabled: true
masking:
  enabled: true
  columns: []
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected masking validation to remain unchanged when protocol.extended_query_enabled is true")
	}
}

// TestLoad_RepoRootConfigYAMLIsValid loads the actual repository-root
// config.yaml (the one cmd/gateway/main.go reads at startup) to prove it
// still parses under strict KnownFields decoding and that its documented
// default (protocol.extended_query_enabled: false) matches reality.
func TestLoad_RepoRootConfigYAMLIsValid(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatalf("unexpected error loading the repo-root config.yaml: %v", err)
	}
	if cfg.Protocol.ExtendedQueryEnabled {
		t.Fatal("expected the repo-root config.yaml to document protocol.extended_query_enabled: false")
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

func TestLoad_UnknownTopLevelFieldIsRejected(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
unknown_top_level_field: 123
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown top-level config field")
	}
}

func TestLoad_UnknownNestedFieldIsRejected(t *testing.T) {
	path := writeTempConfig(t, `
firewall:
  blocked_phrases:
    - "DROP TABLE"
  unknown_nested_field: "oops"
`)

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown nested config field")
	}
}

func TestLoad_EmptyFileIsValid(t *testing.T) {
	path := writeTempConfig(t, "")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error for an empty config file: %v", err)
	}
	if cfg.Masking.Enabled {
		t.Fatal("expected a zero-value Config (Masking.Enabled=false) for an empty file")
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

package sqlmatch

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"drop   table\tusers;": "DROP TABLE USERS;",
		"  SELECT 1  ":         "SELECT 1",
		"a\nb\r\nc":            "A B C",
		"":                     "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchAny(t *testing.T) {
	phrases := []string{"DROP TABLE", "DELETE FROM"}

	cases := []struct {
		query string
		want  string
	}{
		{"DROP TABLE users;", "DROP TABLE"},
		{"drop   table\tusers;", "DROP TABLE"}, // buyuk/kucuk harf ve bosluk duyarsiz
		{"DELETE FROM users WHERE id = 1;", "DELETE FROM"},
		{"SELECT * FROM users;", ""},
		{"UPDATE users SET name = 'x';", ""},
	}

	for _, tc := range cases {
		if got := MatchAny(tc.query, phrases); got != tc.want {
			t.Errorf("MatchAny(%q, %v) = %q, want %q", tc.query, phrases, got, tc.want)
		}
	}
}

func TestMatchAny_EmptyPhrasesNeverMatch(t *testing.T) {
	if got := MatchAny("DROP TABLE users;", nil); got != "" {
		t.Errorf("expected no match against an empty phrase list, got %q", got)
	}
	if got := MatchAny("DROP TABLE users;", []string{"", ""}); got != "" {
		t.Errorf("expected empty phrases to be skipped, got %q", got)
	}
}

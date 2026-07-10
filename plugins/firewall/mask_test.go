package main

import "testing"

func TestMaskEmail(t *testing.T) {
	cases := []struct {
		input       string
		wantMasked  string
		wantChanged bool
	}{
		{"john@example.com", "jo****@example.com", true},
		{"a@example.com", "a****@example.com", true},          // tek karakterlik yerel kisim
		{"ab@example.com", "ab****@example.com", true},        // tam iki karakter
		{"johnsmith@example.com", "jo****@example.com", true}, // sabit **** genisligi, gercek uzunlugu sizdirmaz
		{"not-an-email", "not-an-email", false},
		{"", "", false},
		{"@example.com", "@example.com", false},                         // yerel kisim bos
		{"john@", "john@", false},                                       // alan adi bos
		{"john@@example.com", "john@@example.com", false},               // birden fazla '@'
		{"john example@example.com", "john example@example.com", false}, // yerel kisimda bosluk
		{"john@example", "john@example", false},                         // alan adinda nokta yok
		{"john@.com", "john@.com", false},                               // alan adi noktayla basliyor
		{"john@example.", "john@example.", false},                       // alan adi noktayla bitiyor
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, changed := maskEmail(tc.input)
			if got != tc.wantMasked {
				t.Errorf("maskEmail(%q) value = %q, want %q", tc.input, got, tc.wantMasked)
			}
			if changed != tc.wantChanged {
				t.Errorf("maskEmail(%q) changed = %v, want %v", tc.input, changed, tc.wantChanged)
			}
		})
	}
}

func TestLooksLikeEmail(t *testing.T) {
	valid := []string{"john@example.com", "a@b.co", "john.smith@sub.example.com"}
	for _, v := range valid {
		if !looksLikeEmail(v) {
			t.Errorf("looksLikeEmail(%q) = false, want true", v)
		}
	}

	invalid := []string{"", "no-at-sign", "@example.com", "john@", "john@@x.com", "john @example.com", "john@example", "john@.com", "john@example."}
	for _, v := range invalid {
		if looksLikeEmail(v) {
			t.Errorf("looksLikeEmail(%q) = true, want false", v)
		}
	}
}

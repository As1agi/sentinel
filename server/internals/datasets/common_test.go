package datasets

import "testing"

func TestExtractCVE(t *testing.T) {
	// Use a slice of structs for deterministic order and clean sub-testing
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Standard clean CVE",
			input:    "CVE-2026-40213",
			expected: "CVE-2026-40213",
		},
		{
			name:     "Embedded with prefix and emoji",
			input:    "GD-CVE-343-HS🤟🏿 (CVE-2014-21331)",
			expected: "CVE-2014-21331",
		},
		{
			name:     "Embedded with missing hyphen in prefix",
			input:    "GDCVE-343-HS🤟🏿 (CVE-2014-26631)",
			expected: "CVE-2014-26631",
		},
		{
			name:     "Embedded with Double CVE prefix before hyphen",
			input:    "CVE-(CVE-2014-26631)",
			expected: "CVE-2014-26631",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ExtractCVE(tc.input)
			if result != tc.expected {
				t.Errorf("expected: %q, got: %q", tc.expected, result)
			}
		})
	}
}

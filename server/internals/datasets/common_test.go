package datasets

import "testing"

func TestExtractCVE(t *testing.T) {
	tt := map[string]string{
		"CVE-2026-40213":                   "2026-40213",
		"GD-CVE-343-HS🤟🏿 (CVE-2014-21331)": "2014-21331",
		"GDCVE-343-HS🤟🏿 (CVE-2014-26631)":  "2014-21331",
	}

	for i, cve := range tt {
		result := ExtractCVE(cve)
		if cve != tt[i] {
			t.Errorf("expected : %v , result : %v ", tt[i], result)
		}
	}
}

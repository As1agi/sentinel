package logic

import (
	"testing"
)

func TestMatchDebian(t *testing.T) {
	tests := []struct {
		name       string
		installed  string
		introduced string
		fixed      string
		expected   Result
	}{
		{
			name:       "Standard vulnerable Ubuntu package",
			installed:  "1.2.10-1ubuntu5.1",
			introduced: "1.2.10-1",
			fixed:      "1.2.10-1ubuntu5.2",
			expected:   Vulnerable,
		},
		{
			name:       "Safe package (exactly equal to fixed version)",
			installed:  "2:7.4.1689-3ubuntu1.5+esm35",
			introduced: "0",
			fixed:      "2:7.4.1689-3ubuntu1.5+esm35",
			expected:   Safe,
		},
		{
			name:       "Safe package (newer than fixed version)",
			installed:  "2:7.4.1689-3ubuntu1.5+esm36",
			introduced: "0",
			fixed:      "2:7.4.1689-3ubuntu1.5+esm35",
			expected:   Safe,
		},
		{
			name:       "Safe package via Epoch override (1:34 is newer than 0:99)",
			installed:  "1:34.0.4-1",
			introduced: "0",
			fixed:      "0:99.9.9",
			expected:   Safe,
		},
		{
			name:       "Safe package (older than introduction bound)",
			installed:  "1.2.9-1",
			introduced: "1.2.10-1",
			fixed:      "1.2.11-1",
			expected:   Safe,
		},
		{
			name:       "Vulnerable package (0-day / no known fix)",
			installed:  "1.5.0-1",
			introduced: "1.4.0-1",
			fixed:      "",
			expected:   Vulnerable,
		},
		{
			name:       "Invalid installed version string (Fail Secure)",
			installed:  "malformed_deb_pkg!!",
			introduced: "0",
			fixed:      "1.0.0",
			expected:   InvalidVersion,
		},
		{
			name:       "Invalid introduced version string (Fail Secure)",
			installed:  "1.0.0",
			introduced: "broken-version-str",
			fixed:      "2.0.0",
			expected:   InvalidVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, _ := MatchDebian(tt.installed, tt.introduced, tt.fixed)
			if actual != tt.expected {
				t.Errorf("MatchDebian() failed for [%s]\nInput: inst=%s, intro=%s, fix=%s\nExpected: %d, Got: %d",
					tt.name, tt.installed, tt.introduced, tt.fixed, tt.expected, actual)
			}
		})
	}
}

func TestMatchRpm(t *testing.T) {
	tests := []struct {
		name       string
		installed  string
		introduced string
		fixed      string
		expected   Result
	}{
		{
			name:       "Vulnerable RHEL release packaging (el8_4 vs el8_5)",
			installed:  "4.14.3-4.el8_4",
			introduced: "4.14.3-1",
			fixed:      "4.14.3-4.el8_5",
			expected:   Vulnerable,
		},
		{
			name:       "Safe RPM package (release number is newer)",
			installed:  "8.4.1-2.el8",
			introduced: "0",
			fixed:      "8.4.1-1.el8",
			expected:   Safe,
		},
		{
			name:       "Safe RPM package (older than introduced)",
			installed:  "5.3.0-1.el8",
			introduced: "5.4.0-1.el8",
			fixed:      "5.5.0-1.el8",
			expected:   Safe,
		},
		{
			name:       "Vulnerable RPM package (unpatched branch exposure)",
			installed:  "2.1.1-1.el8",
			introduced: "2.0.0-1.el8",
			fixed:      "",
			expected:   Vulnerable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, _ := MatchRpm(tt.installed, tt.introduced, tt.fixed)
			if actual != tt.expected {
				t.Errorf("MatchRpm() failed for [%s]\nExpected: %d, Got: %d", tt.name, tt.expected, actual)
			}
		})
	}
}

func TestMatchSemver(t *testing.T) {
	tests := []struct {
		name       string
		installed  string
		introduced string
		fixed      string
		expected   Result
	}{
		{
			name:       "Standard vulnerable SemVer dependency",
			installed:  "1.4.1",
			introduced: "1.0.0",
			fixed:      "1.4.2",
			expected:   Vulnerable,
		},
		{
			name:       "Vulnerable SemVer via Pre-release tag (alpha is older than final release)",
			installed:  "1.2.3-alpha.1",
			introduced: "1.0.0",
			fixed:      "1.2.3",
			expected:   Vulnerable,
		},
		{
			name:       "Safe SemVer package (patched)",
			installed:  "2.1.0",
			introduced: "2.0.0",
			fixed:      "2.0.5",
			expected:   Safe,
		},
		{
			name:       "Malformed SemVer string (Fail Secure)",
			installed:  "v1.foo.bar",
			introduced: "1.0.0",
			fixed:      "2.0.0",
			expected:   InvalidVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, _ := MatchSemver(tt.installed, tt.introduced, tt.fixed)
			if actual != tt.expected {
				t.Errorf("MatchSemver() failed for [%s]\nExpected: %d, Got: %d", tt.name, tt.expected, actual)
			}
		})
	}
}

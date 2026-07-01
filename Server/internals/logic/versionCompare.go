package logic

import (
	"log"
	"strings"

	"github.com/hashicorp/go-version"
	debver "github.com/knqyf263/go-deb-version"
	rpmver "github.com/knqyf263/go-rpm-version"
)

type Result int

const (
	Safe           Result = 0
	Vulnerable     Result = 1
	InvalidVersion Result = -1
)

// CheckVulnerability routes the version strings to the correct specification
// parser based on the OS/Ecosystem and checks if it falls in the vulnerable range.
// Returns 1 if vulnerable, 0 if safe.
func CheckVulnerability(ecosystem, installed, introduced, fixed string) Result {
	// Normalize ecosystem string to ensure reliable matching
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))

	switch {
	//"ubuntu", "debian", "linuxmint", "pop"
	case strings.Contains(ecosystem, "ubuntu") || strings.Contains(ecosystem, "debian"):
		return MatchDebian(installed, introduced, fixed)

		//"fedora", "rhel", "centos", "rocky", "almalinux"
	case strings.Contains(ecosystem, "fedora") || strings.Contains(ecosystem, "rocky"):
		return MatchRpm(installed, introduced, fixed)

	default:
		// Fallback for application ecosystems (golang, npm, pypi)
		// which use standard Semantic Versioning (SemVer)
		log.Printf("parsing Semver")
		return MatchSemver(installed, introduced, fixed)
	}
}

// MatchRpm checks if an RPM package falls within [introduced, fixed)
func MatchRpm(installed, introduced, fixed string) Result {
	// knqyf263/go-rpm-version does not return errors on initialization;
	// it parses valid parts defensive against corruption.
	vInst := rpmver.NewVersion(installed)

	// 1. Evaluate Lower Bound
	if introduced != "" && introduced != "0" {
		vIntro := rpmver.NewVersion(introduced)
		if vInst.LessThan(vIntro) {
			return Safe
		}
	}

	// 2. Evaluate Upper Bound
	if fixed != "" {
		vFixed := rpmver.NewVersion(fixed)
		if vInst.LessThan(vFixed) {
			return Vulnerable
		}
		return Safe
	}

	return Vulnerable
}

// --- RED HAT / FEDORA LOGIC ---
// MatchDebian checks if a debian package falls within [introduced, fixed)
func MatchDebian(installed, introduced, fixed string) Result {
	vInst, err := debver.NewVersion(installed)
	if err != nil {
		return InvalidVersion
	}

	// 1. Evaluate Lower Bound (Introduced)
	if introduced != "" && introduced != "0" {
		vIntro, err := debver.NewVersion(introduced)
		if err != nil {
			return InvalidVersion
		}
		if vInst.LessThan(vIntro) {
			return Safe // Installed version is older than the vulnerability
		}
	}

	// 2. Evaluate Upper Bound (Fixed)
	if fixed != "" {
		vFixed, err := debver.NewVersion(fixed)
		if err != nil {
			return InvalidVersion
		}
		// If installed version is less than fixed, it hasn't received the patch
		if vInst.LessThan(vFixed) {
			return Vulnerable
		}
		return Safe // Installed version is equal to or newer than the fix
	}

	// 3. If introduced condition met but no fixed version exists, it's unpatched
	return Vulnerable
}

// MatchSemver checks if an application dependency falls within [introduced, fixed)
func MatchSemver(installed, introduced, fixed string) Result {
	vInst, err := version.NewVersion(installed)
	if err != nil {
		return InvalidVersion
	}

	// 1. Evaluate Lower Bound
	if introduced != "" && introduced != "0" {
		vIntro, err := version.NewVersion(introduced)
		if err != nil {
			return InvalidVersion
		}
		if vInst.LessThan(vIntro) {
			return Safe
		}
	}

	// 2. Evaluate Upper Bound
	if fixed != "" {
		vFixed, err := version.NewVersion(fixed)
		if err != nil {
			return InvalidVersion
		}
		if vInst.LessThan(vFixed) {
			return Vulnerable
		}
		return Safe
	}

	return Vulnerable
}

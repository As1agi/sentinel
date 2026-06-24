package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/go-version" // For generic SemVer fallback
	debver "github.com/knqyf263/go-deb-version"
	rpmver "github.com/knqyf263/go-rpm-version"
)

// CheckVulnerability routes the version strings to the correct specification
// parser based on the OS/Ecosystem and checks if it falls in the vulnerable range.
// Returns 1 if vulnerable, 0 if safe.
func CheckVulnerability(ecosystem, installed, introduced, fixed string) int {
	// Normalize ecosystem string to ensure reliable matching
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))

	switch ecosystem {
	case "ubuntu", "debian", "linuxmint", "pop":
		return checkDeb(installed, introduced, fixed)

	case "fedora", "rhel", "centos", "rocky", "almalinux":
		return checkRpm(installed, introduced, fixed)

	default:
		// Fallback for application ecosystems (golang, npm, pypi)
		// which use standard Semantic Versioning (SemVer)
		return checkSemver(installed, introduced, fixed)
	}
}

// --- DEBIAN / UBUNTU LOGIC ---
func checkDeb(installed, introduced, fixed string) int {
	vInst, err := debver.NewVersion(installed)
	if err != nil {
		log.Printf("[DEB] Failed to parse installed version %s: %v", installed, err)
		return 0 // Fail open (safe) to prevent false-positive noise
	}

	// 1. Check Lower Bound (Did it exist before the vulnerability was introduced?)
	if introduced != "" && introduced != "0" {
		vIntro, err := debver.NewVersion(introduced)
		if err == nil {
			if vInst.LessThan(vIntro) {
				return 0 // Installed version is older than the bug
			}
		}
	}

	// 2. Check Upper Bound (Has it been patched?)
	if fixed != "" {
		vFixed, err := debver.NewVersion(fixed)
		if err == nil {
			// If installed is LessThan fixed, it has NOT received the patch -> Vulnerable
			if vInst.LessThan(vFixed) {
				return 1
			}
			return 0 // Installed is >= fixed -> Safe
		}
	}

	// 3. If there is no fixed version known, and it's >= introduced, it's a 0-day/unpatched
	return 1
}

// --- RED HAT / FEDORA LOGIC ---
func checkRpm(installed, introduced, fixed string) int {
	vInst := rpmver.NewVersion(installed)

	if introduced != "" && introduced != "0" {
		vIntro := rpmver.NewVersion(introduced)
		if vInst.LessThan(vIntro) {
			return 0
		}
	}

	if fixed != "" {
		vFixed := rpmver.NewVersion(fixed)
		if vInst.LessThan(vFixed) {
			return 1
		}
		return 0
	}

	return 1
}

// --- GENERIC SEMVER LOGIC (App Layer Fallback) ---
func checkSemver(installed, introduced, fixed string) int {
	vInst, err := version.NewVersion(installed)
	if err != nil {
		return 0
	}

	if introduced != "" && introduced != "0" {
		vIntro, err := version.NewVersion(introduced)
		if err == nil && vInst.LessThan(vIntro) {
			return 0
		}
	}

	if fixed != "" {
		vFixed, err := version.NewVersion(fixed)
		if err == nil {
			if vInst.LessThan(vFixed) {
				return 1
			}
			return 0
		}
	}

	return 1
}

func testShared() {
	// --- Test Case 1: Ubuntu Backport (DEB) ---
	// Vulnerable range: Introduced at 1.2.10-1, Fixed in 1.2.10-1ubuntu5.2
	installedDeb := "1.2.10-1ubuntu5.1" // Inside the vulnerable window
	fmt.Printf("Ubuntu Test -> %d\n", CheckVulnerability(
		"ubuntu",
		installedDeb,
		"1.2.10-1",
		"1.2.10-1ubuntu5.2",
	)) // Expected: 1

	// --- Test Case 2: Debian Epoch Upgrade (DEB) ---
	installedEpoch := "1:34.0.4-1" // Epoch 1 bypasses standard numbers
	fixedEpoch := "0:99.9.9"       // Massive number, but lower epoch
	fmt.Printf("Debian Epoch Test -> %d\n", CheckVulnerability(
		"debian",
		installedEpoch,
		"0",
		fixedEpoch,
	)) // Expected: 0 (Installed 1:34 is mathematically newer than 0:99)

	// --- Test Case 3: Fedora Base Package (RPM) ---
	installedRpm := "8.4.1-1.el8"
	fixedRpm := "8.4.1-2.el8"
	fmt.Printf("CentOS RPM Test -> %d\n", CheckVulnerability(
		"centos",
		installedRpm,
		"0",
		fixedRpm,
	)) // Expected: 1 (Release 1 is older than Release 2)

	// --- Test Case 4: Future App Dependency Scanner (Golang SemVer) ---
	installedGo := "1.4.1"
	fixedGo := "1.4.2"
	fmt.Printf("Golang App Test -> %d\n", CheckVulnerability(
		"golang",
		installedGo,
		"1.0.0",
		fixedGo,
	)) // Expected: 1
}

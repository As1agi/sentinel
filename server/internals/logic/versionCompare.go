package logic

import (
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/go-version"
	debver "github.com/knqyf263/go-deb-version"
	rpmver "github.com/knqyf263/go-rpm-version"
)

type Result int

const (
	Safe             Result = 0
	Vulnerable       Result = 1
	InvalidVersion   Result = -1
	DuplicateVersion Result = 2
)

// CheckVulnerability routes the version strings to the correct specification
// parser based on the OS/Ecosystem and checks if it falls in the vulnerable range.
// Returns 1 if vulnerable, 0 if safe.
func CheckVulnerability(ecosystem, installed, introduced, fixed string) (Result, error) {
	// Normalize ecosystem string to ensure reliable matching
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))

	switch {
	//"ubuntu", "debian", "linux mint", "pop"
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
func MatchRpm(installed, introduced, fixed string) (Result, error) {
	// knqyf263/go-rpm-version does not return errors on initialization;
	// it parses valid parts defensive against corruption.
	vInst := rpmver.NewVersion(installed)

	//   Evaluate Lower Bound
	if introduced != "" && introduced != "0" {
		vIntro := rpmver.NewVersion(introduced)
		if vInst.LessThan(vIntro) {
			return Safe, nil
		}
	}

	//  Evaluate Upper Bound
	if fixed != "" {
		vFixed := rpmver.NewVersion(fixed)
		if vInst.LessThan(vFixed) {
			return Vulnerable, nil
		}
		return Safe, nil
	}

	return Vulnerable, nil
}

// MatchDebian checks if a debian package falls within [introduced, fixed)
func MatchDebian(installed, introduced, fixed string) (Result, error) {
	//evaluate installed version
	if installed == "" {
		return InvalidVersion, fmt.Errorf("installed version is empty skipping check ")
	}

	vInst, err := debver.NewVersion(installed)
	if err != nil {
		return InvalidVersion, fmt.Errorf("invalid installed Version , %v", err)
	}

	// Evaluate Lower Bound Introduced
	//if introduced == 0 then as far as we know it is vuln
	if introduced != "" && introduced != "0" {
		vIntro, err := debver.NewVersion(introduced)
		if err != nil {
			return InvalidVersion, fmt.Errorf("invalid Introduced Version , %v", err)
		}
		//safe if installed is less than introduced
		if vInst.LessThan(vIntro) {
			return Safe, nil
		}
	}

	// Evaluate Upper Bound Fixed
	//check if unfixed
	if fixed == "" || fixed == "unfixed" {
		return Vulnerable, nil
	}

	vFixed, err := debver.NewVersion(fixed)
	if err != nil {
		return InvalidVersion, fmt.Errorf("invalid fixed Version , %v", err)
	}
	// If installed version is less than fixed, it hasn't received the patch
	if vInst.LessThan(vFixed) {
		//log.Fatalf("FOUND ONE PACKAGE THAT WAS NOT FIXED BUT A FIXED RANGE VALID VERSION\n")
		return Vulnerable, nil
	} else if vInst.GreaterThan(vFixed) || vInst == vFixed {
		//log.Fatalf("FOUND ONE PACKAGE THAT WAS FIXED AND VALID VERSION\n")
		return Safe, nil
	}
	//installed is greater than fixed so we are safe
	//log.Fatalf("COULD NOT MATCH THE VERSIONS CORRECTLY vInst:%v  , vFixed:%v", vInst, vFixed)
	//return InvalidVersion, nil
	return InvalidVersion, fmt.Errorf("COULD NOT MATCH THE VERSIONS CORRECTLY")
	//return InvalidVersion, fmt.Errorf("all versions were matched correctly but no valid conclusion ")
}

// MatchSemver checks if an application dependency falls within [introduced, fixed)
func MatchSemver(installed, introduced, fixed string) (Result, error) {
	if installed != "" {
		return InvalidVersion, fmt.Errorf("invalid semver installed version not found")
	}
	vInst, err := version.NewVersion(installed)
	if err != nil {
		return InvalidVersion, fmt.Errorf("invalid semver installed version,%v", err)
	}

	//  Evaluate Lower Bound
	if introduced != "" && introduced != "0" {
		vIntro, err := version.NewVersion(introduced)
		if err != nil {
			return InvalidVersion, fmt.Errorf("invalid semver introduced,%v", err)

		}
		if vInst.LessThan(vIntro) {
			return Safe, nil
		}
	}

	//   Evaluate Upper Bound
	if fixed != "" {
		vFixed, err := version.NewVersion(fixed)
		if err != nil {
			return InvalidVersion, fmt.Errorf("invalid fixed version,%v", err)

		}
		if vInst.LessThan(vFixed) {
			return Vulnerable, nil
		}
		return Safe, nil
	}

	return Vulnerable, nil
}

package sbom

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	utils "sentinel/internals"
	"strings"
	"time"
)

// GatherOSPackages returns a software bill of materials containing packages for ANY distro using dpkg
func GatherOSPackages(ctx context.Context) (*SBOM, error) {
	// 1. DYNAMIC CAPABILITY CHECK: Verify if the system actually uses dpkg
	_, err := exec.LookPath("dpkg-query")
	if err != nil {
		return nil, fmt.Errorf("unsupported system: dpkg-query executable not found in PATH")
	}

	distro, codename, err := getDistroMetadata()
	if err != nil {
		return nil, fmt.Errorf("failed tracking system identity: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	kernel, arch, err := getKernelAndArch(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed tracking kernel/hardware identity: %w", err)
	}

	machineID, err := GetMachineId()
	if err != nil {
		return nil, fmt.Errorf("failed tracking kernel/hardware identity: %w", err)
	}

	packages := &SBOM{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		OS:            distro.ID, // Retains the true host OS name (e.g., "kali", "parrot")
		OSVersion:     distro.VersionID,
		OSEcosystem:   distro.Ecosystem,
		KernelVersion: kernel,
		Architecture:  arch,
		Hostname:      hostname,
		Packages:      make([]OSPackage, 0),
		MachineID:     machineID,
	}

	// Isolate the upstream tracking target (e.g., "ubuntu" or "debian") for vulnerability mapping
	//trackingBase := strings.Split(distro.Ecosystem, ":")[0]

	// Hardened: binary:Package shields against multi-arch colon corruption (e.g. libc6:i386)
	formatStr := "${binary:Package}|${Version}|${Architecture}|${Source}\n"
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f", formatStr)

	lineParser := func(line string) (OSPackage, bool) {
		parts := strings.Split(line, "|")
		if len(parts) < 4 {
			return OSPackage{}, false
		}
		name := parts[0]
		version := parts[1]
		pkgArch := strings.TrimSpace(parts[2])
		src := getSourceInfo(parts[3], name, version)

		// Generates valid PURLs matching the security tracking authority feed
		//purl := fmt.Sprintf("pkg:deb/%s/%s@%s?arch=%s", trackingBase, name, version, pkgArch)
		purl := fmt.Sprintf("pkg:deb/%s?arch=%s&distro=%s", name, pkgArch, codename)
		return OSPackage{Name: name, Version: version, PURL: purl, Source: src}, true
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout allocation failed: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed executing dpkg-query: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if pkg, valid := lineParser(line); valid {
			packages.Packages = append(packages.Packages, pkg)
		}
	}

	//Intercept scanning buffer overflows explicitly
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("package list stream processing truncated: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("package extraction terminated abruptly: %w", err)
	}

	return packages, nil
}

func getSourceInfo(src string, packageName string, binVersion string) Src {
	parts := strings.Fields(src)
	srclen := len(parts)
	var source Src
	if srclen < 1 {
		source.SourceVersion = "" //flaw?
		source.SourceName = ""
		return source
	}

	if srclen < 2 {
		source.SourceName = parts[0]
		source.SourceVersion = binVersion
		return source
	} else {
		source.SourceName = parts[0]
		source.SourceVersion = utils.RemoveBraces(parts[1])
		return source
	}
}

// getDistroMetadata reads system identification data and extracts the release codename
func getDistroMetadata() (DistroMetadata, string, error) {
	meta := DistroMetadata{ID: "unknown", VersionID: "unknown", Ecosystem: "unknown"}
	codename := "unknown"

	file, err := os.Open("/etc/os-release")
	if err != nil {
		return meta, "", fmt.Errorf("cannot read /etc/os-release: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	var prettyName string
	var idLike string

	scanner := bufio.NewScanner(file)
	if err = scanner.Err(); err != nil {
		return DistroMetadata{}, "", fmt.Errorf("scanner error:%v", err)
	}
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := parts[0]
		val := strings.Trim(parts[1], "\"\n\r ")

		switch key {
		case "ID":
			meta.ID = strings.ToLower(val)
		case "VERSION_ID":
			meta.VersionID = val
		case "VERSION_CODENAME":
			codename = strings.ToLower(val)
		case "ID_LIKE":
			idLike = strings.ToLower(val)
		case "PRETTY_NAME":
			prettyName = strings.ToLower(val)
		}
	}

	// Ancestry Fallback for derivatives
	trackingID := meta.ID
	if trackingID != "ubuntu" && trackingID != "debian" {
		switch {
		case strings.Contains(idLike, "ubuntu"):
			trackingID = "ubuntu"
		case strings.Contains(idLike, "debian"):
			trackingID = "debian"
		default:
			trackingID = "debian"
		}
	}

	// Standardize version layout
	version := meta.VersionID
	if dots := strings.Split(version, "."); len(dots) >= 2 {
		version = dots[0] + "." + dots[1]
	}
	if version == "" {
		version = "unknown"
	}

	if trackingID == "ubuntu" && (strings.Contains(prettyName, "lts") || trackingID != meta.ID) {
		meta.Ecosystem = "ubuntu:" + version + ":lts"
	} else {
		meta.Ecosystem = trackingID + ":" + version
	}

	return meta, codename, nil
}

// getKernelAndArch retrieves host kernel release and normalizes host CPU architecture names
func getKernelAndArch(ctx context.Context) (string, string, error) {
	kernelCmd := exec.CommandContext(ctx, "uname", "-r")
	kernelBytes, err := kernelCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to execute uname -r: %w", err)
	}
	kernelVersion := strings.TrimSpace(string(kernelBytes))

	archCmd := exec.CommandContext(ctx, "uname", "-m")
	archBytes, err := archCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to execute uname -m: %w", err)
	}
	rawArch := strings.TrimSpace(string(archBytes))

	architecture := rawArch
	switch rawArch {
	case "x86_64":
		architecture = "amd64"
	case "aarch64":
		architecture = "arm64"
	case "i386", "i686":
		architecture = "386"
	}

	return kernelVersion, architecture, nil
}

func GetMachineId() (string, error) {
	machineId, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(machineId)), nil
}

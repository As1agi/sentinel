package dataset

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	_ "runtime"
	_ "runtime/debug"
	"server/internals"
	"server/internals/config"
	"strings"
)

type CleanVulnerability internals.CleanVulnerability

// main function

// CleanOSV transforms the raw OSV.dev CVE data and saves it to the cveSavePath
func CleanOSV() error {
	var (
		fileCount     = 0
		recordCount   = 0
		isFirstRecord = true
	)

	//the directory for the raw OSV data
	sourceDir, err := config.GetRawOsvDir()
	if err != nil {
		return fmt.Errorf("%w\n", err)
	}

	JsonCveSavePath, err := config.GetCleanOsvJsonPath()
	if err != nil {
		return fmt.Errorf("%w\n", err)
	}

	fmt.Println("[*] Starting traversal of OSV data directories...")

	// Open the file immediately for writing
	outFile, err := os.Create(JsonCveSavePath)
	if err != nil {
		return fmt.Errorf("error creating output file : %w\n", err)
	}
	defer outFile.Close()

	// Write the opening JSON array bracket
	if _, err = outFile.WriteString("[\n"); err != nil {
		log.Printf("error:%+v", err)
	}

	//todo split into a re-usable function , PLEASEE!!

	//walk the directory and clean all the json files then write them directly to disk file
	err = filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			log.Printf("Current Directory %v", d.Name())
			return err
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			fileCount++

			fileBytes, err := os.ReadFile(path)
			if err != nil {
				fmt.Printf("[!] Error reading file %s: %v\n", path, err)
				return nil
			}

			var advisory OSVAdvisory
			if err := json.Unmarshal(fileBytes, &advisory); err != nil {
				fmt.Printf("[!] Failed to parse %s: %v\n", path, err)
				return nil
			}
			vulns := cleanVuln(advisory)

			// Stream each vulnerability record directly to disk
			for _, vuln := range vulns {
				b, err := json.Marshal(vuln)
				if err != nil {
					fmt.Printf("[!] Failed to marshal record: %v\n", err)
					continue
				}

				if !isFirstRecord {
					if _, err := outFile.WriteString(",\n"); err != nil {
						log.Fatalf("[-] Write error: %v", err)
					}
				}

				if _, err := outFile.Write(b); err != nil {
					log.Fatalf("[-] Write error: %v", err)
				}

				isFirstRecord = false
				recordCount++
			}
		}
		return nil
	})

	if err != nil {
		err = fmt.Errorf("[-] Critical failure: %v\n", err)
		return err
	}

	// Write the closing JSON array bracket
	_, _ = outFile.WriteString("\n]")

	fmt.Printf("[+] Parsed %d raw files.\n", fileCount)
	fmt.Printf("[==>] Successfully streamed %d flat records straight to: %s\n", recordCount, JsonCveSavePath)
	return nil
}

// cleanVuln  builds and returns a SLICE of vulnerabilities for each distro affected by the vulnerability
func cleanVuln(advisory OSVAdvisory) []CleanVulnerability {

	var records []CleanVulnerability

	for _, affected := range advisory.Affected {
		ecosystem := affected.Package.Ecosystem
		pkgName := affected.Package.Name
		purl := affected.Package.Purl

		for _, r := range affected.Ranges {
			if r.Type != "ECOSYSTEM" {
				continue
			}

			//TODO to reduce param overloading just use a struct bruh dont be too lazy 🤨

			// Pass metadata context down so the helper can construct the records directly
			rangeRecords := parseEvents(r.Events, advisory.ID, advisory.Aliases, advisory.Upstream, ecosystem, pkgName, purl)
			records = append(records, rangeRecords...)
		}
	}

	return records
}

// func to get the real cve ID and remove the prepended UBUNTU-*ETC
func getOsvCveId(advisoryID string) string {
	// Split into a maximum of 2 parts: ["UBUNTU", "CVE-2022-0987"]
	parts := strings.SplitN(advisoryID, "-", 2)

	if len(parts) < 2 {
		fmt.Println("Invalid advisory format")
		return advisoryID
	}

	cveID := parts[1]
	return cveID
}

// parseEvents tracks state across the event loop, appending metrics sequentially
func parseEvents(events []OSVEvent, advisoryID string, cveIDs []string, upstream []string, ecosystem, pkgName string, purl string) []CleanVulnerability {
	var records []CleanVulnerability
	var currentIntroduced string
	totalEvents := len(events)

	for i, event := range events {
		if event.Introduced != "" {
			currentIntroduced = event.Introduced

			// If introduced is the final event in the array, the bug is unpatched
			if i == totalEvents-1 {
				records = append(records, CleanVulnerability{
					AdvisoryID:  getOsvCveId(advisoryID),
					Upstream:    upstream,
					Ecosystem:   strings.ToLower(ecosystem),
					PackageName: pkgName,
					Purl:        purl,
					Introduced:  currentIntroduced,
					Fixed:       "unfixed",
				})
			}
		}

		if event.Fixed != "" {
			records = append(records, CleanVulnerability{
				AdvisoryID:  getOsvCveId(advisoryID),
				Upstream:    upstream,
				Ecosystem:   strings.ToLower(ecosystem),
				PackageName: pkgName,
				Purl:        purl,
				Introduced:  currentIntroduced,
				Fixed:       event.Fixed,
			})
			currentIntroduced = "" // Clear state for back to back ranges
		}
	}
	return records
}

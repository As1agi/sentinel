package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var (
	sourceDir  = "./osv"
	outputFile = "./OSV_Normalized.json"
)

// main function
func main() {
	CleanOSV()
}

func CleanOSV() {
	fileCount := 0
	recordCount := 0
	isFirstRecord := true

	fmt.Println("[*] Starting traversal of OSV data directories...")

	// Open the file immediately for writing
	outFile, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("[-] Failed to create output file: %v", err)
	}
	defer outFile.Close()

	// Write the opening JSON array bracket
	if _, err = outFile.WriteString("[\n"); err != nil {
		log.Printf("error:%+v", err)
	}

	err = filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			log.Printf("Current Directory %v", d.Name())
			return nil
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
		fmt.Printf("[-] Critical failure: %v\n", err)
		os.Exit(1)
	}

	// Write the closing JSON array bracket
	_, _ = outFile.WriteString("\n]")

	fmt.Printf("[+] Parsed %d raw files.\n", fileCount)
	fmt.Printf("[==>] Successfully streamed %d flat records straight to: %s\n", recordCount, outputFile)
}

// todo to make everything more space efficient change the layout so we dont have to have redundant upstream
//
// cleanVuln  builds and returns a SLICE of vulnerabilities to keep loops alive
func cleanVuln(advisory OSVAdvisory) []CleanVulnerability {
	var records []CleanVulnerability

	for _, affected := range advisory.Affected {
		ecosystem := affected.Package.Ecosystem
		pkgName := affected.Package.Name
		purl := affected.Package.Purl
		//affectedVersions := affected.Versions
		//removed to make the data lighter
		//SpecificEcosystemBinaries := affected.EcosystemSpecific

		for _, r := range affected.Ranges {
			if r.Type != "ECOSYSTEM" {
				continue
			}

			// Pass metadata context down so the helper can construct the records directly
			rangeRecords := parseEvents(r.Events, advisory.ID, advisory.Aliases, advisory.Upstream, ecosystem, pkgName, purl) //, affectedVersions) //SpecificEcosystemBinaries)
			records = append(records, rangeRecords...)
		}
	}

	return records
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
					AdvisoryID:  advisoryID,
					CVEIDs:      cveIDs,
					Upstream:    upstream,
					Ecosystem:   strings.ToLower(ecosystem),
					PackageName: pkgName,
					Purl:        purl,
					Introduced:  currentIntroduced,
					//AffectedVersion: versionsAffected,
					//EcosystemSpecific: ecosystemspecific,
					Fixed: "unfixed",
				})
			}
		}

		if event.Fixed != "" {
			records = append(records, CleanVulnerability{
				AdvisoryID:  advisoryID,
				CVEIDs:      cveIDs,
				Upstream:    upstream,
				Ecosystem:   strings.ToLower(ecosystem),
				PackageName: pkgName,
				Purl:        purl,
				Introduced:  currentIntroduced,
				//AffectedVersion: versionsAffected,
				//EcosystemSpecific: ecosystemspecific,
				Fixed: event.Fixed,
			})
			currentIntroduced = "" // Clear state for back-to-back ranges
		}
	}
	return records
}

package dataset

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"server/internals"
	"server/internals/config"
	"strings"
	"sync"
)

const (
	fileProcessWorkersCount = 5
)

// CleanOSV transforms the raw OSV.dev CVE data and saves it to the cveSavePath
type normalizedVuln internals.NormalizedVuln

// OsvNormalize orchestrates the concurrent parsing of OSV records
func OsvNormalize() error {
	sourceDir, err := config.GetRawOsvDir()
	if err != nil {
		return fmt.Errorf("getting source dir: %w", err)
	}

	jsonCveSavePath, err := config.GetCleanOsvJsonPath()
	if err != nil {
		return fmt.Errorf("getting save path: %w", err)
	}

	log.Println("[*] Starting concurrent traversal of OSV data directories...")

	outFile, err := os.Create(jsonCveSavePath)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer func() { _ = outFile.Close() }()

	if _, err = outFile.WriteString("[\n"); err != nil {
		return fmt.Errorf("failed writing opening bracket: %w", err)
	}

	// channels for the pipeline
	normalizedVulnChan := make(chan []normalizedVuln, 100)
	pathsChan := make(chan string, 100)

	var wg sync.WaitGroup

	go startProcessFileWorkers(fileProcessWorkersCount, &wg, pathsChan, normalizedVulnChan)

	// start worker for writing files to the disk
	fileCountChan := make(chan int)
	go streamFilesToDisk(outFile, normalizedVulnChan, fileCountChan)
	// Walk Directory
	err = walkDirWritePathToChan(pathsChan, sourceDir)
	if err != nil {
		log.Printf("[-] Directory walk error: %v\n", err)
	}

	// Close paths to signal workers to stop
	close(pathsChan)
	// Wait for all workers to finish
	wg.Wait()

	// Close results to signal writer to stop
	close(normalizedVulnChan)

	// Wait for writer to finish and get file count
	fileCount := <-fileCountChan

	_, _ = outFile.WriteString("\n]")

	log.Printf("[+] Parsed %d raw files concurrently \n", fileCount)
	return nil
}

func walkDirWritePathToChan(pathsChan chan string, sourceDir string) error {
	err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			pathsChan <- path
		} else if d.IsDir() {
			//I used this for debugging
			log.Printf("current directory %v\n", d.Name())
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error walking directory %+v", err)
	}
	return nil
}

func streamFilesToDisk(outFile *os.File, normalizedVulnChan chan []normalizedVuln, fileCountChan chan int) {
	fileCount := 0
	isFirstRecord := true
	for vulns := range normalizedVulnChan {
		if err := writeVulnsToDisk(outFile, vulns, &isFirstRecord); err != nil {
			fmt.Printf("Disk write error: %v", err)
		}
		fileCount++
	}
	fileCountChan <- fileCount
}

// startFileProcessWorkers starts a group of n workers which process raw OSV data(for now) and output them into a channel
// ... pathsChan is a channel with the paths to the raw json data will be read from
// ...normalizedVulnChan is the channel which the normalized vulns will be streamed to
func startProcessFileWorkers(workersCount int, wg *sync.WaitGroup, pathsChan chan string, normalizedVulnChan chan []normalizedVuln) {
	for i := 0; i < workersCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathsChan {
				vulns := processFile(path)
				if len(vulns) > 0 {
					normalizedVulnChan <- vulns
				}
			}
		}()
	}
}

// processFile normalizes json entry
func processFile(path string) []normalizedVuln {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[!] Error reading file %s: %v\n", path, err)
		return nil
	}

	var advisory OSVAdvisory
	if err := json.Unmarshal(fileBytes, &advisory); err != nil {
		log.Printf("[!] Failed to parse %s: %v\n", path, err)
		return nil
	}

	return normalize(advisory)
}

// writeVulnToDisk writes a single vuln entry to the disk
func writeVulnsToDisk(outFile *os.File, vulns []normalizedVuln, isFirstRecord *bool) error {
	for _, vuln := range vulns {
		b, err := json.Marshal(vuln)
		if err != nil {
			fmt.Printf("[!] Failed to marshal record: %v\n", err)
			continue
		}

		if !*isFirstRecord {
			if _, err := outFile.WriteString(",\n"); err != nil {
				return fmt.Errorf("error writting to the outfile %w", err)
			}
		}

		if _, err := outFile.Write(b); err != nil {
			return fmt.Errorf("error writting to the outfile %w", err)
		}

		*isFirstRecord = false
		//recordCount++
	}
	return nil
}

// cleanVuln  builds and returns a SLICE of vulnerabilities for each distro affected by the vulnerability
func normalize(advisory OSVAdvisory) []normalizedVuln {

	var records []normalizedVuln
	n := &normalizedVuln{}

	//this loops through every affected ecosystem for one vulnerability etc. CVE-XXXX-XXX
	//for ubuntu 24.04 LTS and 22.04 LTS
	//then builds a  flat record for that ecosystem
	for _, affected := range advisory.Affected {

		n.AdvisoryID = getOsvCveId(advisory.ID)
		n.Upstream = advisory.Upstream
		n.Ecosystem = affected.Package.Ecosystem
		n.PackageName = affected.Package.Name
		n.Purl = affected.Package.Purl

		//loop through the affected ranges
		for _, r := range affected.Ranges {
			if r.Type != "ECOSYSTEM" {
				continue
			}

			rangeRecords := parseEvents(r.Events, n)
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

// parseEvents parses the introduced and fixed events for the CVE record
func parseEvents(events []OSVEvent, n *normalizedVuln) []normalizedVuln {
	var records []normalizedVuln
	var currentIntroduced string
	totalEvents := len(events)

	// this is in the case that we have many introduced fixed events which is very unlikely
	//may have to delete this loop
	for i, event := range events {
		if event.Introduced != "" {
			currentIntroduced = event.Introduced

			// If introduced is the final event in the array, the bug is unpatched
			if i == totalEvents-1 {
				record := *n
				record.Introduced = currentIntroduced
				record.Fixed = "unfixed"
				records = append(records, record)
			}
		}

		if event.Fixed != "" {
			record := *n
			record.Introduced = currentIntroduced
			record.Fixed = event.Fixed
			records = append(records, record)
			currentIntroduced = "" // Clear state for back to back ranges
		}
	}
	return records
}

package datasets

import (
	"fmt"
	"log"
	"os"
	"server/internals/config"
	"strings"
	"sync"
)

// OsvNormalize orchestrates the concurrent parsing of OSV records
func OsvNormalize() error {
	//we get the base directory with the raw CVE files
	sourceDir, err := config.GetDatasetRawCveDir("osv")
	if err != nil {
		return fmt.Errorf("getting source dir: %w", err)
	}

	jsonCveSavePath, err := config.GetNormalizedCveJsonPath("osv")
	if err != nil {
		return fmt.Errorf("getting save path: %w", err)
	}

	outFile, err := os.Create(jsonCveSavePath)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer func() { _ = outFile.Close() }()
	log.Println("[*] Starting concurrent traversal of OSV data directories...")

	if _, err = outFile.WriteString("[\n"); err != nil {
		return fmt.Errorf("failed writing opening bracket: %w", err)
	}

	// channels for the pipeline
	normalizedVulnChan := make(chan []normalizedVuln, 100)
	pathsChan := make(chan string, 100)

	var wg sync.WaitGroup

	go startFileProcessWorkers(fileProcessWorkersCount, &wg, pathsChan, normalizedVulnChan)

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

// cleanVuln  builds and returns a SLICE of vulnerabilities for each distro affected by a single vulnerability
func osvAdvisoryNormalize(advisory *OsvAdvisory) []normalizedVuln {

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

// startFileProcessWorkers starts a group of n workers which process raw OSV data(for now) and output them into a channel
// ... pathsChan is a channel with the paths to the raw json data will be read from
// ...normalizedVulnChan is the channel which the normalized vulns will be streamed to
func startFileProcessWorkers(workersCount int, wg *sync.WaitGroup, pathsChan chan string, normalizedVulnChan chan []normalizedVuln) {
	for i := 0; i < workersCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathsChan {
				vulns := processFile[OsvAdvisory](path, osvAdvisoryNormalize)
				if len(vulns) > 0 {
					normalizedVulnChan <- vulns
				}
			}
		}()
	}
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
func parseEvents(events []OsvEvent, n *normalizedVuln) []normalizedVuln {
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

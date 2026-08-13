package datasets

import (
	"fmt"
	"log"
	"os"
	"server/internals/config"
	"sync"
)

func init() {
	if err := config.InitDirectories(); err != nil {
		log.Fatal(err)
	}

}

// OsvNormalize orchestrates the concurrent parsing of OSV records
func OsvNormalize(sourceDir string, normalizedCveSavePath string) error {
	outFile, err := os.Create(normalizedCveSavePath)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer func() { _ = outFile.Close() }()

	log.Println("[*] Starting concurrent traversal of OSV data directories...")

	p := fileProcessWorkersParams[OsvAdvisory]{
		workersCount:       fileProcessWorkersCount,
		waitGroup:          new(sync.WaitGroup),
		pathsChan:          make(chan string, 100),
		normalizedVulnChan: make(chan []normalizedVuln, 100),
		normalizeFunc:      osvAdvisoryNormalize,
	}
	go startFileProcessWorkers(p)

	fileCountChan := make(chan int)
	go streamFilesToDisk(outFile, p.normalizedVulnChan, fileCountChan)

	err = walkDirWritePathToChan(p.pathsChan, sourceDir)
	if err != nil {
		log.Printf("[-] Directory walk error: %v\n", err)
	}

	close(p.pathsChan)

	p.waitGroup.Wait()

	close(p.normalizedVulnChan)

	fileCount := <-fileCountChan

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

		n.AdvisoryID = ExtractCVE(advisory.ID)
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

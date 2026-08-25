package datasets

import (
	"encoding/json"
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

	log.Println("[*] Starting traversal of OSV data directories for normalization...")

	p := &cveNormalizeWorkersParams[OsvAdvisory]{
		workersCount:       fileProcessWorkersCount,
		waitGroup:          new(sync.WaitGroup),
		pathsChan:          make(chan string, 100),
		rawCveChan:         make(chan OsvAdvisory, 100),
		normalizedVulnChan: make(chan []normalizedVuln, 100),
		normalizeFunc:      osvAdvisoryNormalize,
	}

	n := &cveExtractWorkersParamas[OsvAdvisory]{
		workersCount: fileProcessWorkersCount,
		pathsChan:    p.pathsChan,
		waitGroup:    new(sync.WaitGroup),
		rawCveChan:   p.rawCveChan,
		extractFunc:  osvExtractCveToChan,
	}

	fileCountChan := make(chan int)

	go cveNormalizeWorkers(p)
	go cveExtractWorkers(n)
	//added this to the wg as a temporary fix to a concurrency issue where the file is closed before we
	//finish writing into it
	done := make(chan struct{})
	go streamFilesToDisk(outFile, p.normalizedVulnChan, done)

	if err := walkDirWritePathToChan(p.pathsChan, sourceDir); err != nil {
		close(p.pathsChan)
		p.waitGroup.Wait()
		return fmt.Errorf("error while walking path for NVD:%v", err)
	}

	close(p.pathsChan)
	p.waitGroup.Wait()

	close(fileCountChan)
	//log.Printf("[+] Parsed %d raw files concurrently \n", fileCount)
	<-done
	return nil
}

// nvdDecodeCveFile extracts the CVEs from an NVD file and streams the CVEs to the recordChan passed in the
// nvdExtractCveWorkersParams
func osvExtractCveToChan(rawCveChan chan OsvAdvisory, filePath string) error {
	cve, err := osvExtractCve(filePath)
	if err != nil {
		return fmt.Errorf("error extracting CVE from %v \n %v", filePath, err)
	}

	rawCveChan <- cve
	return nil
}

func osvExtractCve(filePath string) (OsvAdvisory, error) {
	var cve OsvAdvisory
	//the OSV CVE data contain a single CVE entry in each json file so we can unmarshal directly
	file, err := os.ReadFile(filePath)
	if err != nil {
		return cve, err
	}

	if err = json.Unmarshal(file, &cve); err != nil {
		return cve, err
	}

	return cve, nil
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

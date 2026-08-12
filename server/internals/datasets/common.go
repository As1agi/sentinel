package datasets

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"server/internals"
	"strings"
)

const (
	fileProcessWorkersCount = 5
)

// CleanOSV transforms the raw OSV.dev CVE data and saves it to the cveSavePath
type normalizedVuln internals.NormalizedVuln

var cveRegex = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

func ExtractCVE(rawID string) string {
	if match := cveRegex.FindString(rawID); match != "" {
		return match
	}
	return rawID
}

func walkDirWritePathToChan(pathsChan chan string, sourceDir string) error {
	err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() != "normalized.json" && strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
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

// processFile normalizes json entry
func processFile[T any](path string, normalize func(*T) []normalizedVuln) []normalizedVuln {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[!] Error reading file %s: %v\n", path, err)
		return nil
	}

	var record T
	if err := json.Unmarshal(fileBytes, &record); err != nil {
		log.Printf("[!] Failed to parse %s: %v\n", path, err)
		return nil
	}

	//we call the normalize func for the engine here
	return normalize(&record)
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

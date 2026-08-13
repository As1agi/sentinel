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
	"sync"
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

// walkDirWritePathToChan moves through directories and writes the paths to the pathsChan
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

// streamFilesToDisks writes normalized CVE files from the normalizedVulnChan to the outFile
func streamFilesToDisk(outFile *os.File, normalizedVulnChan chan []normalizedVuln, fileCountChan chan int) {
	fileCount := 0
	for vulns := range normalizedVulnChan {
		if err := writeVulnsToDisk(outFile, vulns); err != nil {
			fmt.Printf("Disk write error: %v", err)
		}
		fileCount++
	}
	fileCountChan <- fileCount
}

// fileProcessWorkersParams holds the parameters for the startFileProcessWorkers func
type fileProcessWorkersParams[T any] struct {
	workersCount       int
	waitGroup          *sync.WaitGroup
	pathsChan          chan string
	normalizedVulnChan chan []normalizedVuln
	normalizeFunc      func(*T) []normalizedVuln
}

// startFileProcessWorkers initiates the unmarshalling and normalization of raw CVE vuln files and streams the normalized vulns
// into the normalizedVuln Channel
// takes the normalization function and the struct as an argument
func startFileProcessWorkers[T any](params fileProcessWorkersParams[T]) {
	for i := 0; i < params.workersCount; i++ {
		params.waitGroup.Add(1)
		go func() {
			defer params.waitGroup.Done()
			for path := range params.pathsChan {
				vulns := processFile[T](path, params.normalizeFunc)
				if len(vulns) > 0 {
					params.normalizedVulnChan <- vulns
				}
			}
		}()
	}
}

// processFile normalizes json CVE entries of type T
func processFile[T any](path string, normalizeFunc func(*T) []normalizedVuln) []normalizedVuln {
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

	return normalizeFunc(&record)
}

// writeVulnToDisk writes a single vuln entry to the disk
func writeVulnsToDisk(outFile *os.File, vulns []normalizedVuln) error {
	for _, vuln := range vulns {
		b, err := json.Marshal(vuln)
		if err != nil {
			fmt.Printf("[!] Failed to marshal record: %v\n", err)
			continue
		}

		b = append(b, '\n')
		if _, err := outFile.Write(b); err != nil {
			return fmt.Errorf("error writting to the outfile %w", err)
		}

	}
	return nil
}

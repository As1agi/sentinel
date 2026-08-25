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
			//log.Printf("wrote %v to paths chan", d.Name())
		} else if d.IsDir() {
			//I use this for debugging
			log.Printf("current directory %v\n", d.Name())
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error walking directory %+v", err)
	}
	//log.Printf("[+] Done walking path")
	return nil
}

//todo implement separation of concerns

// streamFilesToDisks writes normalized CVE files from the normalizedVulnChan to the outFile
func streamFilesToDisk(outFile *os.File, normalizedVulnChan chan []normalizedVuln, done chan struct{}) {
	defer close(done)
	for vulns := range normalizedVulnChan {
		if err := writeVulnsToDisk(outFile, vulns); err != nil {
			fmt.Printf("Disk write error: %v", err)
		}
	}
}

// ====================
//todo define better constrains for the extract fun especially the parameters for the extract func

type cveExtractWorkersParamas[T any] struct {
	workersCount int
	waitGroup    *sync.WaitGroup
	pathsChan    chan string
	rawCveChan   chan T
	//functiontion to extract the CVE from an entry
	extractFunc func(chan T, string) error
}

// todo separation of concerns , do not pass chanels as
func cveExtractWorkers[T any](p *cveExtractWorkersParamas[T]) {
	var filecount = 0
	for i := 0; i < p.workersCount; i++ {
		p.waitGroup.Add(1)
		go func() {
			defer p.waitGroup.Done()
			for path := range p.pathsChan {
				filecount++
				_ = p.extractFunc(p.rawCveChan, path)
			}
		}()
	}
	p.waitGroup.Wait()
	close(p.rawCveChan)
}

// cveNormalizeWorkersParams holds the parameters for the startFileProcessWorkers func
// where T is the struct for the raw data
type cveNormalizeWorkersParams[T any] struct {
	workersCount       int
	waitGroup          *sync.WaitGroup
	pathsChan          chan string
	rawCveChan         chan T
	normalizedVulnChan chan []normalizedVuln
	normalizeFunc      func(*T) []normalizedVuln
}

// startFileProcessWorkers initiates the normalization of raw CVE vulns from the recordChan and streams them
// into the normalizedVuln Channel.
//
// T is the struct for the raw data.
func cveNormalizeWorkers[T any](params *cveNormalizeWorkersParams[T]) {
	for i := 0; i < params.workersCount; i++ {
		params.waitGroup.Add(1)
		go func() {
			defer params.waitGroup.Done()
			for record := range params.rawCveChan {
				vulns := normalizeCve[T](record, params.normalizeFunc)
				if len(vulns) > 0 {
					params.normalizedVulnChan <- vulns
				}
			}
		}()
	}
	params.waitGroup.Wait()
	close(params.normalizedVulnChan)
}

// processFile normalizes json CVE entries of type T using a normalize function passed
func normalizeCve[T any](cve T, normalizeFunc func(*T) []normalizedVuln) []normalizedVuln {
	return normalizeFunc(&cve)
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

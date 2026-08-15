package datasets

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

func NvdNormalize(sourceDir string, normalizedJsonSavePath string) error {
	log.Printf("began NVD normalization")
	outfile, err := os.Create(normalizedJsonSavePath)
	if err != nil {
		return fmt.Errorf("\terror opening file at path %v \n\t %v", normalizedJsonSavePath, err)
	}
	p := &cveNormalizeWorkersParams[NvdAdvisory]{
		workersCount:       fileProcessWorkersCount,
		waitGroup:          new(sync.WaitGroup),
		pathsChan:          make(chan string, 100),
		rawCveChan:         make(chan NvdAdvisory, 200),
		normalizedVulnChan: make(chan []normalizedVuln, 100),
		normalizeFunc:      nvdNormalizeAdvisory,
	}

	n := &extractCveWorkersParams[NvdAdvisory]{
		workersCount: fileProcessWorkersCount,
		pathsChannel: &p.pathsChan,
		waitGroup:    new(sync.WaitGroup),
		rawCveChan:   p.rawCveChan,
	}
	done := make(chan struct{})
	go startCveNormalizeWorkers(p)
	go nvdExtractCveWorkers(n)
	go streamFilesToDisk(outfile, p.normalizedVulnChan, done)
	if err := walkDirWritePathToChan(p.pathsChan, sourceDir); err != nil {
		close(p.pathsChan)
		p.waitGroup.Wait()
		n.waitGroup.Wait()
		return fmt.Errorf("error while walking path for NVD:%v", err)
	}

	//close paths chan first
	close(p.pathsChan)

	p.waitGroup.Wait()
	n.waitGroup.Wait()

	<-done
	//log.Printf("successfully normalized all NVD vulns filecount : %v", fileCount)
	return nil
}

// nvdNormalizeAdvisory normalizes a single NDV advisory]
func nvdNormalizeAdvisory(advisory *NvdAdvisory) []normalizedVuln {
	//we use the NVD for enrichment so there is not need to parse everything just get some extra info and we are done'
	//log.Printf("[-] advisory %v", advisory.ID)
	n := normalizedVuln{}

	//we extract info such as the description and CVSS metrics for enrichment of the OSV data
	n.AdvisoryID = advisory.ID
	n.CvssMetricV2 = advisory.Metrics.CvssMetricV2
	n.CvssMetricV3 = advisory.Metrics.CvssMetricV30
	n.Description = advisory.Descriptions

	//log.Printf("file %+v", n)
	return []normalizedVuln{n}
}

// starts a number of go-routines that actively extract the CVE data from NVD files and streams them to the
// record chan provided in the nvdExtractCveWorkersParams
func nvdExtractCveWorkers(n *extractCveWorkersParams[NvdAdvisory]) {
	var filecount = 0
	for i := 0; i < n.workersCount; i++ {
		n.waitGroup.Add(1)
		go func() {
			defer n.waitGroup.Done()
			for path := range *n.pathsChannel {
				filecount++
				_ = nvdExtractCve(n, path)
			}
		}()
	}
	n.waitGroup.Wait()
	close(n.rawCveChan)
}

// nvdDecodeCveFile extracts the CVEs from an NVD file and streams the CVEs to the recordChan passed in the
// nvdExtractCveWorkersParams
func nvdExtractCve(n *extractCveWorkersParams[NvdAdvisory], filePath string) error {
	var cveWrapper struct {
		Cve NvdAdvisory `json:"cve"`
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("\terror opening file at path %v \n\t err:%v", filePath, err)
	}

	decoder := json.NewDecoder(file)
	if err = decodeToToken(decoder, "vulnerabilities"); err != nil {
		return err
	}

	t, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); !ok || delim != '[' {
		return fmt.Errorf("expected '[' after vulnerabilities key, got %v", t)
	}

	//we now decode and marshal the CVEs and add em to the channel
	for decoder.More() {
		err = decoder.Decode(&cveWrapper)
		if err != nil {
			log.Println(err)
			continue
		}
		//log.Printf("cve : %+v", cveWrapper.Cve)
		n.rawCveChan <- cveWrapper.Cve
	}
	return nil
}

func decodeToToken(decoder *json.Decoder, token string) error {
	for {
		t, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("%vnot found in JSON", token)
			}
			return err
		}

		// Check if the token is a string and matches our target key
		if key, ok := t.(string); ok && key == token {
			break
		}
	}
	return nil
}

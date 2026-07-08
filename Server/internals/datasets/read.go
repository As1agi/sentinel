package dataset

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"server/internals"
)

func read() {

	file, err := os.Open("OSV_Normalized.json")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)

	_, err = decoder.Token()
	if err != nil {
		log.Fatalf("Failed to read opening bracket: %v", err)
	}

	count := 0

	// 4. decoder.More() checks if there is another object in the array
	for decoder.More() {
		var cve internals.CleanVulnerability

		// 5. Decode EXACTLY one object from the stream into our struct
		err := decoder.Decode(&cve)
		if err != nil {
			log.Fatalf("Failed to decode CVE object: %v", err)
		}

		count++
		if count%10000 == 0 {
			fmt.Printf("Processed %d items... Currently at: %s\n", count, cve.AdvisoryID)
		}

	}

	// 7Read the closing bracket ']'
	_, err = decoder.Token()
	if err != nil {
		log.Fatalf("Failed to read closing bracket: %v", err)
	}

	fmt.Printf("Successfully processed all %d CVEs without crashing your RAM!\n", count)
}

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

func read() {
	// 1. Open the file, but DO NOT read the whole thing into memory
	file, err := os.Open("OSV_Normalized.json")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	// 2. Create a decoder attached to the file stream
	decoder := json.NewDecoder(file)

	// 3. Read the opening bracket '[' of the JSON array
	// This moves the decoder past the first token so we can read the objects inside.
	_, err = decoder.Token()
	if err != nil {
		log.Fatalf("Failed to read opening bracket: %v", err)
	}

	count := 0

	// 4. decoder.More() checks if there is another object in the array
	for decoder.More() {
		var cve CleanVulnerability

		// 5. Decode EXACTLY one object from the stream into our struct
		err := decoder.Decode(&cve)
		if err != nil {
			log.Fatalf("Failed to decode CVE object: %v", err)
		}

		// 6. Process the single item (Save to DB here)
		// For now, we will just print every 10,000th item so you can see it working fast.
		count++
		if count%10000 == 0 {
			fmt.Printf("Processed %d items... Currently at: %s\n", count, cve.AdvisoryID)
		}

		// -> Here is where you would call your SQLite insert function
		// err = insertCVEIntoDB(db, cve)
	}

	// 7. Read the closing bracket ']'
	_, err = decoder.Token()
	if err != nil {
		log.Fatalf("Failed to read closing bracket: %v", err)
	}

	fmt.Printf("Successfully processed all %d CVEs without crashing your RAM!\n", count)
}

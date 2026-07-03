package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"server/internals"

	_ "github.com/mattn/go-sqlite3"
)

const (
	BatchSize = 5000
)

// ReadCVEIntoDataBase reads in data from a json file which has an array of CleanVulnerability
// into a database with the correct schema
func ReadCVEIntoDataBase(db *sql.DB, CVEDataPath string) {
	file, err := os.Open(CVEDataPath)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	_, err = decoder.Token() // Consume opening '['
	if err != nil {
		log.Fatalf("Failed to read opening bracket: %v", err)
	}

	count := 0

	// Initialize the very first transaction chunk
	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("Failed to start initial transaction: %v", err)
	}
	// Deferred rollback protects against partial corruptions if the stream panics mid-execution
	defer func() { _ = tx.Rollback() }()

	// Prepare statements *once* on the active transaction lifecycle
	cveStmt, upstreamStmt, err := prepareBatchStatements(tx)
	if err != nil {
		log.Fatalf("Failed to prepare transaction statements: %v", err)
	}

	for decoder.More() {
		var cve internals.CleanVulnerability
		if err := decoder.Decode(&cve); err != nil {
			log.Fatalf("Failed to decode CVE object: %v", err)
		}

		// Write to memory buffers via the prepared statements
		if err := executeInsert(cveStmt, upstreamStmt, cve); err != nil {
			log.Fatalf("Write execution error: %v", err)
		}

		count++

		// Batch size reached: Flush chunk to disk and rotate the transaction context
		if count%BatchSize == 0 {
			// Prepared statements must be closed before committing their parent transaction
			cveStmt.Close()
			upstreamStmt.Close()

			// commit everything in this chunk atomically to disk
			if err := tx.Commit(); err != nil {
				log.Fatalf("Failed to commit batch to disk: %v", err)
			}
			log.Printf("Successfully flushed %d records to the database...", count)

			// Re-initialize for the next chunk
			tx, err = db.Begin()
			if err != nil {
				log.Fatalf("Failed to cycle next transaction: %v", err)
			}

			//Re-prepare statements tied to the brand new transaction frame
			cveStmt, upstreamStmt, err = prepareBatchStatements(tx)
			if err != nil {
				log.Fatalf("Failed to refresh transaction statements: %v", err)
			}
		}
	}

	// Clean up the final lingering partial batch
	cveStmt.Close()
	upstreamStmt.Close()
	if err := tx.Commit(); err != nil {
		log.Fatalf("Failed to process final database flush: %v", err)
	}

	_, err = decoder.Token() // Consume closing ']'
	if err != nil {
		log.Fatalf("Failed to read closing bracket: %v", err)
	}

	fmt.Printf("Engine complete. Successfully indexed all %d CVE components safely!\n", count)
}
func executeInsert(cveStmt *sql.Stmt, upstreamStmt *sql.Stmt, cve internals.CleanVulnerability) error {
	_, err := cveStmt.Exec(cve.AdvisoryID, cve.Ecosystem, cve.PackageName, cve.Purl, cve.Introduced, cve.Fixed)
	if err != nil {
		return fmt.Errorf("cve records execution failure: %w", err)
	}

	for _, upstreamID := range cve.Upstream {
		_, err := upstreamStmt.Exec(cve.AdvisoryID, upstreamID)
		if err != nil {
			return fmt.Errorf("upstream linking mapping execution failure: %w", err)
		}
	}

	return nil
}

// Micro-function: Compiles statements on top of the assigned transaction frame
func prepareBatchStatements(tx *sql.Tx) (*sql.Stmt, *sql.Stmt, error) {
	cveQuery := `
    INSERT INTO cve (advisory_id, ecosystem, package_name, purl, introduced, fixed) 
    VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING;`

	upstreamQuery := `
    INSERT INTO upstream (advisory_id, upstream_id) 
    VALUES (?, ?) ON CONFLICT DO NOTHING;`

	cveStmt, err := tx.Prepare(cveQuery)
	if err != nil {
		return nil, nil, err
	}

	upstreamStmt, err := tx.Prepare(upstreamQuery)
	if err != nil {
		cveStmt.Close()
		return nil, nil, err
	}

	return cveStmt, upstreamStmt, nil
}

//todo we need to set queries to retrieve the info linked to the machineID
// we use the SBOM id to get the package names
//	so for all users we get the SBOMs then we get the use the ID of each SBOM to get the packages
//  then once we find the vuln packages we sort of like send them in batches.. per SBOM, so we scan one SBOM
//  then we send the vulns and stuff if they exist

//todo break the function into micro functions for clean shits

// InsertSBOm handles the 3-tier hierarchy registration and sync
func InsertSBOM(db *sql.DB, s internals.SBOM) error {
	// Start the transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	//Register or Retrieve the User (Hostname)

	var userID int64
	upsertUserQuery := `
		INSERT INTO users (hostname)
		VALUES (?)
		ON CONFLICT(hostname) DO UPDATE SET 
			hostname = excluded.hostname 
		RETURNING id;`

	err = tx.QueryRow(upsertUserQuery, s.Hostname).Scan(&userID)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to process user/hostname %s: %w", s.Hostname, err)
	}

	// STEP 2: Register or Update the Machine (SBOM)
	var sbomID int64
	upsertSBOMQuery := `
		INSERT INTO sboms (user_id, machine_id, timestamp, os, os_version, os_ecosystem, kernel_version, architecture)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id,machine_id) DO UPDATE SET
			timestamp = excluded.timestamp,
			os_version = excluded.os_version,
			kernel_version = excluded.kernel_version
		RETURNING id;`

	err = tx.QueryRow(upsertSBOMQuery,
		userID, s.MachineID, s.Timestamp, s.OS, s.OSVersion, s.OSEcosystem, s.KernelVersion, s.Architecture,
	).Scan(&sbomID)

	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to process machine %s: %w", s.MachineID, err)
	}

	//Wipe Old State

	_, err = tx.Exec(`DELETE FROM packages WHERE sbom_id = ?`, sbomID)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to clear old packages: %w", err)
	}

	//   Insert the New Packages Array
	insertPackageQuery := `
		INSERT INTO packages (sbom_id,name, version, purl, source_name, source_version)
		VALUES (?,?,?,?,?,?);`

	stmt, err := tx.Prepare(insertPackageQuery)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to prepare package statement: %w", err)
	}
	defer stmt.Close()

	for _, pkg := range s.Packages {
		_, err := stmt.Exec(
			sbomID,
			pkg.Name,
			pkg.Version,
			pkg.PURL,
			pkg.Source.SourceName,
			pkg.Source.SourceVersion,
		)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to insert package %s: %w", pkg.Name, err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	log.Println("DONE INSERTING DATA")
	return nil
}

// InsertCVE inserts a single CVE advisory into a database
//func InsertCVE(db *sql.DB, insertStmt *sql.Stmt, cve internals.CleanVulnerability) error {
//
//	_, err := insertStmt.Exec(cve.AdvisoryID, cve.Ecosystem, cve.PackageName, cve.Purl, cve.Introduced, cve.Fixed)
//	if err != nil {
//		return fmt.Errorf("error inserting %v\n , errer :%v\n", cve.AdvisoryID, err)
//	}
//
//	err = InsertUpstreamID(db, cve.Upstream, cve.AdvisoryID)
//	if err != nil {
//		return err
//	}
//
//	return nil
//
//}
//
//func InsertUpstreamID(db *sql.DB, upstream []string, advisoryID string) error {
//	if len(upstream) <= 0 {
//		return nil
//	}
//
//	query := `
//	INSERT INTO upstream(advisory_id,upstream_id) VALUES(?,?) ON CONFLICT DO NOTHING
//`
//	stmt, err := db.Prepare(query)
//	if err != nil {
//		return fmt.Errorf("error preparing DB statement: %v\n", err)
//	}
//
//	//beging inserting the upstream ID
//	for _, upstreamId := range upstream {
//		_, err = stmt.Exec(advisoryID, upstreamId)
//		if err != nil {
//			log.Printf("error inserting upstream ID:%v\n", err)
//		}
//	}
//	return nil
//}

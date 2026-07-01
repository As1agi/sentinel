package database

import (
	"database/sql"
	"fmt"
	"log"
	"server/internals"

	_ "github.com/mattn/go-sqlite3"
)

const (
	dbPath = "./database"
)

func OpenDB() *sql.DB {
	log.Printf("Opening DB")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Enable Foreign Keys (SQLite disables them by default for backwards compatibility)

	return db
}

//todo we need to set queries to retrieve the info linked to the machineID
// we use the SBOM id to get the package names
//	so for all users we get the SBOMs then we get the use the ID of each SBOM to get the packages
//  then once we find the vuln packages we sort of like send them in batches.. per SBOM, so we scan one SBOM
//  then we send the vulns and stuff if they exist

//todo break the function into micro functions for clean shits

// ProcessSBOM handles the 3-tier hierarchy registration and sync
func InsertSBOM(s internals.SBOM) error {
	db := OpenDB()
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

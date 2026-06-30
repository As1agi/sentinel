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

// initSchema creates the necessary tables if they don't exist
func InitSchema() {
	db := OpenDB()
	//enable pragma foreign key
	_, err := db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec(CreateSBOMDataTable)
	if err != nil {
		log.Fatalf("Failed to create sboms table: %v", err)
	}

	_, err = db.Exec(CreatePackagesTable)
	if err != nil {
		log.Fatalf("Failed to create packages table: %v", err)
	}

	_, err = db.Exec(CreateUserTable)
	if err != nil {
		log.Fatalf("Failed to create packages table: %v", err)
	}
}

// / ProcessSBOM handles the 3-tier hierarchy registration and sync
func InsertSBOM(s internals.SBOM) error {
	db := OpenDB()
	// Start the transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// ---------------------------------------------------------
	// STEP 1: Register or Retrieve the User (Hostname)
	// ---------------------------------------------------------
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

	// ---------------------------------------------------------
	// STEP 2: Register or Update the Machine (SBOM)
	// ---------------------------------------------------------
	var sbomID int64
	upsertSBOMQuery := `
		INSERT INTO sboms (user_id, machine_id, timestamp, os, os_version, os_ecosystem, kernel_version, architecture)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(machine_id) DO UPDATE SET
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

	// ---------------------------------------------------------
	// STEP 3: Wipe Old State (Prevent "Ghost Packages")
	// ---------------------------------------------------------
	// We want an exact mirror of the current machine state.
	// Deleting all existing packages for this sbom_id ensures that
	// software uninstalled since the last payload is actually removed from the DB.

	_, err = tx.Exec(`DELETE FROM packages WHERE sbom_id = ?`, sbomID)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to clear old packages: %w", err)
	}

	// ---------------------------------------------------------
	// STEP 4: Insert the New Packages Array
	// ---------------------------------------------------------
	insertPackageQuery := `
		INSERT INTO packages (sbom_id, name, version, purl, source_name, source_version)
		VALUES (?, ?, ?, ?, ?, ?);`

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

	// ---------------------------------------------------------
	// COMMIT
	// ---------------------------------------------------------
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	log.Println("DONE INSERTING DATA")
	return nil
}

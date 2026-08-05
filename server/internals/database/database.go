package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"server/internals"
	"server/internals/logic"

	_ "github.com/mattn/go-sqlite3"
)

const (
	BatchSize = 5000
)

// ReadCveJsonIntoDataBase reads in data from a json file which has an array of CleanVulnerability
// into a database with the correct schema

const (
	cveInsertQuery = `
    INSERT INTO cve (advisory_id, ecosystem, package_name, purl, introduced, fixed)
    VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING;`

	upstreamInsertQuery = `
    INSERT INTO upstream (advisory_id, upstream_id)
    VALUES (?, ?) ON CONFLICT DO NOTHING;`
)

// ReadCveJsonIntoDataBase manages file resources, compiles statement plans on the DB handle,
// and delegates ingestion streaming into thB
func ReadCveJsonIntoDataBase(db *sql.DB, cveJsonPath string) error {
	file, err := os.Open(cveJsonPath)
	if err != nil {
		return fmt.Errorf("failed to open CVE dataset %s: %w", cveJsonPath, err)
	}
	defer func() {
		_ = file.Close()
	}()

	cveDbStmt, err := db.Prepare(cveInsertQuery)
	if err != nil {
		return fmt.Errorf("failed to prepare cve query: %w", err)
	}
	defer func() { _ = cveDbStmt.Close() }()

	upstreamDbStmt, err := db.Prepare(upstreamInsertQuery)
	if err != nil {
		return fmt.Errorf("failed to prepare upstream query: %w", err)
	}
	defer func() { _ = upstreamDbStmt.Close() }()

	log.Println("[*] Streaming CVEs into the database...")

	count, err := streamAndCommitCves(db, file, cveDbStmt, upstreamDbStmt)
	if err != nil {
		return err
	}

	log.Printf("[+] Successfully indexed all %d CVE components safely!\n", count)
	return nil
}

// streamAndCommitCves streams JSON objects and rotates transaction chunks.
func streamAndCommitCves(
	db *sql.DB,
	file *os.File,
	cveDbStmt *sql.Stmt,
	upstreamDbStmt *sql.Stmt,
) (int, error) {
	decoder := json.NewDecoder(file)
	if _, err := decoder.Token(); err != nil { // Consume opening '['
		return 0, fmt.Errorf("failed to read opening bracket: %w", err)
	}

	// Start initial transaction
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("failed to begin initial transaction: %w", err)
	}

	// Bind global statements to current transaction
	cveTxStmt := tx.Stmt(cveDbStmt)
	upstreamTxStmt := tx.Stmt(upstreamDbStmt)

	count := 0

	for decoder.More() {
		var cve internals.NormalizedVuln
		if err := decoder.Decode(&cve); err != nil {
			_ = tx.Rollback()
			return count, fmt.Errorf("failed to decode CVE object at index %d: %w", count, err)
		}

		if err := InsertCveAndUpstream(cveTxStmt, upstreamTxStmt, cve); err != nil {
			_ = tx.Rollback()
			return count, fmt.Errorf("write execution error at index %d: %w", count, err)
		}

		count++

		if count%BatchSize == 0 {
			if err := tx.Commit(); err != nil {
				return count, fmt.Errorf("failed to commit batch at index %d: %w", count, err)
			}

			tx, err = db.Begin()
			if err != nil {
				return count, fmt.Errorf("failed to cycle transaction at index %d: %w", count, err)
			}

			cveTxStmt = tx.Stmt(cveDbStmt)
			upstreamTxStmt = tx.Stmt(upstreamDbStmt)
		}
	}

	// Flush remaining records
	if err := tx.Commit(); err != nil {
		return count, fmt.Errorf("failed to commit final batch: %w", err)
	}

	if _, err := decoder.Token(); err != nil { // Consume closing ']'
		return count, fmt.Errorf("failed to read closing bracket: %w", err)
	}

	return count, nil
}

func InsertCveAndUpstream(cveStmt *sql.Stmt, upstreamStmt *sql.Stmt, cve internals.NormalizedVuln) error {
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

// InsertSBOM inserts SBOM data into the database
func InsertSBOM(db *sql.DB, s internals.SBOM) error {
	// Start the transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	//Register or Retrieve the User

	var userID int64
	upsertUserQuery := `
		INSERT INTO users (hostname)
		VALUES (?)
		ON CONFLICT(hostname) DO UPDATE SET 
			hostname = excluded.hostname 
		RETURNING id;`

	err = tx.QueryRow(upsertUserQuery, s.Hostname).Scan(&userID)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("failed to process user/hostname %s: %w", s.Hostname, err)
	}

	//  Register or Update the Machine
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
		_ = tx.Rollback()
		return fmt.Errorf("failed to process machine %s: %w", s.MachineID, err)
	}

	//Wipe Old State
	_, err = tx.Exec(`DELETE FROM packages WHERE sbom_id = ?`, sbomID)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("failed to clear old packages: %w", err)
	}

	//Insert the New Packages Array
	insertPackageQuery := `
		INSERT INTO packages (sbom_id,name, version, purl, source_name, source_version)
		VALUES (?,?,?,?,?,?);`

	stmt, err := tx.Prepare(insertPackageQuery)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("failed to prepare package statement: %w", err)
	}
	defer func() {
		_ = stmt.Close()
	}()

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
			_ = tx.Rollback()
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

func InsertVulnPackages(db *sql.DB, vulnPackages []logic.VulnPackage, hostName string, machineID string) error {
	log.Printf("Inserting Vulnpackages for hostname:%v\n", hostName)
	//todo make a better upsert
	query := `
	INSERT INTO vulnPackages(MachineID,HostName,packageName,Installed,Introduced,Fixed,Purl,CVE_ID)
	VALUES (?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING 
`
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction:%v", err)
	}
	//prepare insert statement
	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("error preparing InsertVulnPackages Statement %v", err)
	}
	defer func() {
		_ = stmt.Close()
	}()

	//todo use batching

	//insert all the vuln packages into the DB
	//p = package
	for _, p := range vulnPackages {
		if _, err = stmt.Exec(machineID, hostName, p.PackageName, p.Installed, p.Introduced, p.Fixed, p.Purl, p.CveId); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("\n error inserting vulnPackage %+v , %v", p, err)
		}
	}

	//insert the vulnPackages
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("error commiting changes to the database %w", err)
	}

	log.Printf("Done Inserting Vulnpackages for hostname:%v\n", hostName)
	return nil
}

// GetAvailableMachines fetches all machines and maps their Machine ID to the corresponding Hostname.
func GetAvailableMachines(db *sql.DB) (map[string]string, error) {
	//   Combine both tables using an INNER JOIN to fetch all records in one roundtrip
	query := `
		SELECT s.machine_id, u.hostname 
		FROM sboms s
		INNER JOIN users u ON s.user_id = u.id
		WHERE s.machine_id IS NOT NULL;
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute machines query: %w", err)
	}
	//  Defer closing rows to release the connection back to the pool safely
	defer func() { _ = rows.Close() }()

	// Initialize the map to prevent returning a nil map
	machineMap := make(map[string]string)

	//   Iterate through the dataset
	for rows.Next() {
		var machineID string
		var hostname string

		err := rows.Scan(&machineID, &hostname)
		if err != nil {
			return nil, fmt.Errorf("failed to scan machine row: %w", err)
		}

		// Key: Machine ID -> Value: Hostname
		machineMap[machineID] = hostname
	}

	//   Always check for errors encountered during iteration
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error during row iteration: %w", err)
	}

	return machineMap, nil
}

func GetPaginatedVulnPackages(db *sql.DB, machineID string, limit int, offset int) ([]internals.VulnPackage, error) {
	query := `
		SELECT PackageName, CVE_ID,Installed, introduced, fixed, purl 
		FROM vulnPackages 
		WHERE machineId = ? 
		ORDER BY PackageName ASC
		LIMIT ? OFFSET ?;
	`

	rows, err := db.Query(query, machineID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var packages []internals.VulnPackage
	for rows.Next() {
		var pkg internals.VulnPackage
		err := rows.Scan(&pkg.PackageName, &pkg.CveId, &pkg.Installed, &pkg.Introduced, &pkg.Fixed, &pkg.Purl)
		if err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return packages, nil
}

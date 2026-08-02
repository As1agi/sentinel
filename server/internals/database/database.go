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

// VulnPackage for now lets redeclare the VulnPackage
type VulnPackage struct {
	PackageName string `json:"package_name"`
	Installed   string `json:"installed"`
	Introduced  string `json:"introduced"`
	Fixed       string `json:"fixed"`
	Purl        string `json:"purl"`
	CveId       string `json:"CveId"`
	//CVV later on and maybe a summary from AI on how to fix?
}

// ReadCveJsonIntoDataBase reads in data from a json file which has an array of CleanVulnerability
// into a database with the correct schema
func ReadCveJsonIntoDataBase(db *sql.DB, CveJsonPath string) {
	file, err := os.Open(CveJsonPath)
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
	cveStmt, upstreamStmt, err := prepareBatchStatementsSBOMInsert(tx)
	if err != nil {
		log.Fatalf("Failed to prepare transaction statements: %v", err)
	}

	log.Println("[*] streaming CVEs into the database")
	for decoder.More() {
		var cve internals.NormalizedVuln
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
			//log.Printf("Successfully flushed %d records to the database...", count)

			// Re-initialize for the next chunk
			tx, err = db.Begin()
			if err != nil {
				log.Fatalf("Failed to cycle next transaction: %v", err)
			}

			//Re-prepare statements tied to the brand-new transaction frame
			cveStmt, upstreamStmt, err = prepareBatchStatementsSBOMInsert(tx)
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

	fmt.Printf("[+] Successfully indexed all %d CVE components safely!\n", count)
}
func executeInsert(cveStmt *sql.Stmt, upstreamStmt *sql.Stmt, cve internals.NormalizedVuln) error {
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

// todo break the function into tiny functions

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
		tx.Rollback()
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

func InsertVulnPackages(db *sql.DB, vulnPackages []logic.VulnPackage, hostName string, machineID string) error {
	log.Printf("Inserting Vulnpackages for hostname:%v\n", hostName)
	//todo make a better upsert
	query := `
	INSERT INTO vulnPackages(MachineID,HostName,packageName,Installed,Introduced,Fixed,Purl,CVE_ID)
	VALUES (?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING 
`
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("error starting transaction:%v\n", err)
	}
	//prepare insert statement
	stmt, err := tx.Prepare(query)
	if err != nil {
		return fmt.Errorf("error preparing InsertVulnPackages Statement %v\n", err)
	}
	defer stmt.Close()
	//todo use batching

	//insert all the vuln packages into the DB
	//p = package
	for _, p := range vulnPackages {
		if _, err = stmt.Exec(machineID, hostName, p.PackageName, p.Installed, p.Introduced, p.Fixed, p.Purl, p.CveId); err != nil {
			tx.Rollback()
			return fmt.Errorf("\n error inserting vulnPackage %+v , %v", p, err)
		}
	}

	//insert the vulnPackages
	tx.Commit()
	log.Printf("Done Inserting Vulnpackages for hostname:%v\n", hostName)
	return nil
}
func FetchVulnPackages(db *sql.DB, hostName string, machineID string, offset int) []VulnPackage {
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
	defer rows.Close()

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
	defer rows.Close()

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

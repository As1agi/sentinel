package database

import (
	"database/sql"
	"log"
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

// Micro-function: Compiles statements on top of the assigned transaction frame
func prepareBatchStatementsSBOMInsert(tx *sql.Tx) (*sql.Stmt, *sql.Stmt, error) {
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

package database

import (
	"database/sql"
	"fmt"
	"log"
	"server/internals/config"
)

func OpenDB() *sql.DB {
	dataBasePath, err := config.GetDBPath()
	if err != nil {
		log.Fatalf("error opening database : %v\n", err)
	}

	// Format DSN with WAL mode, busy timeout (5s), and synchronous=NORMAL
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL", dataBasePath)

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		log.Fatalf("error opening database : %v\n", err)
	}

	// Restrict to a single connection to serialize writes in Go's connection pool
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Verify connection handle
	if err := db.Ping(); err != nil {
		log.Fatalf("error connecting to database : %v\n", err)
	}
	// 2. Enable Foreign Keys (SQLite disables them by default for backwards compatibility)
	return db
}

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
		_ = cveStmt.Close()
		return nil, nil, err
	}

	return cveStmt, upstreamStmt, nil
}

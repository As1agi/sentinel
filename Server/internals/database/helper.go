package database

import (
	"database/sql"
	"log"
	"server/internals/config"
)

func OpenDB() *sql.DB {
	log.Printf("Opening DataBase")
	dataBasePath, err := config.GetDBPath()

	if err != nil {
		log.Fatalf("error opening database : %v\n", err)
	}
	db, err := sql.Open("sqlite3", dataBasePath)
	if err != nil {
		log.Fatalf("cant open the db at path :%v\n err:%v\n", dataBasePath, err)
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
		cveStmt.Close()
		return nil, nil, err
	}

	return cveStmt, upstreamStmt, nil
}

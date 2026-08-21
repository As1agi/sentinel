package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"server/internals"
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

	//  Enable Foreign Keys (SQLite disables them by default for backwards compatibility)
	return db
}

type Prepare interface {
	Prepare(query string) (*sql.Stmt, error)
}

type QueryDef struct {
	Executor Prepare
	Query    string
}

func extractDescription(cve internals.NormalizedVuln) string {
	var (
		lenDesc     int
		description string
	)

	lenDesc = len(cve.Description)
	if lenDesc < 1 {
		//log.Printf("added empty desc")
		description = "no description"
	} else if lenDesc >= 1 {
		//for now
		description = cve.Description[0].Value
	}

	return description
}

func extractCvssV2(cve internals.NormalizedVuln) (string, error) {
	var (
		lenCvssV2    int
		cvssMetricV2 []byte
		err          error
	)

	lenCvssV2 = len(cve.CvssMetricV2)
	if lenCvssV2 == 0 {
		cvssMetricV2 = []byte("NA")
	} else if lenCvssV2 >= 1 {
		cvssMetricV2, err = json.Marshal(cve.CvssMetricV2)
		if err != nil {
			return "", fmt.Errorf("error extracting cvssv2 : %v", err)
		}
	}
	return string(cvssMetricV2), nil
}

func extractCvssV3(cve internals.NormalizedVuln) (string, error) {
	var (
		lenCvssV3    int
		cvssMetricV3 []byte
		err          error
	)

	lenCvssV3 = len(cve.CvssMetricV3)
	if lenCvssV3 == 0 {
		cvssMetricV3 = []byte("NA")
	} else if lenCvssV3 >= 1 {
		cvssMetricV3, err = json.Marshal(cve.CvssMetricV3)
		if err != nil {
			return "", fmt.Errorf("error extracting cvssv2 : %v", err)
		}
	}
	return string(cvssMetricV3), nil
}

// prepareBatchStatements returns an array of statements in the order they are passed
// // also return a function to close all statements
// func prepareBatchStatements(defs ...QueryDef) ([]*sql.Stmt, func(), error) {
// 	stmts := make([]*sql.Stmt, 0, len(defs))

// 	cleanup := func() {
// 		for _, stmt := range stmts {
// 			if stmt != nil {
// 				_ = stmt.Close()
// 			}
// 		}
// 	}

// 	for i, def := range defs {
// 		stmt, err := def.Executor.Prepare(def.Query)
// 		if err != nil {
// 			// CRITICAL: If preparation fails halfway, we must execute the cleanup
// 			// before returning, otherwise we leak the previously prepared statements.
// 			cleanup()
// 			return nil, nil, fmt.Errorf("failed preparing query at index %d: %w", i, err)
// 		}
// 		stmts = append(stmts, stmt)
// 	}

// 	return stmts, cleanup, nil
// }

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

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

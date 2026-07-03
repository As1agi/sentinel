package database

import "log"

// database schemas
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
	_, err = db.Exec(CreateUniqueConstraint)
	if err != nil {
		log.Fatalf("Failed to create packages table: %v", err)
	}
	_, err = db.Exec(CreateCVETable)
	if err != nil {
		log.Fatalf("Failed to create packages table: %v", err)
	}
	_, err = db.Exec(CreateUpstreamTable)
	if err != nil {
		log.Fatalf("Failed to create packages table: %v", err)
	}

}

const (
	CreateUniqueConstraint = `
	CREATE UNIQUE INDEX IF NOT EXISTS idx_sboms_user_machine 
		ON sboms(user_id, machine_id);
`

	CreateSBOMDataTable = `
CREATE TABLE IF NOT EXISTS sboms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    machine_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    os TEXT NOT NULL,
    os_version TEXT NOT NULL,
    os_ecosystem TEXT NOT NULL,
    kernel_version TEXT NOT NULL ,
    architecture TEXT NOT NULL ,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE 
);`

	CreateUserTable = `
	CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`

	CreatePackagesTable = `
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sbom_id TEXT NOT NULL ,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    purl TEXT,
    source_name TEXT,
    source_version TEXT,
    FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE
);`

	CreateCVETable = `
	CREATE TABLE IF NOT EXISTS cve(
	    id INTEGER PRIMARY KEY AUTOINCREMENT ,
	    advisory_id TEXT NOT NULL, 
	    ecosystem TEXT NOT NULL ,
	    package_name TEXT NOT NULL ,
	    purl TEXT,
	    introduced TEXT NOT NULL ,
	    fixed TEXT                
		,UNIQUE(advisory_id,ecosystem,package_name)
	    )
`
	CreateUpstreamTable = `
	CREATE TABLE IF NOT EXISTS upstream(
	     id INTEGER PRIMARY KEY AUTOINCREMENT ,
	     advisory_id TEXT NOT NULL ,
	     upstream_id TEXT NOT NULL ,
	     UNIQUE(advisory_id,upstream_id)
	    )
`
)

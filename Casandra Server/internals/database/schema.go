package database

//database schemas

const (
	CreateSBOMDataTable = `
CREATE TABLE IF NOT EXISTS sboms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    machine_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    os TEXT NOT NULL,
    os_version TEXT NOT NULL,
    os_ecosystem TEXT,
    kernel_version TEXT,
    architecture TEXT,
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
    sbom_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    purl TEXT,
    source_name TEXT,
    source_version TEXT,
    FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE CASCADE
);`
)

package server

import "database/sql"

type server struct {
	db *sql.DB
	//port string
}

package server

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"server/internals/config"
	"server/internals/database"
)

func init() {
	//prepare the templates then use them later
	fmt.Println("Creating directories...")
	if err := config.InitDirectories(); err != nil {
		log.Fatalf("error initializing directories : %v\n", err)
	}
	fmt.Println("Databasing...")
	database.InitSchema()

}

func Serve(port string) {

	//todo refactor the server struct so we use the port provided
	fmt.Println("Server running on http://localhost:8080/")

	dataBasePath, err := config.GetDBPath()
	if err != nil {
		log.Fatalf("error getting")
	}
	db, err := sql.Open("sqlite3", dataBasePath)

	if err != nil {
		log.Fatalf("error opening the database %v\n", err)
	}

	svr := &server{db: db}

	mux := http.NewServeMux()

	// Explicitly catch only POST requests to this endpoint
	mux.HandleFunc("POST /api/v1/sbom", svr.HandleSBOMData)
	mux.HandleFunc("GET /{$}", svr.Home) //for now dashboard is the main root
	mux.HandleFunc("GET /static/", svr.Static)
	mux.HandleFunc("GET /machines/{machineID}/vulns", svr.RenderVulnPackages)

	fmt.Println("Server running on :8080...")
	if err := http.ListenAndServe("localhost:8080", mux); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}

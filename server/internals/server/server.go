package server

import (
	"database/sql"
	"fmt"
	"log"
	"mime"
	"net/http"
	"server/internals/config"
	"server/internals/database"
)

func init() {
	//prepare the templates then use them later
	log.Println("[*]Creating directories...")
	if err := config.InitDirectories(); err != nil {
		log.Fatalf("error initializing directories : %v\n", err)
	}
	log.Println("[*]Initialising database schema")
	database.InitSchema()
	//register mime types to remove the error when loading output.css
	//http://localhost:8080/static/output.css' because its MIME type ('text/plain') is not a supported stylesheet MIME type, and strict MIME checking is enabled.
	_ = mime.AddExtensionType(".css", "text/css; charset=utf-8")
}

func Serve(port string, dataBasePath string) {

	db, err := sql.Open("sqlite3", dataBasePath)
	if err != nil {
		log.Fatalf("error opening the database %v\n", err)
	}

	svr := &server{db: db, port: port}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/sbom", svr.HandleSBOMData)
	mux.HandleFunc("GET /{$}", svr.Home) //for now dashboard is the main root
	mux.HandleFunc("GET /static/", svr.Static)
	mux.HandleFunc("GET /machines/{machineID}/vulns", svr.RenderVulnPackages)

	fmt.Printf("Server running on http://localhost:%v\n", svr.port)

	if err := http.ListenAndServe(fmt.Sprintf("localhost:%v", svr.port), mux); err != nil {
		log.Printf("[X] Server failed: %v\n", err)
	}
}

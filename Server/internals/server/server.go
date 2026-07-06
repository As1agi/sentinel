package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"server/internals"
	"server/internals/config"
	"server/internals/database"
	"server/internals/logic"
)

// TODO CREATE A SERVER STRUCT TO ALLOW HAVING A CONSTANT DATABASE
func Serve() {
	fmt.Println("Databasing...")
	database.InitSchema()
	fmt.Println("Server running on :8080...")
	//todo remove once we use a server struct
	root, _ := config.ResolvePaths()
	databasepath := path.Join(root.Root, "database")
	db, err := sql.Open("sqlite3", databasepath)

	if err != nil {
		log.Fatalf("error opening the database %v\n", err)
	}

	svr := &server{db: db}

	mux := http.NewServeMux()

	// Explicitly catch only POST requests to this endpoint
	mux.HandleFunc("POST /api/sbom", svr.HandleSBOMData)
	//todo trigger a job to check for the packages for CVEs here, once we receiver a new request
	//	 	then immediately send back the OK to the user, dont disturb them
	//      we may have to create a new worker I guess that actively listens for requests to sort of like check for
	//		vulnerablities

	fmt.Println("Server running on :8080...")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}

func (s *server) HandleSBOMData(w http.ResponseWriter, r *http.Request) {
	// Method validation is already handled by the mux!
	// Validate Content-Type header
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	var data internals.SBOM

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}

	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"status": "error"}`))
		return
	}

	//fmt.Printf("Payload received cleanly: %+v\n", data)

	if err = database.InsertSBOM(s.db, data); err != nil {
		log.Printf("Error inserting data into database %v", err)
	}

	go s.AuditPackages(data.Hostname, data.MachineID)
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status": "accepted"}`))

}

func (s *server) AuditPackages(hostname string, machineID string) {
	//dont return nothing just add them directly to the database to save time and space later on

	log.Printf("Auditing SBOM from user %v\n", hostname)
	_, err := logic.AuditUserPackages(hostname, machineID, s.db)
	if err != nil {
		log.Printf("%v\n", err)
	}

}

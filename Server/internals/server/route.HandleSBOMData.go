package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	path2 "path"
	"server/internals"
	"server/internals/config"
	"server/internals/database"
)

func HandleSBOMPostData(w http.ResponseWriter, r *http.Request) {
	// Method validation is already handled by the mux!
	// Validate Content-Type header
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	//todo remove once we use a server struct
	root, _ := config.ResolvePaths()
	databasepath := path2.Join(root.Root, "database")
	db, err := sql.Open("sqlite3", databasepath)
	var data internals.SBOM

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}

	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"status": "error"}`))
	}

	fmt.Printf("Payload received cleanly: %+v\n", data)

	if err = database.InsertSBOM(db, data); err != nil {
		log.Printf("Error inserting data into database %v", err)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "success"}`))
}

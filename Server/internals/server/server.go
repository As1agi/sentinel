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
	"server/internals/server/templates/pages"
	"strconv"
)

func init() {
	//prepare the templates then use them later
	fmt.Println("Databasing...")
	database.InitSchema()
}

// TODO CREATE A SERVER STRUCT TO ALLOW HAVING A CONSTANT DATABASE
func Serve() {

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
	mux.HandleFunc("POST /api/v1/sbom", svr.HandleSBOMData)
	mux.HandleFunc("GET /{$}", svr.Home) //for now dashboard is the main root
	mux.HandleFunc("GET /static/", svr.Static)
	mux.HandleFunc("GET /machines/{machineID}/vulns", svr.RenderVulnPackages)
	//mux.HandleFunc("GET /dashboard", svr.Home)

	//todo trigger a job to check for the packages for CVEs here, once we receiver a new request
	//	 	then immediately send back the OK to the user, dont disturb them
	//      we may have to create a new worker I guess that actively listens for requests to sort of like check for
	//		vulnerablities

	fmt.Println("Server running on :8080...")
	if err := http.ListenAndServe("localhost:8080", mux); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}

func (s *server) RenderVulnPackages(w http.ResponseWriter, r *http.Request) {
	//get vuln packages from machineID
	machineID := r.PathValue("machineID")
	if machineID == "" {
		http.Error(w, "Missing Machine ID parameter", http.StatusBadRequest)
		return
	}
	offsetStr := r.URL.Query().Get("offset")
	offset := 0 // default baseline fallback
	if offsetStr != "" {
		var err error
		offset, err = strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			http.Error(w, "Invalid offset value parameter", http.StatusBadRequest)
			return
		}
	}

	limit := 25
	vulnPackages, err := database.GetPaginatedVulnPackages(s.db, machineID, limit, offset)
	if err != nil {
		log.Printf("Database retrieval failure: %v", err)
		http.Error(w, "Internal Server Data Error", http.StatusInternalServerError)
		return
	}
	nextOffset := -1
	if len(vulnPackages) == limit {
		nextOffset = offset + limit
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// 5. HTMX Optimization Request Branching
	// If it's an HTMX load-more request, we only render the new rows fragment, not the whole MainFrame page layout
	if r.Header.Get("HX-Request") == "true" {
		err = pages.VulnListRows(vulnPackages, machineID, nextOffset).Render(r.Context(), w)
	} else {
		// Standard browser first-pass view request gets everything wrapped
		err = pages.RenderVulnPackages(vulnPackages, machineID, nextOffset).Render(r.Context(), w)
	}

	if err != nil {
		log.Printf("Rendering error execution: %v", err)
	}
}

// Home is the root page , that is the dashboard
func (s *server) Home(w http.ResponseWriter, r *http.Request) {
	//we fecth the list of all the available SBOMs , return a map of machineID and hostname
	machines, err := database.GetAvailableMachines(s.db)
	//we render the list to the UI
	err = pages.RenderSBOM(machines).Render(r.Context(), w)

	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
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
	//return nothing just add them directly to the database to save time and space later on

	log.Printf("Auditing SBOM from user %v\n", hostname)
	packages, err := logic.AuditUserPackages(hostname, machineID, s.db)
	if err != nil {
		log.Printf("%v\n", err)
	}
	//fmt.Printf("\n\n\n vuln packages %++v\n", packages)
	//save the packages to the database
	if err := database.InsertVulnPackages(s.db, packages, hostname, machineID); err != nil {
		log.Printf("error inserting vulnPackages to the database:%v\n", err)
	}
	log.Printf("Successfuly inserted vulnpackages for the user:%v machineID:%v", hostname, machineID)
}

// Static servers static files to the server
func (s *server) Static(w http.ResponseWriter, r *http.Request) {
	fs := http.StripPrefix("/static/", http.FileServer(http.Dir("./internals/server/assets/static")))
	fs.ServeHTTP(w, r)
}

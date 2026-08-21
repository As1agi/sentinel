package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"server/internals"
	"server/internals/database"
	"server/internals/logic"
	"server/internals/server/templates/pages"
	"strconv"
)

func (s *server) RenderVulnPackages(w http.ResponseWriter, r *http.Request) {
	//get  machineID
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

	limit := 10
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

	// HTMX Optimization Request Branching
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
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
	}
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
		_, err := w.Write([]byte(`{"status": "error"}`))
		if err != nil {
			log.Printf("error writing response %v", err)
		}
		return
	}

	//fmt.Printf("Payload received cleanly: %+v\n", data)

	if err = database.InsertHostSbom(s.db, data); err != nil {
		log.Printf("Error inserting data into database %v", err)
	}

	go s.AuditPackages(data.Hostname, data.MachineID)
	w.WriteHeader(http.StatusAccepted)
	_, err = w.Write([]byte(`{"status": "accepted"}`))
	if err != nil {
		log.Printf("error writing response to user : %v", err)
	}
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
	if err := database.InsertHostVulnPackages(s.db, packages, hostname, machineID); err != nil {
		log.Printf("error inserting vulnPackages to the database:%v\n", err)
	}
	log.Printf("[+]Successfuly inserted vulnpackages for the user:%v machineID:%v", hostname, machineID)
}

// Static servers static files to the server
func (s *server) Static(w http.ResponseWriter, r *http.Request) {
	log.Printf("path : %v", r.URL.Path)
	fs := http.StripPrefix("/static/", http.FileServer(http.Dir("./assets/static/")))
	fs.ServeHTTP(w, r)
}

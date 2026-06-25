package server

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func HandleSBOMPostData(w http.ResponseWriter, r *http.Request) {
	// Method validation is already handled by the mux!

	// Validate Content-Type header
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	var data SBOM
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&data); err != nil {
		http.Error(w, fmt.Sprintf("Bad Request: %v", err), http.StatusBadRequest)
		return
	}

	fmt.Printf("Payload received cleanly: %+v\n", data)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "success"}`))
}

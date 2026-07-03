package server

import (
	"fmt"
	"net/http"
	"server/internals/database"
)

// TODO CREATE A SERVER STRUCT TO ALLOW HAVING A CONSTANT DATABASE
func Serve() {
	fmt.Println("Databasing...")
	database.InitSchema()
	fmt.Println("Server running on :8080...")

	mux := http.NewServeMux()
	// Explicitly catch only POST requests to this endpoint
	mux.HandleFunc("POST /api/sbomData", HandleSBOMPostData)

	fmt.Println("Server running on :8080...")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}

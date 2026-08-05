package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	sbom "sentinel/internals/collector"
	"sentinel/internals/server"
	"time"
)

func main() {
	// Guard execution context against zombie processes or hung packaging utilities
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sbom, err := sbom.GatherOSPackages(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Execution Error: %v\n", err)
		os.Exit(1)
	}

	jsonBytes, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Serialization Error: %v\n", err)
		os.Exit(1)
	}

	log.Printf("%+v", string(jsonBytes))

	err = server.PostSBOM(jsonBytes)
	if err != nil {
		fmt.Printf("Serialization Error: %v\n", err)
	}

}

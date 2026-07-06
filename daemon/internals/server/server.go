package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// AppConfig simulates your environment configuration provider

var Config = AppConfig{
	ProdBaseURL: "https://api.yourproductionsite.com",
}

func PostSBOM(SBOMbytes []byte) error {
	req, err := newPostRequest("sbom", SBOMbytes, true)
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	//send data
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	body, err := io.ReadAll(resp.Body)
	//todo check response status for failures or other status

	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Body: %s\n", string(body))
	return nil
}

// todo remove the localhost flag which is used for testing, instead use .env variables to know
func newPostRequest(serverEndpoint string, data []byte, localHost bool) (*http.Request, error) {
	var baseURL string

	if localHost {
		baseURL = "http://localhost:8080/api"
	} else {
		baseURL = Config.ProdBaseURL
	}

	// url.JoinPath automatically cleans up duplicate or missing slashes
	fullURL, err := url.JoinPath(baseURL, serverEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid URL path: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewBuffer(data))
	if err != nil {
		// Correct pattern: Return nil instead of an empty allocated struct
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set request header fields
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

var (
	supportedDistros  = []string{"ubuntu", "debian"}
	supportedDatasets = []string{"osv", "nvd"}
)

func SupportedDistros() []string {
	distros := make([]string, len(supportedDistros))
	copy(distros, supportedDistros)
	return distros
}

func SupportedDatasets() []string {
	datasets := make([]string, len(supportedDatasets))
	copy(datasets, supportedDatasets)
	return datasets
}

// GetBaseDir resolves path following the XDG Base Directory Specification
func GetBaseDir() (string, error) {
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		return filepath.Join(xdgData, "sentinel"), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to resolve user home directory: %w", err)
	}
	return filepath.Join(home, ".local", "share", "sentinel"), nil
}

// GetDBPath returns /<baseDir>/sentinel.db
func GetDBPath() (string, error) {
	baseDir, err := GetBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, "sentinel.db"), nil
}

// GetDatasetBaseDir returns /<baseDir>/data/<dataset>/<distro>/
func GetDatasetBaseDir(dataset string) (string, error) {
	baseDir, err := GetBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, "data", "cve", dataset), nil
}

func GetDatasetDistroBaseDir(distro, dataset string) (string, error) {
	baseDir, err := GetDatasetRawCveDir(dataset)
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, distro), nil
}

// GetDatasetRawCveDir returns /<baseDir>/data/<dataset>/raw
func GetDatasetRawCveDir(dataset string) (string, error) {
	baseDir, err := GetDatasetBaseDir(dataset)
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, "raw"), nil
}

// GetNormalizedCveJsonPath returns /<baseDir>/data/<dataset>/normalized/normalized.json
func GetNormalizedCveJsonPath(dataset string) (string, error) {
	normDir, err := GetDatasetBaseDir(dataset)
	if err != nil {
		return "", err
	}
	return filepath.Join(normDir, "normalized.json"), nil
}

// InitDirectories initializes the directory hierarchy on the filesystem before ingestion starts
func InitDirectories() error {
	baseDir, err := GetBaseDir()
	if err != nil {
		return err
	}

	// Pre-allocate slice with base directory capacity
	dirsToCreate := []string{baseDir}

	for _, distro := range supportedDistros {
		for _, dataset := range supportedDatasets {
			rawDir, err := GetDatasetRawCveDir(dataset)
			if err != nil {
				return fmt.Errorf("failed to resolve raw dir for %s/%s: %w", distro, dataset, err)
			}

			dirsToCreate = append(dirsToCreate, rawDir)
		}
	}

	for _, dir := range dirsToCreate {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

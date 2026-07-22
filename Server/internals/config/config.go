package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// SupportedDistros centralizes the list of distros so adding new feeds takes 1 line.
var SupportedDistros = []string{"ubuntu", "debian"}

// InitDirectories ensures all required filesystem paths exist before app startup.
func InitDirectories() error {
	rawDir, err := GetRawOsvDir()
	if err != nil {
		return fmt.Errorf("failed to resolve raw OSV directory: %w", err)
	}

	cleanFile, err := GetCleanOsvJsonPath()
	if err != nil {
		return fmt.Errorf("failed to resolve clean OSV path: %w", err)
	}

	// Target parent directories ONLY (filepath.Dir converts .../clean/clean.json -> .../clean)
	dirs := []string{
		filepath.Dir(cleanFile),
	}

	//  Dynamically add raw distro directories
	for _, distro := range SupportedDistros {
		dirs = append(dirs, filepath.Join(rawDir, distro))
	}

	//  Create all directories in a single pass
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// GetBaseDir returns /home/<user>/.local/share/sentinel
func GetBaseDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "sentinel"), nil
}

// GetDBPath returns /home/<user>/.local/share/sentinel/sentinel.db
func GetDBPath() (string, error) {
	baseDir, err := GetBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, "sentinel.db"), nil
}

// GetBaseOsvDir returns /home/<user>/.local/share/sentinel/data/cve/osv
func GetBaseOsvDir() (string, error) {
	baseDir, err := GetBaseDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, "data", "cve", "osv"), nil
}

// GetRawOsvDir returns /home/<user>/.local/share/sentinel/data/cve/osv/raw
func GetRawOsvDir() (string, error) {
	baseDir, err := GetBaseOsvDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, "raw"), nil
}

// GetCleanOsvJsonPath returns /home/<user>/.local/share/sentinel/data/cve/osv/clean/clean.json
func GetCleanOsvJsonPath() (string, error) {
	baseDir, err := GetBaseOsvDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, "clean", "clean.json"), nil
}

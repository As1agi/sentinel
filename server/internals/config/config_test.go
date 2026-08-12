package config_test

import (
	"os"
	"path/filepath"
	"server/internals/config"
	"testing"
	// Update with your actual module path
)

func TestInitDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	//Override XDG_DATA_HOME so GetBaseDir() points to the sandbox instead of ~/.local/share
	t.Setenv("XDG_DATA_HOME", tmpDir)

	// Execute initialization
	if err := config.InitDirectories(); err != nil {
		t.Fatalf("InitDirectories() returned unexpected error: %v", err)
	}

	//Resolve the isolated base directory (~/sentinel inside tmpDir)
	expectedBase, err := config.GetBaseDir()
	if err != nil {
		t.Fatalf("failed to resolve base dir: %v", err)
	}

	// Build list of all directories that MUST exist after InitDirectories runs
	dirsToCheck := []string{
		expectedBase,
	}

	// Dynamically generate expected paths based on supported distros and datasets
	for _, distro := range config.SupportedDistros() {
		for _, dataset := range config.SupportedDatasets() {
			rawDir, err := config.GetDatasetBaseDir(dataset)
			if err != nil {
				t.Fatalf("failed to resolve raw dir for %s/%s: %v", dataset, distro, err)
			}

			normDir, err := config.GetDatasetRawCveDir(dataset)
			if err != nil {
				t.Fatalf("failed to resolve normalized dir for %s/%s: %v", dataset, distro, err)
			}

			dirsToCheck = append(dirsToCheck, rawDir, normDir)
		}
	}

	//Assert existence and file modes
	for _, dir := range dirsToCheck {
		info, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				t.Errorf("expected directory does not exist: %s", dir)
			} else {
				t.Errorf("failed to stat path %s: %v", dir, err)
			}
			continue
		}

		if !info.IsDir() {
			t.Errorf("path exists but is not a directory: %s", dir)
		}

		// Verify directory permissions match expected 0755 mask
		if mode := info.Mode().Perm(); mode != 0755 {
			t.Errorf("directory %s has unexpected permissions: got %o, want 0755", dir, mode)
		}
	}
}

func TestInitDirectories_ReadOnlyParentFailure(t *testing.T) {
	// Test handling of permission errors by attempting to create directories inside a read-only root
	tmpDir := t.TempDir()
	readOnlyDir := filepath.Join(tmpDir, "readonly")

	if err := os.Mkdir(readOnlyDir, 0444); err != nil {
		t.Fatalf("failed to setup read-only fixture: %v", err)
	}

	t.Setenv("XDG_DATA_HOME", readOnlyDir)
	if err := config.InitDirectories(); err == nil {
		t.Error("expected InitDirectories() to fail on read-only path, but got nil")
	}
}

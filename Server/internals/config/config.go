package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// ProjectPaths holds the absolute paths for your application components
type ProjectPaths struct {
	Root string
}

// ResolvePaths locates the project root by looking for go.mod, fallback to Env variables
func ResolvePaths() (*ProjectPaths, error) {
	//  Production Check: If an environment variable is explicitly set, use it.
	// This is critical for Docker containers or production servers where source code/go.mod isn't deployed.
	if prodRoot := os.Getenv("PROJECT_ROOT"); prodRoot != "" {
		return &ProjectPaths{
			Root: prodRoot,
		}, nil
	}

	//  Start at current working directory and look upwards for go.mod
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	dir := cwd
	for {
		// Check if go.mod exists in the current directory level
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			absRoot, _ := filepath.Abs(dir)
			return &ProjectPaths{
				Root: absRoot,
			}, nil
		}

		// Move up to the parent directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached the system filesystem root (e.g., C:\ or /) without finding go.mod
			break
		}
		dir = parent
	}

	return nil, fmt.Errorf("could not find project root (missing go.mod and PROJECT_ROOT env var)")
}

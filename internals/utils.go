package utils

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func RemoveBraces(input string) string {
	// Chain ReplaceAll to target different types of braces
	noBraces := strings.ReplaceAll(input, "{", "")
	noBraces = strings.ReplaceAll(noBraces, "}", "")
	noBraces = strings.ReplaceAll(noBraces, "(", "")
	noBraces = strings.ReplaceAll(noBraces, ")", "")
	noBraces = strings.ReplaceAll(noBraces, "[", "")
	noBraces = strings.ReplaceAll(noBraces, "]", "")

	return noBraces
}

// saveToConfigPath saves a file to a path
func saveToPath(filename string, dir string, marshalledData []byte) error {
	exists, _ := FileExists(dir)
	if exists {
		overwrite, err := AskYesNo(fmt.Sprintf("identity file already exists at %s. Overwrite? [y/N]: ", dir))
		if err != nil {
			return err
		}
		if !overwrite {
			return os.ErrExist
		}
	}

	//create the file
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("error:%v", err)
	}
	//add||force the permission
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("error:%v", err)
	}

	//create a temp file
	tmpFile, err := os.CreateTemp(dir, ".identity-*.tmp")
	if err != nil {
		return fmt.Errorf("error creating temp file:%v", err)
	}

	//get temp file name and ensure we close it
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if _, err = tmpFile.Write(marshalledData); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("error writing into temp file:%v", err)
	}
	if err = tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("error syncing temp file:%v", err)
	}

	if err = tmpFile.Close(); err != nil {
		return fmt.Errorf("error closing temp file:%v", err)
	}

	if err = os.Rename(tmpName, dir); err != nil {
		return fmt.Errorf("error rename temp file to identity file: %w", err)
	}

	if err = os.Chmod(dir, 0o600); err != nil {
		return err
	}
	return nil
}

// FileExists check if file exists
func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("check file exists: %w", err)
}

// return the path to the applications location in the os config path
func getDefaultConfigPath() (string, error) {
	osConfig, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("error:%v", err)
	}
	return filepath.Join(osConfig, "tsup"), nil
}

// AskYesNo yes/no  prompt
func AskYesNo(prompt string) (bool, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("read input: %w", err)
	}
	input = strings.TrimSpace(strings.ToLower(input))

	switch input {
	case "y", "yes":
		return true, nil
	case "n", "no", "":
		return false, nil
	default:
		return false, nil
	}
}

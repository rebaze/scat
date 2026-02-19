package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// EnsureDir creates the directory if it doesn't exist.
func EnsureDir(dir string) error {
	return os.MkdirAll(dir, 0o755)
}

// WriteJSON writes v as pretty-printed JSON to the given path.
func WriteJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

// OutPath joins the output directory and filename.
func OutPath(outDir, filename string) string {
	return filepath.Join(outDir, filename)
}

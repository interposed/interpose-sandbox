package ci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// WriteJSON writes the record to <dir>/<run_id>.json (creating dir). This is
// the hand-off to the operator Releases page, which reads the same directory.
func (r RunRecord) WriteJSON(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, sanitize(r.RunID)+".json")
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// ReadRecords loads every *.json record in dir, newest-started first. A
// missing directory is not an error (returns an empty slice).
func ReadRecords(dir string) ([]RunRecord, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []RunRecord
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var r RunRecord
		if json.Unmarshal(b, &r) == nil {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out, nil
}
